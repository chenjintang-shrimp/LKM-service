"""Github OAuth 服务 —— 授权 URL、处理回调、绑定账户。"""

import secrets

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.err import BizError
from app.db.models import Profile, User, expires_at, now_iso
from app.db.repo import consume_once, get_or_raise
from app.modules.auth.errors import AuthErr
from app.modules.auth.models import OAuthState, UserOAuth
from app.modules.auth.service_auth import log_audit, upgrade_to_normal


def _generate_oauth_state(db: Session, purpose: str) -> str:
    """生成一个高熵的 OAuth state 令牌，存储并返回它。"""
    state = secrets.token_urlsafe(32)
    expiry = expires_at(minutes=10)
    db.add(OAuthState(state=state, purpose=purpose, expires_at=expiry))
    db.flush()
    return state


def _consume_oauth_state(db: Session, state: str, purpose: str) -> None:
    if not consume_once(
        db,
        OAuthState,
        {"consumed": True},
        OAuthState.state == state,
        OAuthState.consumed.is_(False),
        OAuthState.purpose == purpose,
        OAuthState.expires_at > now_iso(),
    ):
        raise BizError(AuthErr.OAUTH_PROVIDER_ERROR, "Invalid or expired OAuth state")


def get_github_auth_url(db: Session, purpose: str = "login") -> str:
    state = _generate_oauth_state(db, purpose)
    return (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.github_client_id}"
        f"&redirect_uri={settings.github_redirect_uri}"
        f"&scope=user:email"
        f"&state={state}"
    )


async def _exchange_github_token(code: str) -> str:
    """将 OAuth 授权码兑换为 GitHub 访问令牌。"""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        data = resp.json()
        access_token = data.get("access_token")
        if not access_token:
            raise BizError(AuthErr.OAUTH_PROVIDER_ERROR, data.get("error_description", "No access token"))
        return access_token


async def _get_github_user(access_token: str) -> dict:
    """获取 GitHub 用户资料和主邮箱。"""
    headers = {"Authorization": f"token {access_token}"}
    async with httpx.AsyncClient() as client:
        # 获取用户资料
        user_resp = await client.get("https://api.github.com/user", headers=headers)
        user_data = user_resp.json()
        if "id" not in user_data:
            raise BizError(AuthErr.OAUTH_PROVIDER_ERROR, "Failed to fetch GitHub user")

        # 获取邮箱列表
        emails_resp = await client.get("https://api.github.com/user/emails", headers=headers)
        emails_data = emails_resp.json()
        primary_email = None
        if isinstance(emails_data, list):
            for entry in emails_data:
                if entry.get("primary") and entry.get("verified"):
                    primary_email = entry["email"]
                    break
            # 备选方案：第一个已验证的邮箱
            if primary_email is None:
                for entry in emails_data:
                    if entry.get("verified"):
                        primary_email = entry["email"]
                        break

        return {
            "provider_user_id": str(user_data["id"]),
            "provider_email": primary_email,
            "login": user_data.get("login", ""),
        }


async def handle_github_callback(db: Session, code: str, state: str) -> dict:
    _consume_oauth_state(db, state, "login")
    access_token = await _exchange_github_token(code)
    gh_user = await _get_github_user(access_token)

    # 1. 现有 OAuth 绑定
    oauth = (
        db.query(UserOAuth)
        .filter(
            UserOAuth.provider == "github",
            UserOAuth.provider_user_id == gh_user["provider_user_id"],
        )
        .first()
    )
    if oauth:
        user = get_or_raise(
            db, User, AuthErr.USER_NOT_FOUND, User.id == int(oauth.user_id), # type: ignore[arg-type]
        )
        return _oauth_login_response(db, user) # type: ignore[arg-type]

    # 2. 通过邮箱查找现有用户 -> 绑定
    if gh_user["provider_email"]:
        user = db.query(User).filter(User.email == gh_user["provider_email"]).first()
        if user:
            db.add(
                UserOAuth(
                    user_id=int(user.id), # type: ignore[arg-type]
                    provider="github",
                    provider_user_id=gh_user["provider_user_id"],
                    provider_email=gh_user["provider_email"],
                )
            )
            db.flush()
            upgrade_to_normal(db, user) # type: ignore[arg-type]
            return _oauth_login_response(db, user) # type: ignore[arg-type]

    # 3. 创建新用户
    username = gh_user["login"]
    # 确保唯一性
    suffix = 1
    base = username
    while db.query(User).filter(User.username == username).first():
        username = f"{base}{suffix}"
        suffix += 1

    user = User(
        username=username,
        email=gh_user["provider_email"],
        hashed_password="",
        account_level="normal",
    )
    db.add(user)
    db.flush()

    db.add(Profile(user_id=int(user.id), role="member"))
    db.flush()

    db.add(
        UserOAuth(
            user_id=int(user.id),
            provider="github",
            provider_user_id=gh_user["provider_user_id"],
            provider_email=gh_user["provider_email"],
        )
    )
    db.flush()

    log_audit(db, user.id, "oauth_login", "github")

    return _oauth_login_response(db, user)


def _oauth_login_response(db: Session, user: User) -> dict:
    """检查 TOTP 要求并返回认证响应。"""
    from app.modules.auth.service_auth import _finalize_auth_response

    return _finalize_auth_response(db, user)


async def bind_github(db: Session, user_id: int, code: str, state: str) -> dict:
    _consume_oauth_state(db, state, "bind")
    access_token = await _exchange_github_token(code)
    gh_user = await _get_github_user(access_token)

    existing_oauth = (
        db.query(UserOAuth)
        .filter(
            UserOAuth.provider == "github",
            UserOAuth.provider_user_id == gh_user["provider_user_id"],
        )
        .first()
    )
    if existing_oauth:
        raise BizError(AuthErr.OAUTH_EMAIL_TAKEN, "This Github account is already bound to another user")

    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == user_id)

    db.add(
        UserOAuth(
            user_id=int(user.id), # type: ignore[arg-type]
            provider="github",
            provider_user_id=gh_user["provider_user_id"],
            provider_email=gh_user["provider_email"],
        )
    )
    db.flush()

    upgrade_to_normal(db, user) # type: ignore[arg-type]

    return {"message": "Github account bound"}
