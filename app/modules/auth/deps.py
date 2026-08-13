"""FastAPI 路由的 JWT 依赖注入。"""

from fastapi import Depends, Header
from jwt import PyJWTError
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.err import BizError, CommonErr
from app.db.models import User, now_iso
from app.db.repo import get_or_raise
from app.db.session import get_session
from app.modules.auth.errors import AuthErr
from app.modules.auth.providers.base import EmailProvider, SmsProvider
from app.modules.auth.providers.console import ConsoleEmailProvider, ConsoleSmsProvider
from app.modules.auth.security import decode_access_token

_LEVEL_ORDER = {"local": 0, "normal": 1, "admin": 2}


class CurrentUser(BaseModel):
    """从已验证的 JWT 访问令牌中提取的用户信息。"""

    id: int
    account_level: str
    role: str


def _parse_bearer(authorization: str | None = Header(None, alias="Authorization")) -> str:
    """从 Authorization 请求头中提取 Bearer 令牌。如果请求头缺失或格式错误，则抛出 BizError(FORBIDDEN)。"""
    if not authorization:
        raise BizError(CommonErr.FORBIDDEN, "Missing authorization header")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise BizError(CommonErr.FORBIDDEN, "Invalid authorization header format")
    return parts[1]


def _resolve_current_user(token: str, db: Session) -> CurrentUser:
    """解码令牌并查找用户。任何失败都抛出 BizError。"""
    try:
        payload = decode_access_token(token)
    except (PyJWTError, ValueError) as exc:
        raise BizError(AuthErr.TOKEN_INVALID) from exc

    user_id = payload.get("user_id")
    if not user_id:
        raise BizError(AuthErr.TOKEN_INVALID, "Token missing user_id")

    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == user_id)

    # 检查账号是否被锁定
    if user.is_locked and user.locked_until and user.locked_until > now_iso():
        raise BizError(AuthErr.ACCOUNT_LOCKED)

    # token_version 检查：如果用户的 token_version 已经被提升（例如注销或密码重置后），令牌无效。
    token_ver = payload.get("token_version")
    if token_ver is not None and token_ver != user.token_version:
        raise BizError(AuthErr.TOKEN_EXPIRED, "Session invalidated – please login again")

    # 密码更改会撤销现有访问令牌
    # JWT iat 必须 >= user.updated_at（允许 5 秒时钟偏差容差）
    if user.updated_at:
        try:
            token_iat = payload.get("iat")
            if token_iat is not None:
                import datetime as _dt
                updated_at: str = user.updated_at  # type: ignore[assignment]
                updated = _dt.datetime.fromisoformat(updated_at)
                iat = float(token_iat)  # type: ignore[arg-type]
                token_time = _dt.datetime.fromtimestamp(iat, tz=_dt.UTC)
                if updated - token_time > _dt.timedelta(seconds=5):
                    raise BizError(AuthErr.TOKEN_EXPIRED, "Password changed – please login again")
        except ValueError:
            import logging
            logging.getLogger("auth.deps").warning(
                "Failed to parse updated_at/iat for token revocation check (user_id=%s)", user.id
            )

    profile = user.profile
    role: str = profile.role if profile else "member"
    return CurrentUser(
        id=int(user.id), # type: ignore[arg-type]
        account_level=str(user.account_level),
        role=role,
    )


def get_current_user(token: str = Depends(_parse_bearer), db: Session = Depends(get_session)) -> CurrentUser:
    """必选 JWT 认证依赖。抛出ERROR"""
    return _resolve_current_user(token, db)


def get_optional_user(token: str | None = Header(None, alias="Authorization"), db: Session = Depends(get_session)) -> CurrentUser | None:
    """可选 JWT 认证依赖。不抛出ERROR"""
    if not token:
        return None
    parts = token.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    try:
        return _resolve_current_user(parts[1], db)
    except (BizError, PyJWTError):
        return None


def RequireLevel(min_level: str):
    """
    级别（从低到高排列）：``local``, ``normal``, ``admin``。
    用法::
        @router.get("/admin-only")
        def admin_endpoint(cur: CurrentUser = Depends(RequireLevel("admin"))):
            ...
    """

    def checker(cur: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        required = _LEVEL_ORDER.get(min_level)
        current = _LEVEL_ORDER.get(cur.account_level, 0)
        if required is None or current < required:
            raise BizError(AuthErr.ACCOUNT_LEVEL_INSUFFICIENT)
        return cur

    return Depends(checker)


def get_sms_provider() -> SmsProvider:
    """返回已配置的短信服务提供商。"""
    import os
    if os.environ.get("LKM_ENV") == "test" or os.environ.get("PYTEST_RUNNING"):
        return ConsoleSmsProvider()
    raise RuntimeError(
        "No SMS provider configured. ConsoleProvider is forbidden outside test mode. "
        "Set LKM_SMS_PROVIDER to a real provider."
    )


def get_email_provider() -> EmailProvider:
    """返回已配置的邮件服务提供商。"""
    import os
    if os.environ.get("LKM_ENV") == "test" or os.environ.get("PYTEST_RUNNING"):
        return ConsoleEmailProvider()
    raise RuntimeError(
        "No Email provider configured. ConsoleProvider is forbidden outside test mode. "
        "Set LKM_EMAIL_PROVIDER to a real provider."
    )
