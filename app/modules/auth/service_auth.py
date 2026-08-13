"""认证服务 —— 注册、密码登录、升级、刷新令牌。"""

import hashlib
import secrets
import secrets as _s
from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.err import BizError, CommonErr
from app.db.models import Profile, User, expires_at, now_iso
from app.db.repo import consume_once, get_or_raise, isolated_update
from app.modules.auth.errors import AuthErr
from app.modules.auth.models import (
    TOTP,
    AuditLog,
    MagicLink,
    PendingRegistration,
    RefreshToken,
)
from app.modules.auth.providers.base import EmailProvider
from app.modules.auth.schemas import (
    UserLoginPassword,
    UserRegLocal,
    UserRegNormal,
)
from app.modules.auth.security import (
    create_access_token,
    create_temp_token,
    hashpwd,
    verifypwd,
)
from app.modules.auth.service_verify import check_code_rate_limit


@runtime_checkable
class BackgroundTasksLike(Protocol):
    def add_task(self, func, *args, **kwargs) -> None: ...

_FAIL_LOCK_THRESHOLD = 5
_FAIL_LOCK_MINUTES = 15


def _normalize_username(username: str) -> str:
    """规范化用户名：去除空白字符并转为小写。"""
    return username.strip().lower()


def _normalize_email(email: str) -> str:
    """规范化邮箱：去除空白字符并转为小写。"""
    return email.strip().lower()


def _generate_refresh_token() -> str:
    """返回一个加密安全的随机十六进制字符串（64 个字符）。"""
    return secrets.token_hex(32)


def _hash_refresh_token(raw: str) -> str:
    """对原始刷新令牌进行 SHA-256 哈希。"""
    return hashlib.sha256(raw.encode()).hexdigest()


def _store_refresh_token(db: Session, user_id: int, raw: str, mfa_verified: bool = False) -> str:
    """持久化哈希后的刷新令牌并返回其过期时间戳字符串。"""
    days = settings.refresh_token_expire_days
    expires_str = expires_at(days=days)
    tok = RefreshToken(
        user_id=user_id,
        token_hash=_hash_refresh_token(raw),
        mfa_verified=mfa_verified,
        expires_at=expires_str,
    )
    db.add(tok)
    db.flush()
    return expires_str


def _issue_session_tokens(
    db: Session, user: User, *, trust_device: bool = False, mfa_verified: bool = False
) -> tuple[str, str]:
    """发放访问令牌 + 刷新令牌，返回 (access_token, raw_refresh)。"""
    profile = user.profile
    role = profile.role if profile else "member"
    access_token = create_access_token(
        user_id=user.id,
        account_level=user.account_level,
        role=role,
        trust_device=trust_device,
        token_version=user.token_version,
    )
    raw_refresh = _generate_refresh_token()
    _store_refresh_token(db, user.id, raw_refresh, mfa_verified=mfa_verified)
    return access_token, raw_refresh


def _create_auth_response(
    db: Session, user: User, requires_2fa: bool = False
) -> dict:
    """构建作为登录 / 注册响应返回的字典。"""
    if requires_2fa:
        temp_token = create_temp_token(user.id)
        return {
            "access_token": None,
            "refresh_token": None,
            "user_id": user.id,
            "account_level": user.account_level,
            "requires_2fa": True,
            "temp_token": temp_token,
        }

    access_token, raw_refresh = _issue_session_tokens(db, user)
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "user_id": user.id,
        "account_level": user.account_level,
        "requires_2fa": False,
        "temp_token": None,
    }


def _check_account_locked(user: User) -> None:
    """检查用户是否被锁定 —— 但返回 INVALID_CREDENTIALS 以防止通过锁检测进行账号枚举。"""
    if not user.is_locked:
        return
    if user.locked_until:
        if user.locked_until > now_iso():
            # 执行虚拟哈希以保持时序一致
            from app.modules.auth.security import verifypwd as _vp
            _vp("dummy", "$dummy$" + "a" * 64)
            raise BizError(AuthErr.INVALID_CREDENTIALS)
        # 锁定已过期 —— 自动解锁
        user.is_locked = False
        user.locked_until = None
        user.failed_login_attempts = 0


def _record_failed_attempt(db: Session, user: User) -> None:
    """通过子事务（保存点）递增登录失败计数器。"""
    from sqlalchemy import update as sa_update

    isolated_update(
        db,
        sa_update(User)
        .where(User.id == user.id)
        .values(failed_login_attempts=User.failed_login_attempts + 1),
    )
    db.refresh(user)

    if user.failed_login_attempts >= _FAIL_LOCK_THRESHOLD:
        locked_until = expires_at(minutes=_FAIL_LOCK_MINUTES)
        isolated_update(
            db,
            sa_update(User)
            .where(User.id == user.id)
            .values(is_locked=True, locked_until=locked_until),
        )
        db.refresh(user)

def register_local(db: Session, info: UserRegLocal) -> dict:
    """创建一个 ``local`` 账户，若已存在且密码正确则自动登录。"""
    username = _normalize_username(info.username)
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        hashed: str = existing.hashed_password  # type: ignore[assignment]
        if not hashed or not verifypwd(info.password, hashed):
            raise BizError(AuthErr.ALREADY_REGISTERED, "Account exists but password is incorrect")
        upgrade_to_normal(db, existing) # type: ignore[arg-type]
        return _create_auth_response(db, existing) # type: ignore[arg-type]

    user = User(
        username=username,
        hashed_password=hashpwd(info.password),
        account_level="local",
    )
    db.add(user)
    db.flush()

    db.add(Profile(user_id=user.id, role="member"))
    db.flush()

    return _create_auth_response(db, user)


#TODO: 确认调用点并按需删除
def _handle_duplicate_user_error(exc: Exception) -> None:
    """如果是唯一性违规，将 IntegrityError 重新抛出为 ALREADY_REGISTERED。"""
    from sqlalchemy.exc import IntegrityError
    if isinstance(exc, IntegrityError):
        raise BizError(AuthErr.ALREADY_REGISTERED, "Account already exists") from exc
    raise


def register_normal_with_password(
    db: Session,
    info: UserRegNormal,
    email_verified: bool = False,
    phone_verified: bool = False,
) -> dict:
    """创建一个带密码的 ``normal`` 账户，若已存在且密码正确则自动登录。"""
    has_email = info.email is not None
    has_phone = info.phone is not None
    if not has_email and not has_phone:
        raise BizError(CommonErr.INVALID_INPUT, "email or phone must be provided")
    if has_email and not email_verified:
        raise BizError(CommonErr.INVALID_INPUT, "email must be verified")
    if has_phone and not phone_verified:
        raise BizError(CommonErr.INVALID_INPUT, "phone must be verified")

    username = _normalize_username(info.username)
    email_normalized = _normalize_email(info.email) if info.email else None

    existing = (
        db.query(User)
        .filter(
            (User.username == username)
            | ((User.email == email_normalized) if email_normalized else False)
            | (User.phone == info.phone)
        )
        .first()
    )
    if existing:
        hashed: str = existing.hashed_password  # type: ignore[assignment]
        if not hashed or not verifypwd(info.password, hashed):
            raise BizError(AuthErr.ALREADY_REGISTERED, "Account exists but password is incorrect")
        if email_normalized and not existing.email:
            existing.email = email_normalized
        if info.phone and not existing.phone:
            existing.phone = info.phone
        upgrade_to_normal(db, existing) # type: ignore[arg-type]
        db.flush()
        return _create_auth_response(db, existing) # type: ignore[arg-type]

    user = User(
        username=username,
        hashed_password=hashpwd(info.password),
        email=email_normalized,
        phone=info.phone,
        account_level="normal",
    )
    db.add(user)
    db.flush()

    db.add(Profile(user_id=user.id, role="member"))
    db.flush()

    return _create_auth_response(db, user)


def register_by_verify(db: Session, field: str, value: str) -> dict:
    """通过邮箱或手机验证创建一个*无密码*的普通用户，若已存在则自动登录。"""
    if field not in ("email", "phone"):
        raise BizError(CommonErr.INVALID_INPUT, "field must be 'email' or 'phone'")

    # 规范化并检查重复
    if field == "email":
        normalized_value = _normalize_email(value)
        existing = db.query(User).filter(User.email == normalized_value).first()
    else:
        normalized_value = value
        existing = db.query(User).filter(User.phone == normalized_value).first()

    if existing:
        upgrade_to_normal(db, existing)  # type: ignore[arg-type]
        db.flush()
        log_audit(db, existing.id, "register_code", f"auto-login via {field}")
        return _create_auth_response(db, existing)  # type: ignore[arg-type]

    # 从值中派生用户名
    if field == "email":
        username = value.split("@")[0]
    else:
        username = f"user_{value[-6:]}"

    # 确保唯一性
    suffix = 1
    base = username
    while db.query(User).filter(User.username == username).first():
        username = f"{base}{suffix}"
        suffix += 1

    user = User(
        username=username,
        email=normalized_value if field == "email" else None,
        phone=value if field == "phone" else None,
        hashed_password="",
        account_level="normal",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="member"))
    db.flush()

    log_audit(db, user.id, "register_code", f"registered via {field}")
    return _create_auth_response(db, user)

def _store_pending_normal_registration(
    db: Session,
    username: str,
    password: str,
    email: str | None,
    phone: str | None,
) -> str:

    txn_id = _s.token_hex(32)
    expiry = expires_at(minutes=15)

    record = PendingRegistration(
        txn_id=txn_id,
        username=_normalize_username(username),
        hashed_password=hashpwd(password),
        email=_normalize_email(email) if email else None,
        phone=phone,
        consumed=False,
        expires_at=expiry,
    )
    db.add(record)
    db.flush()
    return txn_id


def _consume_pending_normal_registration(
    db: Session,
    txn_id: str,
    email_code: str | None = None,
    phone_code: str | None = None,
) -> dict:
    from app.modules.auth.models import PendingRegistration
    from app.modules.auth.service_verify import consume_email_code, consume_phone_code

    pending = get_or_raise(
        db, PendingRegistration, AuthErr.TOKEN_INVALID,
        PendingRegistration.txn_id == txn_id,
        detail="Invalid registration transaction",
    )
    if pending.consumed:
        raise BizError(AuthErr.TOKEN_INVALID, "Registration already completed")
    if pending.expires_at <= now_iso():
        raise BizError(AuthErr.TOKEN_EXPIRED, "Registration expired")

    # 验证所有提交的联系方式 —— 每个提供的联系方式都必须经过验证。
    from sqlalchemy.exc import IntegrityError, OperationalError
    sp = db.begin_nested()
    try:
        if pending.email:
            assert email_code is not None
            consume_email_code(db, str(pending.email), email_code, "register")
        if pending.phone:
            assert phone_code is not None
            consume_phone_code(db, str(pending.phone), phone_code, "register")
        sp.commit()
    except (IntegrityError, OperationalError):
        sp.rollback()
        raise

    pending.consumed = True
    db.flush()

    # 检查重复 —— 如果已存在且密码正确则自动登录
    existing = db.query(User).filter(
        (User.username == pending.username)
        | ((User.email == pending.email) if pending.email else False)
        | ((User.phone == pending.phone) if pending.phone else False)
    ).first()
    if existing:
        hashed: str = existing.hashed_password  # type: ignore[assignment]
        pending_hashed: str = pending.hashed_password  # type: ignore[assignment]
        if not hashed or not verifypwd(pending_hashed, hashed):
            raise BizError(AuthErr.ALREADY_REGISTERED, "Account exists but password is incorrect")
        # 将联系方式绑定到已有账户
        if pending.email and not existing.email:
            existing.email = pending.email
        if pending.phone and not existing.phone:
            existing.phone = pending.phone
        upgrade_to_normal(db, existing) # type: ignore[arg-type]
        db.flush()
        log_audit(db, existing.id, "register_normal", "auto-login via registration")
        return _create_auth_response(db, existing) # type: ignore[arg-type]

    user = User(
        username=str(pending.username),
        email=str(pending.email) if pending.email else None,
        phone=str(pending.phone) if pending.phone else None,
        hashed_password=str(pending.hashed_password),
        account_level="normal",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="member"))
    db.flush()

    log_audit(db, user.id, "register_normal", "password registration complete")
    return _create_auth_response(db, user)

def _check_admin_totp_required(db: Session, user: User) -> dict | None:
    """如果用户是管理员但尚未设置 TOTP，返回 setup 响应；否则返回 None。"""
    if str(user.account_level) != "admin":
        return None
    totp = db.query(TOTP).filter(TOTP.user_id == user.id).first()
    if totp and totp.enabled:
        return None
    setup_token = create_temp_token(user.id, purpose="setup")
    return {
        "access_token": None,
        "refresh_token": None,
        "user_id": int(user.id),
        "account_level": str(user.account_level),
        "requires_2fa": True,
        "setup_required": True,
        "temp_token": setup_token,
    }


def _finalize_auth_response(db: Session, user: User) -> dict:
    """检查管理员 TOTP 和 2FA 要求，返回认证响应。"""
    admin_setup = _check_admin_totp_required(db, user)
    if admin_setup is not None:
        return admin_setup

    requires_2fa = False
    if str(user.account_level) in ("normal", "admin"):
        totp = db.query(TOTP).filter(TOTP.user_id == user.id, TOTP.enabled.is_(True)).first()
        if totp:
            requires_2fa = True

    return _create_auth_response(db, user, requires_2fa=requires_2fa)  # type: ignore[arg-type]


def login_password(db: Session, info: UserLoginPassword, ip_address: str = "") -> dict:
    """通过用户名、邮箱或手机号 + 密码进行认证。"""
    from app.core.throttle import check_password_login_rate_limit
    if ip_address:
        check_password_login_rate_limit(ip_address)

    account = _normalize_username(info.account)
    email_normalized = _normalize_email(info.account)

    user = (
        db.query(User)
        .filter(
            (User.username == account)
            | (User.email == email_normalized)
            | (User.phone == info.account.strip())
        )
        .first()
    )

    if not user:
        # 防御用户枚举：执行一个相同成本的虚拟哈希，
        verifypwd(info.password, "$dummy$" + "a" * 64)
        raise BizError(AuthErr.INVALID_CREDENTIALS)

    _check_account_locked(user) # type: ignore[arg-type]

    try:
        ok = verifypwd(info.password, str(user.hashed_password))
    except (ValueError, TypeError):
        import logging
        logging.getLogger("auth.login").exception(
            "verifypwd raised exception for user_id=%s (possible corrupted hash)", user.id
        )
        ok = False
    if not ok:
        _record_failed_attempt(db, user) # type: ignore[arg-type]
        if user.failed_login_attempts >= _FAIL_LOCK_THRESHOLD:
            log_audit(db, user.id, "account_locked", "5 failed login attempts")
        raise BizError(AuthErr.INVALID_CREDENTIALS)

    # 成功 —— 通过子事务（savepoint）原子性地重置计数器，
    # 防止调用方回滚时把失败计数器也一并回滚。
    from sqlalchemy import update as sa_update
    isolated_update(
        db,
        sa_update(User)
        .where(User.id == user.id)
        .values(failed_login_attempts=0, is_locked=False, locked_until=None),
    )
    db.refresh(user)

    log_audit(db, user.id, "login_password", "success")

    return _finalize_auth_response(db, user) # type: ignore[arg-type]


def login_code(db: Session, contact: str, code: str) -> dict:
    """使用有时效性的验证码进行认证。"""
    from app.modules.auth.service_verify import consume_email_code, consume_phone_code

    if "@" in contact:
        consume_email_code(db, contact, code, "login")
        user = get_or_raise(
            db, User, AuthErr.USER_NOT_FOUND, User.email == _normalize_email(contact),
        )
    else:
        consume_phone_code(db, contact, code, "login")
        user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.phone == contact)

    if user.account_level == "local":
        raise BizError(AuthErr.ACCOUNT_LEVEL_INSUFFICIENT)

    if user.is_locked:
        _check_account_locked(user) # type: ignore[arg-type]

    # 没有 TOTP 的管理员 —— 与密码登录相同的设置流程
    return _finalize_auth_response(db, user) # type: ignore[arg-type]

def request_magic_link(
    db: Session,
    email: str,
    email_provider: EmailProvider,
    purpose: str = "login",
    frontend_url: str = "",
    background_tasks: BackgroundTasksLike | None = None,
) -> None:
    """仅在用户存在时为*邮箱*生成一个魔法链接。

    速率限制为每（邮箱, 用途）对每小时 5 次请求。
    原始令牌为 64 个十六进制字符；仅存储其 SHA-256 哈希值。

    对于不存在的用户，响应和时序无法区分
    —— 不会创建或发送链接，但仍会消耗速率限制配额。
    """
    rate_limit_key = f"magiclink:{email}"
    check_code_rate_limit(rate_limit_key, max_count=5, window=3600)

    user = db.query(User).filter(User.email == email).first()
    if not user or user.account_level == "local":
        # 无操作：不创建也不发送，但速率限制在上方已被消耗
        return

    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    expiry = expires_at(minutes=15)

    link_record = MagicLink(
        email=email,
        token_hash=token_hash,
        purpose=purpose,
        expires_at=expiry,
    )
    db.add(link_record)
    db.flush()

    base_url = frontend_url or settings.api_prefix
    link = f"{base_url}/auth/login/magic-link/verify?token={raw_token}"

    if background_tasks is not None:
        background_tasks.add_task(email_provider.send_magic_link, email, link)


def verify_magic_link(
    db: Session,
    token: str,
    purpose: str = "login",
) -> dict:
    """
    验证魔法链接令牌并返回认证响应。
    可能抛出的异常：
        BizError(TOKEN_INVALID)  – 令牌未找到、用途不匹配或已被使用
        BizError(TOKEN_EXPIRED)  – 令牌已过期
        BizError(USER_NOT_FOUND) – 不存在与该链接邮箱关联的用户
        BizError(ACCOUNT_LEVEL_INSUFFICIENT) – 用户为 ``local`` 级别
        BizError(TOTP_SETUP_REQUIRED) – 管理员用户未启用 TOTP
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    now = now_iso()

    # 原子消费：仅在尚未使用、未过期且用途匹配时才标记为已使用。
    # 这可防止并发重放攻击。
    if not consume_once(
        db,
        MagicLink,
        {"used": True},
        MagicLink.token_hash == token_hash,
        MagicLink.used.is_(False),
        MagicLink.purpose == purpose,
        MagicLink.expires_at > now,
    ):
        # 令牌可能已过期或不存在 —— 检查具体是哪一种情况
        link_record = (
            db.query(MagicLink)
            .filter(MagicLink.token_hash == token_hash)
            .first()
        )
        if not link_record:
            raise BizError(AuthErr.TOKEN_INVALID)
        if link_record.purpose != purpose:
            raise BizError(AuthErr.TOKEN_INVALID)
        if link_record.used:
            raise BizError(AuthErr.TOKEN_INVALID)
        # 必然是已过期
        raise BizError(AuthErr.TOKEN_EXPIRED)

    # 原子更新后重新获取
    link_record = get_or_raise(
        db, MagicLink, AuthErr.TOKEN_INVALID,
        MagicLink.token_hash == token_hash,
    )

    user = get_or_raise(
        db, User, AuthErr.USER_NOT_FOUND, User.email == link_record.email,
    )

    if user.account_level == "local":
        raise BizError(AuthErr.ACCOUNT_LEVEL_INSUFFICIENT)

    # 没有 TOTP 的管理员必须设置它
    if user.account_level == "admin":
        totp = db.query(TOTP).filter(TOTP.user_id == user.id).first()
        if not totp or not totp.enabled:
            raise BizError(AuthErr.TOTP_SETUP_REQUIRED)

    # 与 login_password 相同的 2FA 检查
    requires_2fa = False
    if user.account_level in ("normal", "admin"):
        totp = db.query(TOTP).filter(TOTP.user_id == user.id, TOTP.enabled.is_(True)).first()
        if totp:
            requires_2fa = True

    return _create_auth_response(db, user, requires_2fa=requires_2fa) # type: ignore[arg-type]

def upgrade_to_normal(db: Session, user: User) -> None:
    """将 ``local`` 用户升级为 ``normal``。对于已是 normal 或 admin 的用户无操作。"""
    if user.account_level == "local":
        user.account_level = "normal"
        db.flush()
        log_audit(db, user.id, "level_change", "local -> normal")


def refresh_access_token(db: Session, raw_refresh: str) -> dict:
    tok_hash = _hash_refresh_token(raw_refresh)
    now = now_iso()

    # 原子撤销：仅在令牌存在且尚未被撤销时才撤销
    if not consume_once(
        db,
        RefreshToken,
        {"revoked_at": now},
        RefreshToken.token_hash == tok_hash,
        RefreshToken.revoked_at.is_(None),
    ):
        # 令牌已被使用、不存在或已被撤销
        raise BizError(AuthErr.TOKEN_INVALID)

    # 现在获取记录以得到 user_id 和 mfa_verified
    stored = get_or_raise(
        db, RefreshToken, AuthErr.TOKEN_INVALID,
        RefreshToken.token_hash == tok_hash,
    )

    # 过期检查
    if stored.expires_at <= now:
        raise BizError(AuthErr.TOKEN_EXPIRED)

    # 发放新令牌
    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == stored.user_id)

    # 管理员用户的刷新令牌会话必须经过 MFA 认证
    if user.account_level == "admin" and not stored.mfa_verified:
        raise BizError(AuthErr.TOKEN_INVALID, "Admin refresh token requires MFA assurance")

    access_token, raw_new = _issue_session_tokens(db, user, mfa_verified=stored.mfa_verified)
    return {"access_token": access_token, "refresh_token": raw_new}

def revoke_all_refresh_tokens(db: Session, user_id: int) -> None:
    """撤销指定用户所有未撤销的刷新令牌，并使其所有访问令牌失效。"""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    ).update({"revoked_at": now_iso()}, synchronize_session="fetch")
    # 递增 token_version 以使所有现有访问令牌失效
    from sqlalchemy import update as sa_update
    db.execute(
        sa_update(User)
        .where(User.id == user_id)
        .values(token_version=User.token_version + 1)
    )
    db.flush()


def log_audit(
    db: Session,
    user_id: int | None,
    action: str,
    detail: str | None = None,
    ip_address: str | None = None,
) -> None:
    """创建一条审计日志记录。"""
    uid: int | None = user_id if user_id is not None else None
    entry = AuditLog(
        user_id=uid,
        action=action,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    db.flush()
