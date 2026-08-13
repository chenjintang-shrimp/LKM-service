"""密码恢复服务。"""

from sqlalchemy.orm import Session

from app.core.err import BizError, CommonErr
from app.db.models import User, expires_at, now_iso
from app.db.repo import consume_once, get_or_raise
from app.modules.auth.errors import AuthErr
from app.modules.auth.models import TOTP, RecoveryTransaction
from app.modules.auth.security import hashpwd
from app.modules.auth.service_auth import (
    BackgroundTasksLike,
    log_audit,
    revoke_all_refresh_tokens,
    verify_magic_link,
)
from app.modules.auth.service_verify import (
    consume_email_code,
    consume_phone_code,
)


def _find_user_by_contact(db: Session, field: str, value: str) -> User:
    """通过邮箱或手机号查找用户。"""
    if field == "email":
        user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.email == value)
    elif field == "phone":
        user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.phone == value)
    else:
        raise BizError(CommonErr.INVALID_INPUT, "field must be 'email' or 'phone'")

    if user.account_level == "local":
        raise BizError(AuthErr.RECOVERY_NOT_SUPPORTED, "Local accounts do not support recovery")

    if user.account_level == "admin":
        raise BizError(
            AuthErr.RECOVERY_METHOD_UNAVAILABLE,
            "Admin accounts must use the dedicated admin recovery flow",
        )

    return user # type: ignore[arg-type]


def _user_requires_mfa(db: Session, user: User) -> bool:
    """如果用户启用了 TOTP 并且必须使用第二因素验证，则返回 True。"""
    if user.account_level == "admin":
        return True
    totp = db.query(TOTP).filter(TOTP.user_id == user.id, TOTP.enabled.is_(True)).first()
    return totp is not None


def _reset_password(db: Session, user: User, new_password: str) -> None:
    """哈希新密码、设置它、解锁账户、撤销所有令牌，并记录审计日志。"""
    user.hashed_password = hashpwd(new_password)
    user.is_locked = False
    user.locked_until = None
    user.failed_login_attempts = 0
    user.updated_at = now_iso()  # 使已发放的访问令牌失效（iat < updated_at）
    db.flush()

    revoke_all_refresh_tokens(db, user.id)

    log_audit(db, user.id, "password_reset", detail="recovery")

def check_recovery_methods(_db: Session, _account: str) -> dict:
    """检查账户可用的恢复方法。 """
    # 始终统一 —— 不泄露账户是否存在、是否为 local 或 admin
    return {"recoverable": False}

def recover_by_phone(db: Session, phone: str, code: str, new_password: str | None = None) -> dict:
    """第 1 步：验证手机联系方式以进行密码恢复。 """
    consume_phone_code(db, phone, code, "reset")
    user = _find_user_by_contact(db, "phone", phone)

    if _user_requires_mfa(db, user):
        return _start_user_recovery_txn(db, user)

    if not new_password:
        raise BizError(CommonErr.INVALID_INPUT, "new_password is required")
    _reset_password(db, user, new_password)
    return {"message": "Password reset successful"}


def recover_by_email_code(db: Session, email: str, code: str, new_password: str | None = None) -> dict:
    """第 1 步：验证邮箱联系方式以进行密码恢复。 """
    consume_email_code(db, email, code, "reset")
    user = _find_user_by_contact(db, "email", email)

    if _user_requires_mfa(db, user):
        return _start_user_recovery_txn(db, user)

    if not new_password:
        raise BizError(CommonErr.INVALID_INPUT, "new_password is required")
    _reset_password(db, user, new_password)
    return {"message": "Password reset successful"}


def recover_by_magic_link(db: Session, token: str, new_password: str | None = None) -> dict:
    """第 1 步：验证密码恢复的魔法链接。"""
    verify_magic_link(db, token, purpose="reset")

    import hashlib

    from app.modules.auth.models import MagicLink

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    link_record = get_or_raise(
        db, MagicLink, AuthErr.TOKEN_INVALID,
        MagicLink.token_hash == token_hash,
    )

    user = get_or_raise(
        db, User, AuthErr.USER_NOT_FOUND, User.email == link_record.email,
    )

    if user.account_level == "admin":
        raise BizError(
            AuthErr.RECOVERY_METHOD_UNAVAILABLE,
            "Admin accounts must use the dedicated admin recovery flow",
        )

    if _user_requires_mfa(db, user): # type: ignore[arg-type]
        return _start_user_recovery_txn(db, user) # type: ignore[arg-type]

    if not new_password:
        raise BizError(CommonErr.INVALID_INPUT, "new_password is required")
    _reset_password(db, user, new_password) # type: ignore[arg-type]
    return {"message": "Password reset successful"}


def _start_user_recovery_txn(db: Session, user: User) -> dict:
    """为启用了 MFA 的用户创建恢复事务，并返回requires_2fa 详情，以便调用方在重置前完成 2FA。"""
    txn_id = _generate_recovery_txn_id()
    expiry = expires_at(minutes=15)

    from app.modules.auth.security import create_temp_token

    contact = user.email or user.phone or ""
    txn = RecoveryTransaction(
        txn_id=txn_id,
        user_id=user.id,
        contact=contact,
        contact_verified=True,
        totp_verified=False,
        consumed=False,
        state="second_factor_pending",
        expires_at=expiry,
    )
    db.add(txn)
    db.flush()

    temp_token = create_temp_token(user.id, purpose="recovery", txn_id=txn_id)

    return {
        "message": "MFA required. Complete 2FA to finish password reset.",
        "requires_2fa": True,
        "txn_id": txn_id,
        "temp_token": temp_token,
    }

def _generate_recovery_txn_id() -> str:
    import secrets
    return secrets.token_hex(32)


def recover_admin_begin(
    db: Session, contact: str,
    background_tasks: BackgroundTasksLike | None = None,
) -> dict:
    """第 1 步：启动管理员恢复。服务层负责生成验证码并通过 background_tasks 发送。"""

    from app.modules.auth.deps import get_email_provider, get_sms_provider

    user = db.query(User).filter(
        (User.email == contact) | (User.phone == contact)
    ).first()

    if user and str(user.account_level) == "admin":
        txn_id = _generate_recovery_txn_id()
        expiry = expires_at(minutes=15)

        txn = RecoveryTransaction(
            txn_id=txn_id,
            user_id=user.id, # type: ignore[arg-type]
            contact=contact,
            contact_verified=False,
            totp_verified=False,
            consumed=False,
            state="contact_pending",
            expires_at=expiry,
        )
        db.add(txn)
        db.flush()

        from app.modules.auth.service_verify import (
            check_code_rate_limit,
            create_email_verification,
            create_phone_verification,
        )

        if "@" in contact:
            check_code_rate_limit(f"recover:admin:{contact}", max_count=3, window=3600)
            code, _ = create_email_verification(db, contact, "reset")
            if background_tasks is not None:
                background_tasks.add_task(get_email_provider().send_code, contact, code)
        else:
            check_code_rate_limit(f"recover:admin:{contact}", max_count=3, window=3600)
            code, _ = create_phone_verification(db, contact, "reset")
            if background_tasks is not None:
                background_tasks.add_task(get_sms_provider().send_code, contact, code)

        return {
            "message": "If the account is eligible, recovery instructions have been sent.",
            "txn_id": txn_id,
        }

    from app.modules.auth.security import verifypwd as _vpw
    from app.modules.auth.service_verify import check_code_rate_limit

    check_code_rate_limit(f"recover:admin:{contact}", max_count=3, window=3600)
    _vpw("dummy", "$dummy$" + "a" * 64)
    return {"message": "If the account is eligible, recovery instructions will be sent to the registered contact."}


def _get_recovery_txn(db: Session, txn_id: str):
    txn = get_or_raise(
        db, RecoveryTransaction, AuthErr.TOKEN_INVALID,
        RecoveryTransaction.txn_id == txn_id,
        detail="Invalid recovery transaction",
    )
    if txn.consumed:
        raise BizError(AuthErr.TOKEN_INVALID, "Recovery transaction already used")
    if txn.expires_at <= now_iso():
        raise BizError(AuthErr.TOKEN_EXPIRED, "Recovery transaction expired")
    return txn


def recover_admin_verify_contact(db: Session, txn_id: str, code: str) -> dict:
    """第 2 步：在恢复事务中验证管理员的邮箱/手机验证码。"""
    txn = _get_recovery_txn(db, txn_id)

    if "@" in txn.contact:
        consume_email_code(db, txn.contact, code, "reset") # type: ignore[arg-type]
    else:
        consume_phone_code(db, txn.contact, code, "reset") # type: ignore[arg-type]

    txn.contact_verified = True
    db.flush()

    from app.modules.auth.security import create_temp_token
    temp_token = create_temp_token(txn.user_id, purpose="recovery", txn_id=txn_id) # type: ignore[arg-type]

    return {
        "message": "Contact verified. Proceed to 2FA verification.",
        "txn_id": txn_id,
        "temp_token": temp_token,
    }


def recover_admin_verify_totp(db: Session, txn_id: str, temp_token: str) -> dict:
    """第 3 步：确认管理员已通过此恢复事务的 2FA 验证。"""
    import hashlib

    from app.modules.auth.models import TempTokenUsage
    from app.modules.auth.security import decode_temp_token

    txn = _get_recovery_txn(db, txn_id)

    if not txn.contact_verified:
        raise BizError(AuthErr.RECOVERY_METHOD_UNAVAILABLE, "Contact verification required first")

    try:
        payload = decode_temp_token(temp_token)
    except Exception as exc:
        raise BizError(AuthErr.TOKEN_INVALID, "Invalid 2FA temp token") from exc

    user_id = payload.get("user_id", payload.get("sub"))
    if user_id != txn.user_id:
        raise BizError(AuthErr.TOKEN_INVALID, "Token user does not match recovery transaction user")

    if payload.get("purpose") != "recovery":
        raise BizError(AuthErr.TOKEN_INVALID, "Token was not issued for recovery")

    if payload.get("txn_id") != txn_id:
        raise BizError(AuthErr.TOKEN_INVALID, "Token does not match this recovery transaction")

    # 必须已被 /auth/2fa/verify 消费 —— 在成功的 2FA 之后
    token_hash = hashlib.sha256(temp_token.encode()).hexdigest()
    usage = db.query(TempTokenUsage).filter(
        TempTokenUsage.token_hash == token_hash,
        TempTokenUsage.user_id == user_id,
        TempTokenUsage.purpose == "recovery",
        TempTokenUsage.txn_id == txn_id,
        TempTokenUsage.consumed.is_(True),
    ).first()
    if not usage:
        raise BizError(AuthErr.TOKEN_INVALID, "Temp token not verified – complete 2FA first")

    txn.totp_verified = True
    db.flush()

    return {
        "message": "2FA verified. You may now set a new password.",
        "txn_id": txn_id,
    }


def _consume_recovery_txn(db: Session, txn_id: str) -> User:
    """原子消费恢复事务，返回关联的用户。"""
    now = now_iso()

    if not consume_once(
        db,
        RecoveryTransaction,
        {"consumed": True, "completed_at": now},
        RecoveryTransaction.txn_id == txn_id,
        RecoveryTransaction.consumed.is_(False),
        RecoveryTransaction.contact_verified.is_(True),
        RecoveryTransaction.totp_verified.is_(True),
        RecoveryTransaction.expires_at > now,
    ):
        raise BizError(AuthErr.TOKEN_INVALID, "Recovery transaction invalid or already consumed")

    txn = get_or_raise(
        db, RecoveryTransaction, AuthErr.TOKEN_INVALID,
        RecoveryTransaction.txn_id == txn_id,
    )

    user = get_or_raise(
        db, User, AuthErr.USER_NOT_FOUND, User.id == int(txn.user_id), # type: ignore[arg-type]
    )

    return user


def recover_user_complete(
    db: Session, txn_id: str, new_password: str
) -> dict:
    """在 2FA 之后完成用户（非管理员）的恢复事务。"""
    user = _consume_recovery_txn(db, txn_id)

    if str(user.account_level) == "admin":
        raise BizError(
            AuthErr.RECOVERY_METHOD_UNAVAILABLE,
            "Admin accounts must use the dedicated admin recovery flow",
        )

    _reset_password(db, user, new_password)  # type: ignore[arg-type]

    return {"message": "Password reset successful"}


def recover_admin_complete(
    db: Session, txn_id: str, new_password: str
) -> dict:
    """第 4 步：使用新密码原子地完成管理员恢复。使用条件 UPDATE 确保只有一个调用方会成功。"""
    user = _consume_recovery_txn(db, txn_id)

    if str(user.account_level) != "admin":
        raise BizError(AuthErr.ACCOUNT_LEVEL_INSUFFICIENT)

    _reset_password(db, user, new_password)

    return {"message": "Password reset successful"}
