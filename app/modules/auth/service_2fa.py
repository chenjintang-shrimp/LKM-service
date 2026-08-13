"""双因素认证（TOTP）服务。"""

import hashlib

import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.err import BizError
from app.db.models import User
from app.db.repo import consume_once, get_or_raise, isolated_update
from app.modules.auth.errors import AuthErr
from app.modules.auth.models import TOTP, RecoveryCode, TempTokenUsage
from app.modules.auth.security import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
)
from app.modules.auth.service_auth import _issue_session_tokens, log_audit

_TOTP_MAX_FAILED = 3


def _check_totp_failed(totp_record: TOTP | None) -> None:
    if totp_record and totp_record.failed_attempts >= _TOTP_MAX_FAILED:
        raise BizError(AuthErr.TOTP_CODE_INVALID, "TOTP verification locked – too many failures")


def _record_totp_failure(db: Session, totp_record: TOTP | None) -> None:
    """通过子事务（保存点）递增 TOTP 失败计数器，使其在调用方事务因 BizError 回滚时仍能保留。"""
    if not totp_record:
        return

    from sqlalchemy import update as sa_update

    isolated_update(
        db,
        sa_update(TOTP)
        .where(TOTP.user_id == totp_record.user_id)
        .values(failed_attempts=TOTP.failed_attempts + 1),
    )
    db.refresh(totp_record)


def _reset_totp_failures(db: Session, totp_record: TOTP | None) -> None:
    """通过调用方会话重置 TOTP 失败计数 —— 仅在成功路径中调用。"""
    if totp_record and totp_record.failed_attempts > 0:
        totp_record.failed_attempts = 0
        db.flush()


def _decode_temp_token(raw_token: str) -> dict:
    """解码并验证临时令牌 JWT，但不消费它。"""
    try:
        payload = jwt.decode(
            raw_token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != "temp":
            raise ValueError("not a temp token")
    except Exception as exc:
        raise BizError(AuthErr.TOKEN_INVALID) from exc

    return payload


def _check_and_consume_temp_token(db: Session, raw_token: str, user_id: int, txn_id: str | None = None) -> dict:
    """在成功的第二因素验证后原子地消费临时令牌。"""
    from sqlalchemy.exc import IntegrityError

    payload = _decode_temp_token(raw_token)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    purpose = payload.get("purpose", "2fa")

    # 使用保存点来隔离插入尝试
    sp = db.begin_nested()
    try:
        usage = TempTokenUsage(
            token_hash=token_hash,
            user_id=user_id,
            purpose=purpose,
            txn_id=txn_id,
            consumed=True,
        )
        db.add(usage)
        db.flush()
        sp.commit()
    except IntegrityError:
        sp.rollback()
        # 其他人已认领这个哈希值 —— 检查是否已消费
        existing = db.query(TempTokenUsage).filter(
            TempTokenUsage.token_hash == token_hash,
        ).first()
        if existing and existing.consumed:
            raise BizError(AuthErr.TOKEN_INVALID, "Temp token already used")
        raise BizError(AuthErr.TOKEN_INVALID, "Temp token conflict")

    return payload


def _create_auth_tokens(db: Session, user: User, trust_device: bool = False) -> dict:
    """为给定用户发放访问令牌和刷新令牌。"""
    access_token, raw_refresh = _issue_session_tokens(
        db, user, trust_device=trust_device, mfa_verified=True,
    )
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "user_id": user.id,
        "account_level": user.account_level,
    }

def setup_2fa_begin(db: Session, user_id: int) -> dict:
    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == user_id)
    if user.account_level == "local":
        raise BizError(AuthErr.ACCOUNT_LEVEL_INSUFFICIENT)

    totp_record = db.query(TOTP).filter(TOTP.user_id == user_id).first()
    if totp_record and totp_record.enabled:
        raise BizError(AuthErr.TOTP_ALREADY_ENABLED)

    secret = generate_totp_secret()
    encrypted = encrypt_secret(secret)

    if totp_record:
        totp_record.secret = encrypted
        totp_record.enabled = False
        totp_record.confirmed_saved = False
        totp_record.failed_attempts = 0
    else:
        totp_record = TOTP(user_id=user_id, secret=encrypted, enabled=False)
        db.add(totp_record)
    db.flush()

    return {"secret": secret, "qr_code_uri": get_totp_uri(secret, user.username, settings.app_name)} # type: ignore[arg-type]

def setup_2fa_complete(db: Session, user_id: int, code: str) -> dict:
    totp_record = db.query(TOTP).filter(TOTP.user_id == user_id).first()
    if not totp_record or totp_record.enabled:
        raise BizError(AuthErr.TOTP_NOT_ENABLED)

    _check_totp_failed(totp_record) # type: ignore[arg-type]

    plain_secret = decrypt_secret(str(totp_record.secret))
    if verify_totp(plain_secret, code) is None:
        _record_totp_failure(db, totp_record) # type: ignore[arg-type]
        raise BizError(AuthErr.TOTP_CODE_INVALID)
    _reset_totp_failures(db, totp_record) # type: ignore[arg-type]

    totp_record.enabled = True
    totp_record.confirmed_saved = False
    db.flush()

    plain_codes: list[str] = []
    for plain, hashed in generate_recovery_codes(10):
        plain_codes.append(plain)
        rc = RecoveryCode(user_id=user_id, code_hash=hashed, used=False)
        db.add(rc)
    db.flush()

    log_audit(db, user_id, "2fa_enabled", "success")

    return {"recovery_codes": plain_codes, "confirmed_saved_required": True}


def confirm_recovery_codes_saved(db: Session, user_id: int) -> dict:
    """标记用户已保存其恢复码。"""
    totp_record = db.query(TOTP).filter(TOTP.user_id == user_id).first()
    if not totp_record or not totp_record.enabled:
        raise BizError(AuthErr.TOTP_NOT_ENABLED)
    totp_record.confirmed_saved = True
    db.flush()
    log_audit(db, user_id, "recovery_codes_confirmed", "success")
    return {"message": "Recovery codes confirmed saved"}

def verify_2fa(
    db: Session,
    temp_token: str,
    code: str | None = None,
    recovery_code: str | None = None,
    trust_device: bool = False,
) -> dict:
    # 仅解码 —— 不消费。消费在成功的第二因素验证*之后*进行，
    # 错误的TOTP/恢复码不会永久地消耗临时令牌或满足恢复检查。
    payload = _decode_temp_token(raw_token=temp_token)
    user_id = payload["user_id"]
    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == user_id)

    if str(user.account_level) == "admin":
        trust_device = False

    txn_id = payload.get("txn_id")

    if recovery_code:
        code_hash = hashlib.sha256(recovery_code.encode()).hexdigest()
        # 原子消费：仅在尚未使用时才标记为已使用
        if not consume_once(
            db,
            RecoveryCode,
            {"used": True},
            RecoveryCode.user_id == user_id,
            RecoveryCode.code_hash == code_hash,
            RecoveryCode.used.is_(False),
        ):
            raise BizError(AuthErr.RECOVERY_CODE_INVALID)
    elif code:
        totp_record = db.query(TOTP).filter(TOTP.user_id == user_id, TOTP.enabled.is_(True)).first()
        if not totp_record:
            raise BizError(AuthErr.TOTP_NOT_ENABLED)

        _check_totp_failed(totp_record) # type: ignore[arg-type]

        plain_secret = decrypt_secret(str(totp_record.secret))
        actual_counter = verify_totp(plain_secret, code)
        if actual_counter is None:
            _record_totp_failure(db, totp_record) # type: ignore[arg-type]
            raise BizError(AuthErr.TOTP_CODE_INVALID)

        _reset_totp_failures(db, totp_record) # type: ignore[arg-type]

        # 重放保护：原子地存储匹配的计数器
        from sqlalchemy import or_

        if not consume_once(
            db,
            TOTP,
            {"last_counter": actual_counter},
            TOTP.user_id == user_id,
            or_(TOTP.last_counter.is_(None), TOTP.last_counter < actual_counter),
        ):
            raise BizError(AuthErr.TOTP_CODE_INVALID, "TOTP code already used")
    else:
        raise BizError(AuthErr.TOTP_CODE_INVALID)

    # 成功 —— 现在原子地消费临时令牌
    _check_and_consume_temp_token(db, temp_token, user_id, txn_id=txn_id)

    purpose = payload.get("purpose", "2fa")

    # 临时令牌用途的严格白名单
    # 只有 "2fa" 可以发放登录会话。"recovery" 仅授予第二因素证明。
    # 任何其他用途都会被拒绝。
    _ALLOWED_PURPOSES = {"2fa", "recovery"}
    if purpose not in _ALLOWED_PURPOSES:
        raise BizError(AuthErr.TOKEN_INVALID, f"Temp token purpose '{purpose}' not allowed for 2FA verification")

    if purpose == "recovery":
        return {
            "access_token": None,
            "refresh_token": None,
            "user_id": user.id,
            "account_level": user.account_level,
            "trust_device": False,
            "mfa_verified": True,
            "message": "2FA verified for recovery",
        }

    # purpose == "2fa" —— 发放登录会话
    result = _create_auth_tokens(db, user, trust_device=trust_device) # type: ignore[arg-type]
    result["trust_device"] = trust_device
    return result

def disable_2fa(db: Session, user_id: int, code: str) -> dict:
    totp_record = db.query(TOTP).filter(TOTP.user_id == user_id).first()
    if not totp_record or not totp_record.enabled:
        raise BizError(AuthErr.TOTP_NOT_ENABLED)

    _check_totp_failed(totp_record) # type: ignore[arg-type]

    plain_secret = decrypt_secret(str(totp_record.secret))
    if verify_totp(plain_secret, code) is None:
        _record_totp_failure(db, totp_record) # type: ignore[arg-type]
        raise BizError(AuthErr.TOTP_CODE_INVALID)
    _reset_totp_failures(db, totp_record) # type: ignore[arg-type]

    totp_record.enabled = False
    totp_record.secret = ""
    totp_record.confirmed_saved = False
    totp_record.failed_attempts = 0
    totp_record.last_counter = None
    db.flush()

    db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()
    db.flush()

    level = db.query(User.account_level).filter(User.id == user_id).scalar()
    log_audit(db, user_id, "2fa_disabled", "success")

    if level == "admin":
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.account_level = "normal"
            db.flush()
            log_audit(db, user_id, "level_change", "admin -> normal (2FA disabled)")

    return {"message": "2FA disabled"}
