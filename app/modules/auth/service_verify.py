"""验证码服务：生成、哈希、创建、消费、速率限制。"""

import datetime
import hashlib
import hmac
import secrets

from sqlalchemy import update as sa_update

from app.core.err import BizError
from app.core.throttle import RateLimiter
from app.db.models import now_iso
from app.db.repo import consume_once, isolated_update
from app.modules.auth.errors import AuthErr
from app.modules.auth.models import EmailVerification, PhoneVerification

_CODE_EXPIRE_MINUTES = 10
_MAX_FAILED_ATTEMPTS = 3

_rate_limiter = RateLimiter()

def generate_code() -> str:
    """返回一个 6 位数字验证码，格式为零填充字符串。"""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code(raw: str, purpose: str = "", contact: str = "", nonce: str = "") -> str:
    import hmac

    from app.core.config import settings
    pepper = settings.verification_code_pepper.encode()
    msg = f"{raw}:{purpose}:{contact}:{nonce}".encode()
    return hmac.new(pepper, msg, hashlib.sha256).hexdigest()

def _create_verification(
    db, model, contact_attr: str, contact: str, purpose: str
) -> tuple[str, int]:
    """创建一条验证码记录并返回 (明文验证码, 记录ID)。"""
    code = generate_code()
    nonce = secrets.token_hex(8)
    record = model(
        **{contact_attr: contact},  # type: ignore[call-arg]
        code_hash=hash_code(code, purpose, contact=contact, nonce=nonce),
        nonce=nonce,
        purpose=purpose,
        expires_at=_expires_at(),
    )
    db.add(record)
    db.flush()
    db.refresh(record)
    return code, record.id


def _latest_verification(db, model, contact_attr: str, contact: str, purpose: str):
    """取该联系方式未使用的最新一条验证码记录。"""
    return (
        db.query(model)
        .filter(
            getattr(model, contact_attr) == contact,
            model.purpose == purpose,
            model.used.is_(False),
        )
        .order_by(model.created_at.desc())
        .first()
    )


def create_email_verification(
    db, email: str, purpose: str
) -> tuple[str, int]:
    """创建一个 EmailVerification 记录并返回 (明文验证码, 记录ID)。"""
    return _create_verification(db, EmailVerification, "email", email, purpose)


def create_phone_verification(
    db, phone: str, purpose: str
) -> tuple[str, int]:
    """创建一个 PhoneVerification 记录并返回 (明文验证码, 记录ID)。"""
    return _create_verification(db, PhoneVerification, "phone", phone, purpose)

def consume_email_code(
    db, email: str, code: str, purpose: str
) -> bool:
    """验证并消费最新匹配的 EmailVerification。"""
    record = _latest_verification(db, EmailVerification, "email", email, purpose)
    return _consume(db, record, code)


def consume_phone_code(
    db, phone: str, code: str, purpose: str
) -> bool:
    """验证并消费最新匹配的 PhoneVerification。"""
    record = _latest_verification(db, PhoneVerification, "phone", phone, purpose)
    return _consume(db, record, code)


def _consume(db, record, code: str) -> bool:
    if record is None:
        raise BizError(AuthErr.VERIFICATION_CODE_INVALID)

    now = now_iso()

    # 过期检查
    if record.expires_at <= now:
        raise BizError(AuthErr.VERIFICATION_CODE_EXPIRED)

    # 失败尝试次数过多
    if record.failed_attempts >= _MAX_FAILED_ATTEMPTS:
        raise BizError(AuthErr.VERIFICATION_CODE_INVALID)

    # 验证码不匹配 —— 通过子事务（保存点）递增计数器，
    contact = getattr(record, "email", None) or getattr(record, "phone", "")
    if not hmac.compare_digest(record.code_hash, hash_code(code, record.purpose, contact=contact, nonce=record.nonce)):
        record_cls = type(record)
        isolated_update(
            db,
            sa_update(record_cls)
            .where(record_cls.id == record.id)
            .values(failed_attempts=record_cls.failed_attempts + 1),
        )
        db.refresh(record)
        raise BizError(AuthErr.VERIFICATION_CODE_INVALID)

    record_cls = type(record)
    if not consume_once(
        db,
        record_cls,
        {"used": True},
        record_cls.id == record.id,
        record_cls.used.is_(False),
        record_cls.failed_attempts < _MAX_FAILED_ATTEMPTS,
        record_cls.expires_at > now,
    ):
        raise BizError(AuthErr.VERIFICATION_CODE_INVALID)

    return True

def check_code_rate_limit(
    key: str, max_count: int = 5, window: int = 3600
) -> None:
    """
    如果 *key* 超过了限制，则抛出 ``BizError(VERIFICATION_CODE_RATE_LIMIT)``。
    使用全局内存中的滑动窗口速率限制器。
    """
    if not _rate_limiter.check(key, max_count, window):
        raise BizError(AuthErr.VERIFICATION_CODE_RATE_LIMIT)

def _expires_at() -> str:
    base = datetime.datetime.fromisoformat(now_iso())
    return (base + datetime.timedelta(minutes=_CODE_EXPIRE_MINUTES)).isoformat()
