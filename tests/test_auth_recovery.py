"""Tests for password recovery (service_recovery)."""

import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.err import BizError
from app.modules.auth.errors import AuthErr
from app.db.models import Base, User, Profile
import app.modules.auth.models  # noqa: F401
from app.modules.auth.models import MagicLink, RefreshToken


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal: sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mk_local(db, username="alice", password="secret123456"):
    from app.modules.auth.security import hashpwd

    user = User(
        username=username,
        hashed_password=hashpwd(password),
        account_level="local",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="member"))
    db.flush()
    return user


def _mk_normal(db, username="bob", password="secret123456", email="bob@example.com", phone="13800001111"):
    from app.modules.auth.security import hashpwd

    user = User(
        username=username,
        email=email,
        phone=phone,
        hashed_password=hashpwd(password),
        account_level="normal",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="member"))
    db.flush()
    return user


def _mk_admin(db, username="admin", password="admin123", email="admin@example.com", phone="13800002222"):
    from app.modules.auth.security import hashpwd

    user = User(
        username=username,
        email=email,
        phone=phone,
        hashed_password=hashpwd(password),
        account_level="admin",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="admin"))
    db.flush()
    return user


def _svc():
    from app.modules.auth import service_recovery

    return service_recovery


def should_default_new_recovery_state_and_counters(db):
    from app.modules.auth.models import RecoveryTransaction

    user = _mk_admin(db)
    txn = RecoveryTransaction(
        txn_id="txn-model",
        user_id=user.id,
        contact=user.email,
        expires_at="2099-01-01T00:00:00+00:00",
    )
    db.add(txn)
    db.flush()
    assert user.token_version == 0
    assert txn.state == "contact_pending"
    assert (txn.failed_contact_attempts, txn.failed_second_factor_attempts, txn.failed_setup_attempts) == (0, 0, 0)
    assert txn.recovery_jti_hash is None
    assert txn.completed_at is None


def _create_phone_code(db, phone, purpose="reset"):
    from app.modules.auth.service_verify import create_phone_verification

    return create_phone_verification(db, phone, purpose)


def _create_email_code(db, email, purpose="reset"):
    from app.modules.auth.service_verify import create_email_verification

    return create_email_verification(db, email, purpose)


def _create_magic_link(db, email, purpose="reset"):
    import datetime as dt
    import secrets

    from app.db.models import now_iso as _now

    raw = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires = (dt.datetime.fromisoformat(_now()) + dt.timedelta(minutes=15)).isoformat()

    link = MagicLink(email=email, token_hash=token_hash, purpose=purpose, expires_at=expires)
    db.add(link)
    db.flush()
    return raw


# ===================================================================
# check_recovery_methods
# ===================================================================


class TestCheckRecoveryMethods:
    # Anti-enumeration (R3-013): check_recovery_methods always returns
    # recoverable=False regardless of whether the account exists, is local,
    # normal, or admin.  The real eligibility is determined internally by
    # the email/phone send flows.

    def should_return_uniform_false_for_local_user(self, db):
        _mk_local(db, username="alice")
        result = _svc().check_recovery_methods(db, "alice")
        assert result["recoverable"] is False

    def should_return_uniform_false_for_normal_user(self, db):
        _mk_normal(db, username="bob", email="bob@example.com", phone="13800001111")
        result = _svc().check_recovery_methods(db, "bob")
        assert result["recoverable"] is False

    def should_return_uniform_false_for_nonexistent(self, db):
        result = _svc().check_recovery_methods(db, "nobody")
        assert result["recoverable"] is False

    def should_return_uniform_false_when_lookup_by_email(self, db):
        _mk_normal(db, username="bob", email="bob@example.com")
        result = _svc().check_recovery_methods(db, "bob@example.com")
        assert result["recoverable"] is False

    def should_return_uniform_false_when_lookup_by_phone(self, db):
        _mk_normal(db, username="bob", phone="13800001111")
        result = _svc().check_recovery_methods(db, "13800001111")
        assert result["recoverable"] is False

    def should_return_uniform_false_for_admin(self, db):
        _mk_admin(db, username="admin", email="admin@example.com")
        result = _svc().check_recovery_methods(db, "admin")
        assert result["recoverable"] is False

    def should_show_recoverable_for_normal_with_totp_enabled(self, db):
        from app.modules.auth.models import TOTP

        user = _mk_normal(db, username="secure", email="secure@example.com")
        totp = TOTP(user_id=user.id, secret="MZXW6YTBOJQXI33F", enabled=True)
        db.add(totp)
        db.flush()

        result = _svc().check_recovery_methods(db, "secure")
        assert result["recoverable"] is False
        # No MFA/method leakage (R2-018)

    def should_show_recoverable_for_normal_without_totp(self, db):
        _mk_normal(db, username="bob", email="bob@example.com")
        result = _svc().check_recovery_methods(db, "bob")
        assert result["recoverable"] is False


# ===================================================================
# recover_by_phone
# ===================================================================


class TestRecoverByPhone:
    def should_reset_password_with_valid_code(self, db):
        user = _mk_normal(db, username="bob", password="old123", phone="13800001111")
        orig_hash = user.hashed_password

        code, _ = _create_phone_code(db, "13800001111", "reset")
        result = _svc().recover_by_phone(db, "13800001111", code, "newpwd456")
        assert result["message"] == "Password reset successful"

        # Password was changed
        db.refresh(user)
        assert user.hashed_password != orig_hash

        # New password works
        from app.modules.auth.security import verifypwd

        assert verifypwd("newpwd456", user.hashed_password)

    def should_reject_wrong_code(self, db):
        _mk_normal(db, username="bob", password="old123", phone="13800001111")
        _create_phone_code(db, "13800001111", "reset")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_phone(db, "13800001111", "000000", "newpwd456")
        assert exc.value.errcode == AuthErr.VERIFICATION_CODE_INVALID

    def should_reject_local_user(self, db):
        _mk_local(db, username="alice", password="old123")
        # give them a phone manually
        user = db.query(User).filter(User.username == "alice").first()
        user.phone = "13800003333"
        db.flush()

        code, _ = _create_phone_code(db, "13800003333", "reset")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_phone(db, "13800003333", code, "newpwd456")
        assert exc.value.errcode == AuthErr.RECOVERY_NOT_SUPPORTED

    def should_reset_failed_login_attempts_and_lock(self, db):
        user = _mk_normal(db, username="bob", password="old123", phone="13800001111")
        user.failed_login_attempts = 4
        user.is_locked = True
        user.locked_until = "2099-01-01T00:00:00+00:00"
        db.flush()

        code, _ = _create_phone_code(db, "13800001111", "reset")
        _svc().recover_by_phone(db, "13800001111", code, "newpwd456")

        db.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.is_locked is False
        assert user.locked_until is None

    def should_revoke_all_refresh_tokens(self, db):
        user = _mk_normal(db, username="bob", password="old123", phone="13800001111")
        # Add a refresh token
        import datetime as dt

        tok = RefreshToken(
            user_id=user.id,
            token_hash="abc123",
            expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).isoformat(),
        )
        db.add(tok)
        db.flush()
        assert tok.revoked_at is None

        code, _ = _create_phone_code(db, "13800001111", "reset")
        _svc().recover_by_phone(db, "13800001111", code, "newpwd456")

        db.refresh(tok)
        assert tok.revoked_at is not None


# ===================================================================
# recover_by_email_code
# ===================================================================


class TestRecoverByEmailCode:
    def should_reset_password_with_valid_code(self, db):
        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        orig_hash = user.hashed_password

        code, _ = _create_email_code(db, "bob@example.com", "reset")
        result = _svc().recover_by_email_code(db, "bob@example.com", code, "newpwd456")
        assert result["message"] == "Password reset successful"

        db.refresh(user)
        assert user.hashed_password != orig_hash

        from app.modules.auth.security import verifypwd

        assert verifypwd("newpwd456", user.hashed_password)

    def should_reject_wrong_code(self, db):
        _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        _create_email_code(db, "bob@example.com", "reset")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_email_code(db, "bob@example.com", "000000", "newpwd456")
        assert exc.value.errcode == AuthErr.VERIFICATION_CODE_INVALID

    def should_reject_local_user(self, db):
        _mk_local(db, username="alice", password="old123")
        user = db.query(User).filter(User.username == "alice").first()
        user.email = "alice@example.com"
        db.flush()

        code, _ = _create_email_code(db, "alice@example.com", "reset")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_email_code(db, "alice@example.com", code, "newpwd456")
        assert exc.value.errcode == AuthErr.RECOVERY_NOT_SUPPORTED

    def should_reset_failed_login_attempts_and_lock(self, db):
        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        user.failed_login_attempts = 3
        user.is_locked = True
        user.locked_until = "2099-01-01T00:00:00+00:00"
        db.flush()

        code, _ = _create_email_code(db, "bob@example.com", "reset")
        _svc().recover_by_email_code(db, "bob@example.com", code, "newpwd456")

        db.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.is_locked is False
        assert user.locked_until is None

    def should_revoke_all_refresh_tokens(self, db):
        import datetime as dt

        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        tok = RefreshToken(
            user_id=user.id,
            token_hash="def456",
            expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).isoformat(),
        )
        db.add(tok)
        db.flush()
        assert tok.revoked_at is None

        code, _ = _create_email_code(db, "bob@example.com", "reset")
        _svc().recover_by_email_code(db, "bob@example.com", code, "newpwd456")

        db.refresh(tok)
        assert tok.revoked_at is not None


# ===================================================================
# recover_by_magic_link
# ===================================================================


class TestRecoverByMagicLink:
    def should_reset_password_with_valid_token(self, db):
        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        orig_hash = user.hashed_password

        token = _create_magic_link(db, "bob@example.com", "reset")
        result = _svc().recover_by_magic_link(db, token, "newpwd456")
        assert result["message"] == "Password reset successful"

        db.refresh(user)
        assert user.hashed_password != orig_hash

        from app.modules.auth.security import verifypwd

        assert verifypwd("newpwd456", user.hashed_password)

    def should_reject_wrong_purpose(self, db):
        _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        token = _create_magic_link(db, "bob@example.com", "login")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_magic_link(db, token, "newpwd456")
        assert exc.value.errcode == AuthErr.TOKEN_INVALID

    def should_reject_used_token(self, db):
        _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        token = _create_magic_link(db, "bob@example.com", "reset")

        # First use succeeds
        _svc().recover_by_magic_link(db, token, "newpwd456")

        # Second use (replay) should fail
        with pytest.raises(BizError) as exc:
            _svc().recover_by_magic_link(db, token, "newpwd789")
        assert exc.value.errcode == AuthErr.TOKEN_INVALID

    def should_reject_local_user(self, db):
        _mk_local(db, username="alice", password="old123")
        user = db.query(User).filter(User.username == "alice").first()
        user.email = "alice@example.com"
        db.flush()

        token = _create_magic_link(db, "alice@example.com", "reset")

        with pytest.raises(BizError) as exc:
            _svc().recover_by_magic_link(db, token, "newpwd456")
        assert exc.value.errcode in (AuthErr.ACCOUNT_LEVEL_INSUFFICIENT, AuthErr.RECOVERY_NOT_SUPPORTED)

    def should_reset_failed_login_attempts_and_lock(self, db):
        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        user.failed_login_attempts = 5
        user.is_locked = True
        user.locked_until = "2099-01-01T00:00:00+00:00"
        db.flush()

        token = _create_magic_link(db, "bob@example.com", "reset")
        _svc().recover_by_magic_link(db, token, "newpwd456")

        db.refresh(user)
        assert user.failed_login_attempts == 0
        assert user.is_locked is False
        assert user.locked_until is None

    def should_revoke_all_refresh_tokens(self, db):
        import datetime as dt

        user = _mk_normal(db, username="bob", password="old123", email="bob@example.com")
        tok = RefreshToken(
            user_id=user.id,
            token_hash="ghi789",
            expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).isoformat(),
        )
        db.add(tok)
        db.flush()
        assert tok.revoked_at is None

        token = _create_magic_link(db, "bob@example.com", "reset")
        _svc().recover_by_magic_link(db, token, "newpwd456")

        db.refresh(tok)
        assert tok.revoked_at is not None

    def should_reject_expired_token(self, db):
        import datetime as dt
        import secrets

        _mk_normal(db, username="bob", password="old123", email="bob@example.com")

        raw = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        expires = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
        link = MagicLink(email="bob@example.com", token_hash=token_hash, purpose="reset", expires_at=expires)
        db.add(link)
        db.flush()

        with pytest.raises(BizError) as exc:
            _svc().recover_by_magic_link(db, raw, "newpwd456")
        assert exc.value.errcode == AuthErr.TOKEN_EXPIRED


# ===================================================================
# _find_user_by_contact edge cases
# ===================================================================


class TestFindUserByContact:
    def should_raise_user_not_found_when_no_match(self, db):
        with pytest.raises(BizError) as exc:
            from app.modules.auth.service_recovery import _find_user_by_contact

            _find_user_by_contact(db, "email", "noone@example.com")
        assert exc.value.errcode == AuthErr.USER_NOT_FOUND

    def should_raise_recovery_not_supported_for_local_user(self, db):
        _mk_local(db, username="alice")
        user = db.query(User).filter(User.username == "alice").first()
        user.email = "alice@example.com"
        db.flush()

        with pytest.raises(BizError) as exc:
            from app.modules.auth.service_recovery import _find_user_by_contact

            _find_user_by_contact(db, "email", "alice@example.com")
        assert exc.value.errcode == AuthErr.RECOVERY_NOT_SUPPORTED
