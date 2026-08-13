"""Tests for TOTP 2FA service (service_2fa.py).

Covers:
- setup_2fa_begin: rejects local users, generates valid secrets/URIs,
  rejects already-enabled TOTP.
- setup_2fa_complete: verifies code, produces recovery codes.
- verify_2fa: with TOTP code and recovery code.
- disable_2fa: disables TOTP, admin downgrade to normal.
"""

import hashlib
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.err import BizError
from app.modules.auth.errors import AuthErr
from app.db.models import Base, User
from app.modules.auth.models import RecoveryCode, TOTP
from app.modules.auth.security import (
    create_temp_token,
    encrypt_secret,
    generate_totp_secret,
    hashpwd,
)

# Re-import the settings so that get_totp_uri uses the same app_name


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
# Helpers
# ---------------------------------------------------------------------------


def _svc():
    from app.modules.auth import service_2fa

    return service_2fa


def _create_user(
    db,
    username="testuser",
    account_level="normal",
    email="test@example.com",
):
    """Create a minimal user (with profile) and return it."""
    from app.db.models import Profile

    user = User(
        username=username,
        email=email,
        hashed_password=hashpwd("secret123456"),
        account_level=account_level,
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id, role="member"))
    db.flush()
    return user


def _enable_totp_for_user(db, user_id):
    """Create a TOTP record with a known secret and mark enabled=True."""
    secret = generate_totp_secret()
    encrypted = encrypt_secret(secret)
    db.add(TOTP(user_id=user_id, secret=encrypted, enabled=True))
    db.flush()
    return secret


def _generate_totp_code(secret, offset=0):
    """Generate a valid TOTP code for *secret* at the current time step + offset."""
    import base64
    import hmac
    import struct

    now = int(time.time()) // 30 + offset
    key = base64.b32decode(secret, casefold=True)
    msg = struct.pack(">Q", now)
    h_val = hmac.new(key, msg, hashlib.sha1).digest()
    off = h_val[-1] & 0x0F
    code = (struct.unpack(">I", h_val[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


# ===================================================================
# TestSetup2FABegin
# ===================================================================


class TestSetup2FABegin:
    def should_reject_local_user(self, db):
        user = _create_user(db, username="localuser", account_level="local", email=None)
        with pytest.raises(BizError) as exc:
            _svc().setup_2fa_begin(db, user.id)
        assert exc.value.errcode == AuthErr.ACCOUNT_LEVEL_INSUFFICIENT

    def should_return_secret_and_uri_for_normal_user(self, db):
        user = _create_user(db, username="normaluser")
        result = _svc().setup_2fa_begin(db, user.id)
        assert "secret" in result
        assert "qr_code_uri" in result
        assert len(result["secret"]) >= 16
        assert result["qr_code_uri"].startswith("otpauth://totp/")
        assert "normaluser" in result["qr_code_uri"]

    def should_reject_already_enabled(self, db):
        user = _create_user(db, username="enableduser")
        _enable_totp_for_user(db, user.id)
        with pytest.raises(BizError) as exc:
            _svc().setup_2fa_begin(db, user.id)
        assert exc.value.errcode == AuthErr.TOTP_ALREADY_ENABLED

    def should_store_encrypted_secret(self, db):
        user = _create_user(db, username="encryptcheck")
        result = _svc().setup_2fa_begin(db, user.id)
        totp_record = db.query(TOTP).filter(TOTP.user_id == user.id).first()
        assert totp_record is not None
        assert totp_record.secret != result["secret"]  # encrypted != plain
        assert totp_record.enabled is False

    def should_accept_admin_user(self, db):
        user = _create_user(db, username="adminuser", account_level="admin")
        result = _svc().setup_2fa_begin(db, user.id)
        assert "secret" in result
        assert "qr_code_uri" in result


# ===================================================================
# TestSetup2FAComplete
# ===================================================================


class TestSetup2FAComplete:
    def should_enable_totp_and_return_recovery_codes(self, db):
        user = _create_user(db, username="completeuser")
        # Begin setup to create the TOTP record
        begin_result = _svc().setup_2fa_begin(db, user.id)
        secret = begin_result["secret"]

        code = _generate_totp_code(secret)
        result = _svc().setup_2fa_complete(db, user.id, code)
        assert "recovery_codes" in result
        assert len(result["recovery_codes"]) == 10
        assert result["confirmed_saved_required"] is True

        # Verify TOTP is now enabled
        totp_record = db.query(TOTP).filter(TOTP.user_id == user.id).first()
        assert totp_record.enabled is True

        # Verify recovery codes are stored as hashes
        stored_codes = db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).all()
        assert len(stored_codes) == 10
        for rc in stored_codes:
            assert rc.used is False

    def should_reject_when_no_totp_record_exists(self, db):
        user = _create_user(db, username="nototp")
        with pytest.raises(BizError) as exc:
            _svc().setup_2fa_complete(db, user.id, "123456")
        assert exc.value.errcode == AuthErr.TOTP_NOT_ENABLED

    def should_reject_invalid_code(self, db):
        user = _create_user(db, username="badcode")
        _svc().setup_2fa_begin(db, user.id)
        with pytest.raises(BizError) as exc:
            _svc().setup_2fa_complete(db, user.id, "000000")
        assert exc.value.errcode == AuthErr.TOTP_CODE_INVALID

    def should_reject_already_enabled(self, db):
        user = _create_user(db, username="alreadyenabled")
        begin_result = _svc().setup_2fa_begin(db, user.id)
        code = _generate_totp_code(begin_result["secret"])
        _svc().setup_2fa_complete(db, user.id, code)

        # Second complete should fail
        with pytest.raises(BizError) as exc:
            _svc().setup_2fa_complete(db, user.id, code)
        assert exc.value.errcode == AuthErr.TOTP_NOT_ENABLED


# ===================================================================
# TestVerify2FA
# ===================================================================


class TestVerify2FA:
    def should_verify_with_valid_code(self, db):
        user = _create_user(db, username="verifyuser")
        secret = _enable_totp_for_user(db, user.id)

        temp_token = create_temp_token(user.id)
        code = _generate_totp_code(secret)
        result = _svc().verify_2fa(db, temp_token, code=code)
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user_id"] == user.id

    def should_reject_invalid_code(self, db):
        user = _create_user(db, username="badverify")
        _enable_totp_for_user(db, user.id)

        temp_token = create_temp_token(user.id)
        with pytest.raises(BizError) as exc:
            _svc().verify_2fa(db, temp_token, code="000000")
        assert exc.value.errcode == AuthErr.TOTP_CODE_INVALID

    def should_verify_with_recovery_code(self, db):
        user = _create_user(db, username="recoveruser")
        secret = _enable_totp_for_user(db, user.id)

        # Create a recovery code entry directly
        recovery_plain = "test-recovery-code-12345"
        code_hash = hashlib.sha256(recovery_plain.encode()).hexdigest()
        db.add(RecoveryCode(user_id=user.id, code_hash=code_hash, used=False))
        db.flush()

        temp_token = create_temp_token(user.id)
        result = _svc().verify_2fa(
            db, temp_token, recovery_code=recovery_plain
        )
        assert "access_token" in result
        assert "refresh_token" in result

        # Verify the recovery code is marked used
        rc = (
            db.query(RecoveryCode)
            .filter(RecoveryCode.user_id == user.id, RecoveryCode.code_hash == code_hash)
            .first()
        )
        assert rc.used is True

    def should_reject_invalid_recovery_code(self, db):
        user = _create_user(db, username="badrecover")
        _enable_totp_for_user(db, user.id)

        temp_token = create_temp_token(user.id)
        with pytest.raises(BizError) as exc:
            _svc().verify_2fa(db, temp_token, recovery_code="nonexistent")
        assert exc.value.errcode == AuthErr.RECOVERY_CODE_INVALID

    def should_reject_invalid_temp_token(self, db):
        with pytest.raises(BizError) as exc:
            _svc().verify_2fa(db, "invalid-token", code="123456")
        assert exc.value.errcode == AuthErr.TOKEN_INVALID

    def should_override_trust_device_for_admin(self, db):
        """Admin users should always have trust_device=False."""
        user = _create_user(db, username="admintrust", account_level="admin")
        secret = _enable_totp_for_user(db, user.id)

        temp_token = create_temp_token(user.id)
        code = _generate_totp_code(secret)
        result = _svc().verify_2fa(
            db, temp_token, code=code, trust_device=True
        )
        # trust_device should be False even though we passed True
        assert result["trust_device"] is False


# ===================================================================
# TestDisable2FA
# ===================================================================


class TestDisable2FA:
    def should_disable_totp_and_clear_data(self, db):
        user = _create_user(db, username="disableuser")
        secret = _enable_totp_for_user(db, user.id)

        # Add a recovery code
        code_hash = hashlib.sha256("dummy-recovery".encode()).hexdigest()
        db.add(RecoveryCode(user_id=user.id, code_hash=code_hash, used=False))
        db.flush()

        code = _generate_totp_code(secret)
        result = _svc().disable_2fa(db, user.id, code)
        assert result["message"] == "2FA disabled"

        totp_record = db.query(TOTP).filter(TOTP.user_id == user.id).first()
        assert totp_record.enabled is False
        assert totp_record.secret == ""

        # Recovery codes should be deleted
        rcs = db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).all()
        assert len(rcs) == 0

    def should_reject_when_not_enabled(self, db):
        user = _create_user(db, username="notenabled")
        with pytest.raises(BizError) as exc:
            _svc().disable_2fa(db, user.id, "123456")
        assert exc.value.errcode == AuthErr.TOTP_NOT_ENABLED

    def should_downgrade_admin_to_normal(self, db):
        user = _create_user(db, username="admin2fa", account_level="admin")
        secret = _enable_totp_for_user(db, user.id)

        code = _generate_totp_code(secret)
        result = _svc().disable_2fa(db, user.id, code)
        assert result["message"] == "2FA disabled"

        # Verify admin downgrade
        db.expire_all()
        user = db.query(User).filter(User.id == user.id).first()
        assert user.account_level == "normal"

    def should_reject_invalid_code(self, db):
        user = _create_user(db, username="wrongcodedisable")
        _enable_totp_for_user(db, user.id)

        with pytest.raises(BizError) as exc:
            _svc().disable_2fa(db, user.id, "000000")
        assert exc.value.errcode == AuthErr.TOTP_CODE_INVALID
