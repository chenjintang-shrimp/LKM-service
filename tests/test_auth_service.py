import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.err import BizError, CommonErr
from app.modules.auth.errors import AuthErr
from app.db.models import Base
import app.modules.auth.models  # noqa: F401
from app.modules.auth.models import RefreshToken


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


def _reg_local(db, username="alice", password="secret123456"):
    from app.modules.auth.schemas import UserRegLocal

    return _service().register_local(db, UserRegLocal(username=username, password=password))


def _reg_normal(db, username="bob", password="secret123456", email="bob@example.com", phone="13800001111"):
    from app.modules.auth.schemas import UserRegNormal

    return _service().register_normal_with_password(
        db, UserRegNormal(username=username, password=password, email=email, phone=phone),
        email_verified=True, phone_verified=True,
    )


def _login(db, account, password):
    from app.modules.auth.schemas import UserLoginPassword

    return _service().login_password(db, UserLoginPassword(account=account, password=password))


def _service():
    from app.modules.auth import service_auth

    return service_auth


# ===================================================================
# TestRegisterLocal
# ===================================================================


class TestRegisterLocal:
    def should_create_local_user_and_profile(self, db):
        from app.db.models import User, Profile

        result = _reg_local(db, username="alice", password="secret123456")
        assert result["access_token"]
        assert result["refresh_token"]
        assert result["user_id"] == 1
        assert result["account_level"] == "local"

        user = db.query(User).filter(User.id == 1).first()
        assert user.username == "alice"
        assert user.account_level == "local"
        assert "$" in user.hashed_password

        profile = db.query(Profile).filter(Profile.user_id == 1).first()
        assert profile is not None
        assert profile.role == "member"

    def should_reject_duplicate_username(self, db):
        _reg_local(db, username="alice")
        with pytest.raises(BizError) as exc:
            _reg_local(db, username="alice", password="other1234567")
        assert exc.value.errcode == AuthErr.ALREADY_REGISTERED


# ===================================================================
# TestRegisterNormal
# ===================================================================


class TestRegisterNormal:
    def should_create_normal_user_with_verified_email_and_phone(self, db):
        from app.db.models import User

        result = _reg_normal(db, username="bob", email="bob@example.com", phone="13800001111")
        assert result["user_id"] == 1

        user = db.query(User).filter(User.id == result["user_id"]).first()
        assert user.username == "bob"
        assert user.email == "bob@example.com"
        assert user.phone == "13800001111"
        assert user.account_level == "normal"
        assert "$" in user.hashed_password

    def should_reject_if_email_and_phone_not_verified(self, db):
        from app.modules.auth.schemas import UserRegNormal

        svc = _service()
        with pytest.raises(BizError) as exc:
            svc.register_normal_with_password(
                db, UserRegNormal(username="bob", password="secret123456", email="bob@example.com", phone="13800001111"),
                email_verified=False, phone_verified=True,
            )
        assert exc.value.errcode == CommonErr.INVALID_INPUT


# ===================================================================
# TestLoginPassword
# ===================================================================


class TestLoginPassword:
    # --- success paths ---

    def should_login_by_username(self, db):
        _reg_local(db, username="alice", password="secret123456")
        result = _login(db, "alice", "secret123456")
        assert result["user_id"] == 1
        assert result["access_token"]
        assert result["refresh_token"]
        assert result["account_level"] == "local"

    def should_login_by_email(self, db):
        _reg_local(db, username="alice", password="secret123456")
        # give the user an email manually
        from app.db.models import User

        user = db.query(User).filter(User.id == 1).first()
        user.email = "alice@example.com"
        db.flush()

        result = _login(db, "alice@example.com", "secret123456")
        assert result["user_id"] == 1

    def should_login_by_phone(self, db):
        _reg_local(db, username="alice", password="secret123456")
        from app.db.models import User

        user = db.query(User).filter(User.id == 1).first()
        user.phone = "13800001111"
        db.flush()

        result = _login(db, "13800001111", "secret123456")
        assert result["user_id"] == 1

    # --- failure paths ---

    def should_reject_wrong_password(self, db):
        _reg_local(db, username="alice", password="secret123456")
        with pytest.raises(BizError) as exc:
            _login(db, "alice", "wrongpass")
        assert exc.value.errcode == AuthErr.INVALID_CREDENTIALS

    def should_reject_nonexistent_account(self, db):
        with pytest.raises(BizError) as exc:
            _login(db, "nobody", "secret123456")
        assert exc.value.errcode == AuthErr.INVALID_CREDENTIALS

    def should_lock_after_5_failed_attempts(self, db):
        _reg_local(db, username="alice", password="secret123456")
        from app.db.models import User

        for _ in range(5):
            try:
                _login(db, "alice", "wrongpass")
            except BizError:
                # Expire only – don't rollback, so the flush in _record_failed_attempt
                # is preserved. The exception itself rolls back nothing at the DB level
                # because autoflush=False; only flush calls persist.
                db.expire_all()

        user = db.query(User).filter(User.username == "alice").first()
        assert user.failed_login_attempts == 5
        assert user.is_locked is True

        with pytest.raises(BizError) as exc:
            _login(db, "alice", "secret123456")
        assert exc.value.errcode == AuthErr.INVALID_CREDENTIALS

    def should_reset_failed_counter_on_success(self, db):
        _reg_local(db, username="alice", password="secret123456")
        from app.db.models import User

        # 2 failures
        for _ in range(2):
            try:
                _login(db, "alice", "wrongpass")
            except BizError:
                db.expire_all()

        # then success
        result = _login(db, "alice", "secret123456")
        assert result["user_id"] == 1

        user = db.query(User).filter(User.username == "alice").first()
        assert user.failed_login_attempts == 0
        assert user.is_locked is False

    def should_return_setup_token_for_admin_without_totp(self, db):
        """Admin-level user without TOTP should get a setup_required response."""
        from app.db.models import User

        user = User(username="admin", email="admin@example.com",
                     hashed_password="dummy$notreal", account_level="admin")
        db.add(user)
        db.flush()
        from app.modules.auth.security import hashpwd

        user.hashed_password = hashpwd("admin123")
        db.flush()

        result = _login(db, "admin", "admin123")
        assert result["requires_2fa"] is True
        assert result.get("setup_required") is True
        assert result["temp_token"] is not None

    def should_return_temp_token_when_2fa_required(self, db):
        """If user has TOTP enabled, login returns requires_2fa=True and a temp_token."""
        from app.db.models import User
        from app.modules.auth.models import TOTP

        user = User(username="secure", email="secure@example.com",
                     hashed_password="dummy$notreal", account_level="normal")
        db.add(user)
        db.flush()
        from app.modules.auth.security import hashpwd

        user.hashed_password = hashpwd("secret123456")

        # enable TOTP
        totp = TOTP(user_id=user.id, secret="MZXW6YTBOJQXI33F", enabled=True)
        db.add(totp)
        db.flush()

        result = _login(db, "secure", "secret123456")
        assert result["requires_2fa"] is True
        assert result["temp_token"]
        assert result["access_token"] is None
        assert result["refresh_token"] is None


# ===================================================================
# TestRegisterByVerify
# ===================================================================


class TestRegisterByVerify:
    def should_create_user_by_email_verify(self, db):
        from app.db.models import User

        svc = _service()
        result = svc.register_by_verify(db, "email", "new@example.com")
        user_id = result["user_id"]
        assert result["access_token"] is not None
        assert result["refresh_token"] is not None
        assert result["account_level"] == "normal"

        user = db.query(User).filter(User.id == user_id).first()
        assert user.email == "new@example.com"
        assert user.account_level == "normal"
        assert user.hashed_password == ""

    def should_create_user_by_phone_verify(self, db):
        from app.db.models import User

        svc = _service()
        result = svc.register_by_verify(db, "phone", "13900001111")
        user_id = result["user_id"]
        assert result["access_token"] is not None

        user = db.query(User).filter(User.id == user_id).first()
        assert user.phone == "13900001111"
        assert user.account_level == "normal"


# ===================================================================
# TestUpgrade
# ===================================================================


class TestUpgrade:
    def should_upgrade_local_to_normal(self, db):
        from app.db.models import User

        _reg_local(db, username="alice")
        user = db.query(User).filter(User.username == "alice").first()
        assert user.account_level == "local"

        svc = _service()
        svc.upgrade_to_normal(db, user)
        db.flush()

        user = db.query(User).filter(User.username == "alice").first()
        assert user.account_level == "normal"

    def should_not_downgrade_already_normal(self, db):
        from app.db.models import User

        user = User(username="normal_guy", email="n@example.com",
                     hashed_password="x", account_level="normal")
        db.add(user)
        db.flush()

        svc = _service()
        svc.upgrade_to_normal(db, user)
        db.flush()

        assert user.account_level == "normal"

    def admin_should_stay_admin(self, db):
        from app.db.models import User

        user = User(username="boss", email="boss@example.com",
                     hashed_password="x", account_level="admin")
        db.add(user)
        db.flush()

        svc = _service()
        svc.upgrade_to_normal(db, user)
        db.flush()

        assert user.account_level == "admin"


# ===================================================================
# TestRefresh
# ===================================================================


class TestRefresh:
    def should_refresh_valid_token(self, db):
        _reg_local(db, username="alice", password="secret123456")
        tokens = db.query(RefreshToken).filter(RefreshToken.user_id == 1).all()
        assert len(tokens) == 1

        # get the raw refresh token from the registration result
        result = _reg_local(db, username="bob", password="other1234567")
        raw = result["refresh_token"]

        svc = _service()
        new = svc.refresh_access_token(db, raw)
        assert new["access_token"]
        assert new["refresh_token"]
        assert new["refresh_token"] != raw  # rotation

        # old token should be revoked
        old_hash = hashlib.sha256(raw.encode()).hexdigest()
        old = db.query(RefreshToken).filter(RefreshToken.token_hash == old_hash).first()
        assert old.revoked_at is not None

    def should_reject_revoked_token(self, db):
        result = _reg_local(db, username="alice")
        raw = result["refresh_token"]

        svc = _service()
        # first refresh works
        svc.refresh_access_token(db, raw)

        # second refresh with same (revoked) token rejects
        with pytest.raises(BizError) as exc:
            svc.refresh_access_token(db, raw)
        assert exc.value.errcode == AuthErr.TOKEN_INVALID

    def should_reject_expired_token(self, db):
        result = _reg_local(db, username="alice")
        raw = result["refresh_token"]

        # manually expire the token in DB
        tok_hash = hashlib.sha256(raw.encode()).hexdigest()
        import datetime as dt

        tok = db.query(RefreshToken).filter(RefreshToken.token_hash == tok_hash).first()
        tok.expires_at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
        db.flush()

        svc = _service()
        with pytest.raises(BizError) as exc:
            svc.refresh_access_token(db, raw)
        assert exc.value.errcode == AuthErr.TOKEN_EXPIRED


# ===================================================================
# TestRevokeAll
# ===================================================================


class TestRevokeAll:
    def should_revoke_all_user_tokens(self, db):
        result1 = _reg_local(db, username="alice")
        result2 = _reg_local(db, username="bob")

        svc = _service()
        svc.revoke_all_refresh_tokens(db, 1)

        # alice's tokens revoked
        tok1 = db.query(RefreshToken).filter(RefreshToken.user_id == 1).all()
        for t in tok1:
            assert t.revoked_at is not None

        # bob's tokens untouched
        tok2 = db.query(RefreshToken).filter(RefreshToken.user_id == 2).all()
        for t in tok2:
            assert t.revoked_at is None


# ===================================================================
# TestAuditLog
# ===================================================================


class TestAuditLog:
    def should_create_audit_log(self, db):
        from app.modules.auth.models import AuditLog

        _reg_local(db, username="alice")
        svc = _service()
        svc.log_audit(db, 1, "login", detail="password login", ip_address="127.0.0.1")

        logs = db.query(AuditLog).filter(AuditLog.user_id == 1).all()
        assert len(logs) == 1
        assert logs[0].action == "login"
        assert logs[0].detail == "password login"
        assert logs[0].ip_address == "127.0.0.1"
