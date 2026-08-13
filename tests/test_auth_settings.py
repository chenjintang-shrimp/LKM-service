"""Tests for email/phone binding endpoints (router_settings.py).

Covers:
- Bind email request + verify with upgrade local->normal
- Bind phone request + verify
- Error cases: duplicate email/phone, wrong code
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.err import BizError
from app.modules.auth.errors import AuthErr
from app.db.models import Base
import app.modules.auth.models  # noqa: F401 — ensure auth tables (refresh_tokens, etc.) are created


def _unwrap(response):
    """Extract the data dict from a JSONResponse returned by @respond."""
    return json.loads(response.body.decode())


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
# service helpers (mimic test_auth_service pattern)
# ---------------------------------------------------------------------------


def _reg_local(db, username="alice", password="secret123456"):
    from app.modules.auth.schemas import UserRegLocal

    svc = _service()
    return svc.register_local(db, UserRegLocal(username=username, password=password))


def _get_user(db, user_id: int):
    from app.db.models import User

    return db.query(User).filter(User.id == user_id).first()


def _service():
    from app.modules.auth import service_auth

    return service_auth


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBindEmail:
    """Bind email request + verify, covering auto-upgrade local->normal."""

    def should_bind_email_and_upgrade_local_to_normal(self, db):
        """Full happy path: request code, verify, email bound, account upgraded."""
        # Arrange: create a local user

        reg_result = _reg_local(db, username="alice")
        user_id = reg_result["user_id"]
        assert _get_user(db, user_id).account_level == "local"

        # Stub providers so we can capture the code
        captured = {}

        async def fake_send_code(email, code):
            captured["code"] = code

        # Act: request email binding
        from app.modules.auth.service_verify import create_email_verification

        code, record_id = create_email_verification(db, "alice@example.com", "bind")
        captured["code"] = code

        # Now use the router function directly
        from app.modules.auth.router_settings import bind_email_verify

        class FakeCurrentUser:
            id = user_id
            account_level = "local"
            role = "member"

        result = bind_email_verify(
            body=type("Body", (), {"email": "alice@example.com", "code": code})(),
            cur=FakeCurrentUser(),
            db=db,
        )

        # Assert
        data = _unwrap(result)
        assert data["data"]["message"] == "Email bound successfully"

        user = _get_user(db, user_id)
        assert user.email == "alice@example.com"
        # account should be upgraded from local to normal
        assert user.account_level == "normal"

    def should_reject_duplicate_email(self, db):
        """Should fail if email is already taken by another user."""
        # Create two local users
        reg1 = _reg_local(db, username="alice")
        reg2 = _reg_local(db, username="bob")

        from app.modules.auth.service_verify import create_email_verification

        # Bind email to alice directly
        user1 = _get_user(db, reg1["user_id"])
        user1.email = "same@example.com"
        db.flush()

        # Try to bind the same email to bob
        code, record_id = create_email_verification(db, "same@example.com", "bind")

        class FakeCurrentUser:
            id = reg2["user_id"]
            account_level = "local"
            role = "member"

        from app.modules.auth.router_settings import bind_email_verify

        with pytest.raises(BizError) as exc:
            bind_email_verify(
                body=type("Body", (), {"email": "same@example.com", "code": code})(),
                cur=FakeCurrentUser(),
                db=db,
            )
        assert exc.value.errcode == AuthErr.ALREADY_REGISTERED

    def should_reject_wrong_code(self, db):
        """Should fail with wrong verification code."""
        reg = _reg_local(db, username="alice")

        from app.modules.auth.service_verify import create_email_verification

        create_email_verification(db, "alice@example.com", "bind")

        from app.modules.auth.router_settings import bind_email_verify

        class FakeCurrentUser:
            id = reg["user_id"]
            account_level = "local"
            role = "member"

        with pytest.raises(BizError) as exc:
            bind_email_verify(
                body=type("Body", (), {"email": "alice@example.com", "code": "000000"})(),
                cur=FakeCurrentUser(),
                db=db,
            )
        assert exc.value.errcode == AuthErr.VERIFICATION_CODE_INVALID


class TestBindPhone:
    """Bind phone request + verify."""

    def should_bind_phone_and_upgrade_local_to_normal(self, db):
        """Full happy path: request code, verify, phone bound, account upgraded."""
        reg = _reg_local(db, username="alice")
        user_id = reg["user_id"]
        assert _get_user(db, user_id).account_level == "local"

        from app.modules.auth.service_verify import create_phone_verification

        code, record_id = create_phone_verification(db, "13800001111", "bind")

        from app.modules.auth.router_settings import bind_phone_verify

        class FakeCurrentUser:
            id = user_id
            account_level = "local"
            role = "member"

        result = bind_phone_verify(
            body=type("Body", (), {"phone": "13800001111", "code": code})(),
            cur=FakeCurrentUser(),
            db=db,
        )

        data = _unwrap(result)
        assert data["data"]["message"] == "Phone bound successfully"

        user = _get_user(db, user_id)
        assert user.phone == "13800001111"
        assert user.account_level == "normal"

    def should_reject_duplicate_phone(self, db):
        """Should fail if phone already taken."""
        reg1 = _reg_local(db, username="alice")
        reg2 = _reg_local(db, username="bob")

        # Bind phone to alice directly
        user1 = _get_user(db, reg1["user_id"])
        user1.phone = "13800001111"
        db.flush()

        from app.modules.auth.service_verify import create_phone_verification

        code, record_id = create_phone_verification(db, "13800001111", "bind")

        from app.modules.auth.router_settings import bind_phone_verify

        class FakeCurrentUser:
            id = reg2["user_id"]
            account_level = "local"
            role = "member"

        with pytest.raises(BizError) as exc:
            bind_phone_verify(
                body=type("Body", (), {"phone": "13800001111", "code": code})(),
                cur=FakeCurrentUser(),
                db=db,
            )
        assert exc.value.errcode == AuthErr.ALREADY_REGISTERED

    def should_reject_wrong_code(self, db):
        """Should fail with wrong verification code."""
        reg = _reg_local(db, username="alice")

        from app.modules.auth.service_verify import create_phone_verification

        create_phone_verification(db, "13800001111", "bind")

        from app.modules.auth.router_settings import bind_phone_verify

        class FakeCurrentUser:
            id = reg["user_id"]
            account_level = "local"
            role = "member"

        with pytest.raises(BizError) as exc:
            bind_phone_verify(
                body=type("Body", (), {"phone": "13800001111", "code": "000000"})(),
                cur=FakeCurrentUser(),
                db=db,
            )
        assert exc.value.errcode == AuthErr.VERIFICATION_CODE_INVALID


class TestBindEmailUpgrade:
    """Specifically test that bind email upgrades local->normal."""

    def should_upgrade_when_binding_email(self, db):
        """Bind email to a local user: account_level must become normal."""
        reg = _reg_local(db, username="upgrademe")
        user_id = reg["user_id"]
        user = _get_user(db, user_id)
        assert user.account_level == "local"
        assert user.email is None

        from app.modules.auth.service_verify import create_email_verification

        code, _ = create_email_verification(db, "upgrade@example.com", "bind")

        from app.modules.auth.router_settings import bind_email_verify

        class FakeCurrentUser:
            id = user_id
            account_level = "local"
            role = "member"

        bind_email_verify(
            body=type("Body", (), {"email": "upgrade@example.com", "code": code})(),
            cur=FakeCurrentUser(),
            db=db,
        )

        user = _get_user(db, user_id)
        assert user.email == "upgrade@example.com"
        assert user.account_level == "normal"

    def should_not_downgrade_normal_user(self, db):
        """Binding email to an already-normal user: should stay normal."""
        from app.db.models import User, Profile

        # Create an already-normal user
        user = User(
            username="normaluser",
            email="normal@example.com",
            hashed_password="x",
            account_level="normal",
        )
        db.add(user)
        db.flush()
        db.add(Profile(user_id=user.id, role="member"))
        db.flush()
        user_id = user.id

        # Bind a different email (the user already has one, but we're binding another)
        from app.modules.auth.service_verify import create_email_verification

        code, _ = create_email_verification(db, "another@example.com", "bind")

        from app.modules.auth.router_settings import bind_email_verify

        class FakeCurrentUser:
            id = user_id
            account_level = "normal"
            role = "member"

        bind_email_verify(
            body=type("Body", (), {"email": "another@example.com", "code": code})(),
            cur=FakeCurrentUser(),
            db=db,
        )

        user = _get_user(db, user_id)
        # Already normal, should not have been changed
        assert user.account_level == "normal"
