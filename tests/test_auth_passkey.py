"""Tests for the Passkey service (service_passkey.py) with real WebAuthn crypto."""

import hashlib
import json
import base64
import struct
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.err import BizError
from app.modules.auth.errors import AuthErr
from app.db.models import Base
import app.modules.auth.models  # noqa: F401
from app.modules.auth.models import PasskeyCredential


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(s: str) -> bytes:
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


# ---- crypto helpers for creating valid WebAuthn assertions ---------


def _generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _public_key_bytes(key) -> bytes:
    """Uncompressed point: 0x04 || x || y."""
    nums = key.private_numbers().public_numbers
    return b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _make_authenticator_data(rp_id: str, sign_count: int, flags: int = 0x01) -> bytes:
    """Build minimal authenticatorData: rpIdHash || flags || signCount."""
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    return rp_id_hash + bytes([flags]) + struct.pack(">I", sign_count)


def _sign_assertion(key, auth_data: bytes, client_data_json_b64: str) -> bytes:
    """Sign assertion payload: authData || SHA-256(clientDataJSON).

    Returns a raw 64-byte (r||s) signature in WebAuthn format.
    """
    import hashlib
    client_hash = hashlib.sha256(_b64decode(client_data_json_b64)).digest()
    signed = auth_data + client_hash
    der_sig = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return _der_to_raw(der_sig)


def _der_to_raw(der_sig: bytes) -> bytes:
    """Convert a DER-encoded ECDSA signature to raw 64-byte r||s format."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _service():
    from app.modules.auth import service_passkey
    return service_passkey


def _reg_local(db, username="alice", password="secret123456"):
    from app.modules.auth.schemas import UserRegLocal
    from app.modules.auth.service_auth import register_local
    return register_local(db, UserRegLocal(username=username, password=password))


def _reg_normal(db, username="bob", email="bob@test.com", password="secret123456"):
    """Register a normal user and make sure account_level is normal."""
    from app.db.models import User
    from app.modules.auth.schemas import UserRegLocal
    from app.modules.auth.service_auth import register_local
    result = register_local(db, UserRegLocal(username=username, password=password))
    user = db.query(User).filter(User.id == result["user_id"]).first()
    user.account_level = "normal"
    user.email = email
    db.flush()
    return user


def _register_passkey(db, user_id, credential_id, device_name="TestKey", key=None):
    """Helper: directly insert a PasskeyCredential with a valid EC key."""
    if key is None:
        key = _generate_ec_key()
    pub_bytes = _public_key_bytes(key)
    pk = PasskeyCredential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=_b64(pub_bytes),
        sign_count=0,
        device_name=device_name,
    )
    db.add(pk)
    db.flush()


# ==================================================================
# TestBeginPasskeyRegistration
# ==================================================================


class TestBeginPasskeyRegistration:
    def should_produce_challenge(self, db):
        _reg_normal(db)
        result = _service().begin_passkey_registration(db, user_id=1)
        assert "challenge_id" in result
        pk = result["public_key"]
        assert pk["rp"]["name"] == "LKM Service"
        assert pk["pubKeyCredParams"]

    def should_allow_local_user_to_begin_registration(self, db):
        _reg_local(db, username="alice")
        svc = _service()
        result = svc.begin_passkey_registration(db, user_id=1)
        assert "challenge_id" in result

    def should_reject_nonexistent_user(self, db):
        svc = _service()
        with pytest.raises(BizError) as exc:
            svc.begin_passkey_registration(db, user_id=999)
        assert exc.value.errcode == AuthErr.USER_NOT_FOUND

    def should_include_exclude_credentials(self, db):
        user = _reg_normal(db)
        _register_passkey(db, user.id, "cred-1")
        result = _service().begin_passkey_registration(db, user.id)
        excludes = result["public_key"]["excludeCredentials"]
        assert len(excludes) == 1
        assert excludes[0]["id"] == _b64(b"cred-1")


# ==================================================================
# TestCompletePasskeyRegistration
# ==================================================================


class TestCompletePasskeyRegistration:
    def should_register_valid_key(self, db):
        user = _reg_normal(db)
        svc = _service()
        begin = svc.begin_passkey_registration(db, user.id)
        challenge_id = begin["challenge_id"]
        challenge = begin["public_key"]["challenge"]

        # Build a valid attestation
        key = _generate_ec_key()
        pub_bytes = _public_key_bytes(key)
        cred_id_b64 = _b64(b"test-creds")

        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))

        import cbor2
        auth_data = _make_authenticator_data("localhost", 0, flags=0x41)
        aaguid = b"\x00" * 16
        cred_id_bytes = b"test-creds"
        cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pub_bytes[1:33], -3: pub_bytes[33:]})
        attested = auth_data + aaguid + struct.pack(">H", len(cred_id_bytes)) + cred_id_bytes + cose_key

        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": attested,
        })
        att_obj_b64 = _b64(att_obj)

        result = svc.complete_passkey_registration(db, user.id, {
            "rawId": cred_id_b64,
            "challenge_id": challenge_id,
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": att_obj_b64,
            },
        })
        assert result["message"] == "Passkey registered successfully"

    def should_reject_wrong_challenge(self, db):
        user = _reg_normal(db)
        svc = _service()
        begin = svc.begin_passkey_registration(db, user.id)
        challenge_id = begin["challenge_id"]

        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": "wrong-challenge",
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))

        import cbor2
        key = _generate_ec_key()
        pub_bytes = _public_key_bytes(key)
        auth_data = _make_authenticator_data("localhost", 0, flags=0x41)
        aaguid = b"\x00" * 16
        cred_id_bytes = b"wrong-creds"
        cose_key_cbor = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pub_bytes[1:33], -3: pub_bytes[33:]})
        attested = auth_data + aaguid + struct.pack(">H", len(cred_id_bytes)) + cred_id_bytes + cose_key_cbor
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": attested})
        att_obj_b64 = _b64(att_obj)

        with pytest.raises(BizError) as exc:
            svc.complete_passkey_registration(db, user.id, {
                "rawId": _b64(b"cred"),
                "challenge_id": challenge_id,
                "response": {
                    "clientDataJSON": client_data_b64,
                    "attestationObject": att_obj_b64,
                },
            })
        # Challenge mismatch raises PASSKEY_VERIFICATION_FAILED (the generic
        # verification error code, used for both registration and login).
        assert exc.value.errcode in (AuthErr.PASSKEY_REGISTRATION_FAILED, AuthErr.PASSKEY_VERIFICATION_FAILED)


# ==================================================================
# TestBeginPasskeyLogin
# ==================================================================


class TestBeginPasskeyLogin:
    def should_produce_challenge(self, db):
        result = _service().begin_passkey_login(db)
        assert "challenge_id" in result
        pk = result["public_key"]
        assert "challenge" in pk
        assert pk["rpId"] == "localhost"


# ==================================================================
# TestCompletePasskeyLogin
# ==================================================================


class TestCompletePasskeyLogin:
    def should_succeed_passkey_login_for_normal_user(self, db):
        user = _reg_normal(db)
        key = _generate_ec_key()
        cred_id = "my-credential-id"
        _register_passkey(db, user.id, cred_id, key=key)

        svc = _service()
        begin = svc.begin_passkey_login(db)
        challenge_id = begin["challenge_id"]
        challenge = begin["public_key"]["challenge"]

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))

        auth_data = _make_authenticator_data("localhost", 1)
        signature = _sign_assertion(key, auth_data, client_data_b64)
        signature_b64 = _b64(signature)

        result = svc.complete_passkey_login(db, {
            "rawId": cred_id,
            "challenge_id": challenge_id,
            "response": {
                "authenticatorData": _b64(auth_data),
                "clientDataJSON": client_data_b64,
                "signature": signature_b64,
            },
        })
        assert result["user_id"] == user.id
        assert result["access_token"] is not None

    def should_increment_sign_count_on_login(self, db):
        user = _reg_normal(db)
        key = _generate_ec_key()
        cred_id = "counter-cred"
        _register_passkey(db, user.id, cred_id, key=key)

        svc = _service()

        for i in range(2):
            begin = svc.begin_passkey_login(db)
            challenge_id = begin["challenge_id"]
            challenge = begin["public_key"]["challenge"]

            client_data = json.dumps({
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": "http://localhost:5173",
            })
            client_data_b64 = _b64(client_data.encode("utf-8"))
            auth_data = _make_authenticator_data("localhost", i + 1)
            signature = _sign_assertion(key, auth_data, client_data_b64)

            result = svc.complete_passkey_login(db, {
                "rawId": cred_id,
                "challenge_id": challenge_id,
                "response": {
                    "authenticatorData": _b64(auth_data),
                    "clientDataJSON": client_data_b64,
                    "signature": _b64(signature),
                },
            })
            assert result["user_id"] == user.id

        pk = db.query(PasskeyCredential).filter(PasskeyCredential.credential_id == cred_id).first()
        assert pk.sign_count == 2


    def should_reject_missing_signature(self, db):
        user = _reg_normal(db)
        cred_id = "some-cred"
        _register_passkey(db, user.id, cred_id)

        svc = _service()
        begin = svc.begin_passkey_login(db)

        with pytest.raises(BizError) as exc:
            svc.complete_passkey_login(db, {
                "rawId": cred_id,
                "challenge_id": begin["challenge_id"],
            })
        assert exc.value.errcode == AuthErr.PASSKEY_VERIFICATION_FAILED


    def should_reject_wrong_signature(self, db):
        user = _reg_normal(db)
        key = _generate_ec_key()
        wrong_key = _generate_ec_key()
        cred_id = "wrong-sig-cred"
        _register_passkey(db, user.id, cred_id, key=key)

        svc = _service()
        begin = svc.begin_passkey_login(db)
        challenge = begin["public_key"]["challenge"]

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))
        auth_data = _make_authenticator_data("localhost", 1)
        wrong_sig = _sign_assertion(wrong_key, auth_data, client_data_b64)

        with pytest.raises(BizError) as exc:
            svc.complete_passkey_login(db, {
                "rawId": cred_id,
                "challenge_id": begin["challenge_id"],
                "response": {
                    "authenticatorData": _b64(auth_data),
                    "clientDataJSON": client_data_b64,
                    "signature": _b64(wrong_sig),
                },
            })
        assert exc.value.errcode == AuthErr.PASSKEY_VERIFICATION_FAILED


    def should_reject_local_user_passkey_login(self, db):
        """A local user with a passkey should be rejected at login (completed manually)."""
        from app.db.models import User
        _reg_local(db, username="localuser")
        user = db.query(User).filter(User.username == "localuser").first()
        key = _generate_ec_key()
        cred_id = "local-cred"
        _register_passkey(db, user.id, cred_id, key=key)

        svc = _service()
        begin = svc.begin_passkey_login(db)
        challenge = begin["public_key"]["challenge"]

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))
        auth_data = _make_authenticator_data("localhost", 1)
        signature = _sign_assertion(key, auth_data, client_data_b64)

        with pytest.raises(BizError) as exc:
            svc.complete_passkey_login(db, {
                "rawId": cred_id,
                "challenge_id": begin["challenge_id"],
                "response": {
                    "authenticatorData": _b64(auth_data),
                    "clientDataJSON": client_data_b64,
                    "signature": _b64(signature),
                },
            })
        assert exc.value.errcode == AuthErr.ACCOUNT_LEVEL_INSUFFICIENT


    def should_reject_wrong_rp_id(self, db):
        user = _reg_normal(db)
        key = _generate_ec_key()
        cred_id = "rp-mismatch"
        _register_passkey(db, user.id, cred_id, key=key)

        svc = _service()
        begin = svc.begin_passkey_login(db)
        challenge = begin["public_key"]["challenge"]

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:5173",
        })
        client_data_b64 = _b64(client_data.encode("utf-8"))
        auth_data = _make_authenticator_data("evil.com", 1)

        with pytest.raises(BizError) as exc:
            svc.complete_passkey_login(db, {
                "rawId": cred_id,
                "challenge_id": begin["challenge_id"],
                "response": {
                    "authenticatorData": _b64(auth_data),
                    "clientDataJSON": client_data_b64,
                    "signature": _b64(os.urandom(64)),
                },
            })
        assert exc.value.errcode == AuthErr.PASSKEY_VERIFICATION_FAILED


# ==================================================================
# TestCredentialManagement
# ==================================================================


class TestCredentialManagement:
    def should_list_credentials(self, db):
        user = _reg_normal(db)
        _register_passkey(db, user.id, "cred-1", "Phone")
        _register_passkey(db, user.id, "cred-2", "Laptop")
        result = _service().list_credentials(db, user.id)
        assert len(result) == 2

    def should_delete_credential(self, db):
        user = _reg_normal(db)
        _register_passkey(db, user.id, "cred-del")
        creds = _service().list_credentials(db, user.id)
        assert len(creds) == 1
        _service().delete_credential(db, user.id, creds[0]["id"])
        assert len(_service().list_credentials(db, user.id)) == 0

    def should_not_delete_other_user_credential(self, db):
        u1 = _reg_normal(db, username="alice", email="alice@t.com")
        _reg_normal(db, username="bob", email="bob@t.com")
        _register_passkey(db, u1.id, "alice-key")
        creds = _service().list_credentials(db, u1.id)
        with pytest.raises(BizError):
            _service().delete_credential(db, 2, creds[0]["id"])
