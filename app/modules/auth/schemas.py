from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field


class ProfileRole(StrEnum):
    MEMBER = "member"
    ADMIN = "admin"


def _validate_password(v: str) -> str:
    if len(v) < 12:
        raise ValueError("Password must be at least 12 characters")
    return v


Password = Annotated[str, AfterValidator(_validate_password)]


class ProfileInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    nickname: str | None = None
    avatar: str | None = None
    role: ProfileRole = ProfileRole.MEMBER


class ProfileUpdate(BaseModel):
    nickname: str | None = None
    avatar: str | None = None


class AccountLevel(StrEnum):
    LOCAL = "local"
    NORMAL = "normal"
    ADMIN = "admin"


class UserRegLocal(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: Password = Field(...)


class UserRegNormal(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: Password = Field(...)
    email: EmailStr | None = None
    phone: str | None = Field(None, min_length=5, max_length=20)


class UserRegByPhone(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)


class UserRegByEmail(BaseModel):
    email: EmailStr


class UserLoginPassword(BaseModel):
    account: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class AuthTokenData(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    user_id: int
    account_level: str
    requires_2fa: bool = False
    setup_required: bool = False
    temp_token: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str

class TOTPSetupBeginData(BaseModel):
    secret: str
    qr_code_uri: str


class TOTPSetupCompleteRequest(BaseModel):
    code: str


class TOTPSetupCompleteData(BaseModel):
    recovery_codes: list[str]
    confirmed_saved_required: bool


class TOTPSetupCompleteTempData(BaseModel):
    """管理员强制设置的响应 — 包含认证令牌。"""
    recovery_codes: list[str]
    confirmed_saved_required: bool
    access_token: str | None = None
    refresh_token: str | None = None


class TOTPVerifyRequest(BaseModel):
    temp_token: str
    code: str | None = None
    recovery_code: str | None = None
    trust_device: bool = False


class TOTPDisableRequest(BaseModel):
    code: str


# ── 通用消息响应 ──────────────────────────────────────────────


class MessageResponse(BaseModel):
    message: str


# ── 注册响应 ──────────────────────────────────────────────────


class RegNormalResponse(BaseModel):
    message: str
    txn_id: str
    email_sent: bool = False
    phone_sent: bool = False


class RegByPhoneResponse(BaseModel):
    phone: str
    message: str


class RegByEmailResponse(BaseModel):
    email: EmailStr
    message: str


# ── Recovery 响应 ─────────────────────────────────────────────


class RecoverCheckResponse(BaseModel):
    recoverable: bool


class RecoverRequires2FAResponse(BaseModel):
    message: str
    requires_2fa: bool | None = None
    txn_id: str | None = None
    temp_token: str | None = None


class AdminRecoverBeginResponse(BaseModel):
    message: str
    txn_id: str


class AdminRecoverVerifyContactResponse(BaseModel):
    message: str
    txn_id: str
    temp_token: str


class AdminRecoverVerifyTOTPResponse(BaseModel):
    message: str
    txn_id: str


# ── OAuth 响应 ────────────────────────────────────────────────


class OAuthRedirectResponse(BaseModel):
    url: str


# ── Passkey 响应 ──────────────────────────────────────────────


class PasskeyRegistrationOptionsResponse(BaseModel):
    challenge_id: str
    public_key: dict


class PasskeyLoginOptionsResponse(BaseModel):
    challenge_id: str
    public_key: dict


class PasskeyRegisterCompleteRequest(BaseModel):
    """WebAuthn 注册完成请求体。"""
    rawId: str
    challenge_id: str
    response: dict = Field(default_factory=dict)
    device_name: str | None = None


class PasskeyLoginCompleteRequest(BaseModel):
    """WebAuthn 登录完成请求体。"""
    rawId: str
    challenge_id: str
    response: dict = Field(default_factory=dict)


class PasskeyRegisterCompleteResponse(BaseModel):
    message: str
    device_name: str


class PasskeyCredentialItem(BaseModel):
    id: int
    credential_id: str
    device_name: str
    created_at: str  # ISO datetime


# ── TOTP 验证响应 ─────────────────────────────────────────────


# ── Settings 响应 ───────────────────────────────────────────────


class BindCodeRequestResponse(BaseModel):
    message: str
    record_id: int


class BindCodeVerifyResponse(BaseModel):
    message: str


class TOTPConfirmResponse(BaseModel):
    message: str


class TOTPVerifyResponse(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    user_id: int
    account_level: str
    trust_device: bool = False
    mfa_verified: bool | None = None
    message: str | None = None


class TOTPDisableResponse(BaseModel):
    message: str
