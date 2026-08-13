"""设置路由 -- 邮箱 / 手机号绑定端点。

所有端点都需要已登录用户（get_current_user）。

POST /auth/settings/bind-email/request  {email}  -> 通过 EmailProvider 发送验证码
POST /auth/settings/bind-email/verify   {email, code} -> 绑定 + 如果是本地用户则升级
POST /auth/settings/bind-phone/request  {phone}  -> 通过 SmsProvider 发送验证码
POST /auth/settings/bind-phone/verify   {phone, code} -> 绑定 + 如果是本地用户则升级
"""

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.err import BizError, respond
from app.modules.auth.errors import AuthErr
from app.db.models import User
from app.db.repo import get_or_raise
from app.db.session import get_session
from app.modules.auth import service_auth
from app.modules.auth.deps import (
    CurrentUser,
    get_current_user,
    get_email_provider,
    get_sms_provider,
)
from app.modules.auth.providers.base import EmailProvider, SmsProvider
from app.modules.auth.schemas import BindCodeRequestResponse, BindCodeVerifyResponse
from app.modules.auth.service_verify import (
    check_code_rate_limit,
    consume_email_code,
    consume_phone_code,
    create_email_verification,
    create_phone_verification,
)
from app.modules.common import ApiResp
from typing import Annotated

router = APIRouter(prefix="/auth/settings", tags=["auth-settings"])

_BIND_PURPOSE = "bind"

class BindEmailRequest(BaseModel):
    email: EmailStr


class BindEmailVerify(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)


class BindPhoneRequest(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)


class BindPhoneVerify(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)
    code: str = Field(..., min_length=6, max_length=6)

@router.post("/bind-email/request", response_model=ApiResp[BindCodeRequestResponse])
@respond
def bind_email_request(
    body: BindEmailRequest,
    background_tasks: BackgroundTasks,
    _cur: Annotated[CurrentUser, Depends(get_current_user)],
    email_provider: Annotated[EmailProvider, Depends(get_email_provider)],
    db: Annotated[Session, Depends(get_session)],
):
    """请求用于绑定的邮箱验证码。"""
    # 检查邮箱是否已被占用
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise BizError(AuthErr.ALREADY_REGISTERED, "Email already bound to another account")

    rate_limit_key = f"bind_email:{body.email}"
    check_code_rate_limit(rate_limit_key)

    code, record_id = create_email_verification(db, body.email, _BIND_PURPOSE)
    background_tasks.add_task(email_provider.send_code, body.email, code)

    return {"message": "Verification code sent to email", "record_id": record_id}


@router.post("/bind-email/verify", response_model=ApiResp[BindCodeVerifyResponse])
@respond
def bind_email_verify(
    body: BindEmailVerify,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """验证邮箱验证码并将邮箱绑定到当前用户。"""
    consume_email_code(db, body.email, body.code, _BIND_PURPOSE)

    # 确保邮箱仍未被占用（可能在请求和验证之间被占用）
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise BizError(AuthErr.ALREADY_REGISTERED, "Email already bound to another account")

    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == cur.id)

    user.email = body.email
    db.flush()

    # 如果适用，将本地用户升级为普通用户
    service_auth.upgrade_to_normal(db, user) # type: ignore[arg-type]

    return {"message": "Email bound successfully"}

@router.post("/bind-phone/request", response_model=ApiResp[BindCodeRequestResponse])
@respond
def bind_phone_request(
    body: BindPhoneRequest,
    background_tasks: BackgroundTasks,
    _cur: Annotated[CurrentUser, Depends(get_current_user)],
    sms_provider: Annotated[SmsProvider, Depends(get_sms_provider)],
    db: Annotated[Session, Depends(get_session)],
):
    """请求用于绑定的短信验证码。"""
    # 检查手机号是否已被占用
    existing = db.query(User).filter(User.phone == body.phone).first()
    if existing:
        raise BizError(AuthErr.ALREADY_REGISTERED, "Phone already bound to another account")

    rate_limit_key = f"bind_phone:{body.phone}"
    check_code_rate_limit(rate_limit_key)

    code, record_id = create_phone_verification(db, body.phone, _BIND_PURPOSE)
    background_tasks.add_task(sms_provider.send_code, body.phone, code)

    return {"message": "Verification code sent to phone", "record_id": record_id}


@router.post("/bind-phone/verify", response_model=ApiResp[BindCodeVerifyResponse])
@respond
def bind_phone_verify(
    body: BindPhoneVerify,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """验证手机验证码并将手机号绑定到当前用户。"""
    consume_phone_code(db, body.phone, body.code, _BIND_PURPOSE)

    # 确保手机号仍未被占用
    existing = db.query(User).filter(User.phone == body.phone).first()
    if existing:
        raise BizError(AuthErr.ALREADY_REGISTERED, "Phone already bound to another account")

    user = get_or_raise(db, User, AuthErr.USER_NOT_FOUND, User.id == cur.id)

    user.phone = body.phone
    db.flush()

    # 如果适用，将本地用户升级为普通用户
    service_auth.upgrade_to_normal(db, user) # type: ignore[arg-type]

    return {"message": "Phone bound successfully"}
