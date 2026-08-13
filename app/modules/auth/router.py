from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.err import BizError, CommonErr, respond
from app.db.models import User as UserModel
from app.db.session import get_session
from app.modules.auth import service_auth
from app.modules.auth.deps import (
    CurrentUser,
    get_current_user,
    get_email_provider,
    get_sms_provider,
)
from app.modules.auth.providers.base import EmailProvider
from app.modules.auth.schemas import (
    AuthTokenData,
    MessageResponse,
    ProfileInfo,
    ProfileUpdate,
    RefreshRequest,
    RegByEmailResponse,
    RegByPhoneResponse,
    RegNormalResponse,
    TokenPair,
    UserLoginPassword,
    UserRegByEmail,
    UserRegByPhone,
    UserRegLocal,
    UserRegNormal,
)
from app.modules.auth.service import get_profile, update_profile
from app.modules.auth.service_auth import (
    _consume_pending_normal_registration,
    _store_pending_normal_registration,
)
from app.modules.auth.service_verify import (
    check_code_rate_limit,
    consume_email_code,
    consume_phone_code,
    create_email_verification,
    create_phone_verification,
)
from app.modules.common import ApiResp

router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/me", response_model=ApiResp[CurrentUser])
@respond
def get_me(cur: CurrentUser = Depends(get_current_user)):
    return cur


@router.get("/{user_id}", response_model=ApiResp[ProfileInfo])
@respond
def get_user(user_id: int, db: Session = Depends(get_session)):
    return get_profile(db, user_id)


@router.put("/{user_id}/profile", response_model=ApiResp[ProfileInfo])
@respond
def edit_profile(
    user_id: int,
    info: ProfileUpdate,
    cur: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_session),
):
    if cur.id != user_id:
        raise BizError(CommonErr.FORBIDDEN)
    update_profile(db, user_id, info)
    return get_profile(db, user_id)

@router.post("/reg/local", response_model=ApiResp[AuthTokenData])
@respond
def register_local(info: UserRegLocal, db: Session = Depends(get_session)):
    return service_auth.register_local(db, info)


@router.post("/reg/normal", response_model=ApiResp[RegNormalResponse])
@respond
def register_normal_with_password_route(
    info: UserRegNormal,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    """发起普通注册 """
    if not info.email and not info.phone:
        raise BizError(
            CommonErr.INVALID_INPUT,
            "At least one of email or phone is required for normal registration",
        )

    # 存储待处理的注册数据
    txn_id = _store_pending_normal_registration(
        db, info.username, info.password, info.email, info.phone
    )

    result: dict = {
        "message": "Verification code(s) sent",
        "txn_id": txn_id,
        "email_sent": False,
        "phone_sent": False,
    }

    if info.email:
        check_code_rate_limit(f"reg:email:{info.email}", max_count=5, window=3600)
        email_code, _ = create_email_verification(db, info.email, "register")
        background_tasks.add_task(get_email_provider().send_code, info.email, email_code)
        result["email_sent"] = True

    if info.phone:
        check_code_rate_limit(f"reg:phone:{info.phone}", max_count=5, window=3600)
        phone_code, _ = create_phone_verification(db, info.phone, "register")
        background_tasks.add_task(get_sms_provider().send_code, info.phone, phone_code)
        result["phone_sent"] = True

    return result


@router.post("/reg/normal/verify", response_model=ApiResp[AuthTokenData])
@respond
def register_normal_verify(
    txn_id: str,
    email_code: str | None = None,
    phone_code: str | None = None,
    db: Session = Depends(get_session),
):
    """使用用户名+密码+联系方式完成普通注册。"""
    return _consume_pending_normal_registration(
        db, txn_id, email_code=email_code, phone_code=phone_code
    )


@router.post("/reg/phone", response_model=ApiResp[RegByPhoneResponse])
@respond
def register_phone(
    info: UserRegByPhone,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    """发起仅手机号的注册。发送短信验证码。"""
    check_code_rate_limit(f"reg:phone:{info.phone}", max_count=5, window=3600)
    code, _ = create_phone_verification(db, info.phone, "register")
    background_tasks.add_task(get_sms_provider().send_code, info.phone, code)
    return {"phone": info.phone, "message": "SMS verification code sent"}


@router.post("/reg/phone/verify", response_model=ApiResp[AuthTokenData])
@respond
def register_phone_verify(phone: str, code: str, db: Session = Depends(get_session)):
    """完成仅手机号的注册 — 创建一个普通账号（无密码）。"""
    check_code_rate_limit(f"reg:phone:verify:{phone}", max_count=5, window=3600)
    consume_phone_code(db, phone, code, "register")
    return service_auth.register_by_verify(db, "phone", phone)


@router.post("/reg/email", response_model=ApiResp[RegByEmailResponse])
@respond
def register_email(
    info: UserRegByEmail,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    """发起仅邮箱的注册。发送邮箱验证码。"""
    check_code_rate_limit(f"reg:email:{info.email}", max_count=5, window=3600)
    code, _ = create_email_verification(db, info.email, "register")
    background_tasks.add_task(get_email_provider().send_code, info.email, code)
    return {"email": info.email, "message": "Email verification code sent"}


@router.post("/reg/email/verify", response_model=ApiResp[AuthTokenData])
@respond
def register_email_verify(email: str, code: str, db: Session = Depends(get_session)):
    """完成仅邮箱的注册 — 创建一个普通账号（无密码）。"""
    check_code_rate_limit(f"reg:email:verify:{email}", max_count=5, window=3600)
    consume_email_code(db, email, code, "register")
    return service_auth.register_by_verify(db, "email", email)


@router.post("/login/code/request", response_model=ApiResp[MessageResponse])
@respond
def login_code_request(
    contact: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    """请求登录验证码。自动检测邮箱还是手机号。"""

    # 无论用户是否存在，都进行速率限制
    check_code_rate_limit(f"login:code:{contact}", max_count=5, window=3600)

    # 检查用户是否存在且符合条件
    if "@" in contact:
        user = db.query(UserModel).filter(UserModel.email == contact).first()
    else:
        user = db.query(UserModel).filter(UserModel.phone == contact).first()

    if not user or user.account_level == "local":
        # 统一响应 — 不泄露用户是否存在
        return {"message": "If account exists, verification code sent"}

    # 用户存在 — 创建并发送验证码
    if "@" in contact:
        code, _ = create_email_verification(db, contact, "login")
        background_tasks.add_task(get_email_provider().send_code, contact, code)
    else:
        code, _ = create_phone_verification(db, contact, "login")
        background_tasks.add_task(get_sms_provider().send_code, contact, code)

    return {"message": "Verification code sent"}


@router.post("/login/code", response_model=ApiResp[AuthTokenData])
@respond
def login_code(
    contact: str,
    code: str,
    db: Session = Depends(get_session),
):
    """使用验证码登录。仅限普通/管理员用户。"""
    check_code_rate_limit(f"login:code:verify:{contact}", max_count=5, window=3600)
    return service_auth.login_code(db, contact, code)


@router.post("/login/password", response_model=ApiResp[AuthTokenData])
@respond
def login_password_route(info: UserLoginPassword, db: Session = Depends(get_session)):
    return service_auth.login_password(db, info)


@router.post("/refresh", response_model=ApiResp[TokenPair])
@respond
def refresh_access_token_route(info: RefreshRequest, db: Session = Depends(get_session)):
    check_code_rate_limit("token:refresh:global", max_count=30, window=60)
    return service_auth.refresh_access_token(db, info.refresh_token)


@router.post("/logout", response_model=ApiResp[MessageResponse])
@respond
def logout_route(cur: CurrentUser = Depends(get_current_user), db: Session = Depends(get_session)):
    service_auth.revoke_all_refresh_tokens(db, cur.id)
    return {"message": "Logged out successfully"}


@router.post("/login/magic-link/request", response_model=ApiResp[MessageResponse])
@respond
def magic_link_request(
    background_tasks: BackgroundTasks,
    email: str = Query(...),
    email_provider: EmailProvider = Depends(get_email_provider),
    db: Session = Depends(get_session),
):
    service_auth.request_magic_link(
        db,
        email,
        email_provider,
        purpose="login",
        frontend_url=settings.frontend_callback,
        background_tasks=background_tasks,
    )
    return {"message": "If email exists, magic link sent"}


@router.get("/login/magic-link/verify", response_model=ApiResp[AuthTokenData])
@respond
def magic_link_verify(
    token: str,
    db: Session = Depends(get_session),
):
    check_code_rate_limit("magic-link:verify:global", max_count=10, window=3600)
    return service_auth.verify_magic_link(db, token, purpose="login")
