"""
2FA (TOTP) HTTP 端点。
POST   /auth/2fa/setup/begin     RequireLevel("normal")  开始 TOTP 设置
POST   /auth/2fa/setup/temp      temp_token 认证         开始 TOTP 设置（管理员强制设置）
POST   /auth/2fa/setup/complete  RequireLevel("normal")  完成 TOTP 设置
POST   /auth/2fa/verify          public (temp_token)     登录时验证 2FA
DELETE /auth/2fa                  RequireLevel("normal")  禁用 2FA
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.err import BizError, respond
from app.modules.auth.errors import AuthErr
from app.db.models import User, expires_at, now_iso
from app.db.repo import consume_once
from app.db.session import get_session
from app.modules.auth import service_2fa
from app.modules.auth.deps import CurrentUser, RequireLevel
from app.modules.auth.models import SetupTransaction
from app.modules.auth.schemas import (
    TOTPConfirmResponse,
    TOTPDisableRequest,
    TOTPDisableResponse,
    TOTPSetupBeginData,
    TOTPSetupCompleteData,
    TOTPSetupCompleteRequest,
    TOTPSetupCompleteTempData,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)
from app.modules.common import ApiResp
from typing import Annotated

router = APIRouter(prefix="/auth/2fa", tags=["auth-2fa"])


def _decode_setup_temp_token(temp_token: str) -> tuple[str, int]:
    """解码并验证 setup 临时令牌，返回 (token_hash, user_id)。"""
    import hashlib
    from app.modules.auth.security import decode_temp_token

    try:
        payload = decode_temp_token(temp_token)
    except Exception as exc:
        raise BizError(AuthErr.TOKEN_INVALID) from exc
    if payload.get("purpose") != "setup":
        raise BizError(AuthErr.TOKEN_INVALID, "Not a setup token")
    user_id = payload.get("user_id")
    if not user_id:
        raise BizError(AuthErr.TOKEN_INVALID)
    token_hash = hashlib.sha256(temp_token.encode()).hexdigest()
    return token_hash, user_id # type: ignore[arg-type]


@router.post("/setup/begin", response_model=ApiResp[TOTPSetupBeginData])
@respond
def setup_2fa_begin(
    db: Annotated[Session, Depends(get_session)],
    cur: CurrentUser = RequireLevel("normal"),
):
    """开始 TOTP 设置。返回密钥和二维码 URI。"""
    result = service_2fa.setup_2fa_begin(db, cur.id)
    return result

@router.post("/setup/temp", response_model=ApiResp[TOTPSetupBeginData])
@respond
def setup_2fa_temp(
    temp_token: str,
    db: Annotated[Session, Depends(get_session)],
):
    """使用登录时获得的临时令牌开始 TOTP 设置（管理员强制设置）。"""
    from sqlalchemy.exc import IntegrityError

    token_hash, user_id = _decode_setup_temp_token(temp_token)

    # 原子性地声明设置令牌 — 只有一个 begin 调用会成功
    try:
        db.add(SetupTransaction(
            token_hash=token_hash,
            user_id=user_id,
            consumed=False,
            expires_at=expires_at(minutes=10),
        ))
        db.flush()
    except IntegrityError:
        db.rollback()
        raise BizError(AuthErr.TOKEN_INVALID, "Setup token already used")

    return service_2fa.setup_2fa_begin(db, user_id)

@router.post("/setup/complete/temp", response_model=ApiResp[TOTPSetupCompleteTempData])
@respond
def setup_2fa_complete_temp(
    temp_token: str,
    code: str,
    db: Annotated[Session, Depends(get_session)],
):
    """使用临时令牌完成 TOTP 设置（管理员强制设置路径）。"""
    token_hash, user_id = _decode_setup_temp_token(temp_token)

    # 原子性地消耗设置事务
    if not consume_once(
        db,
        SetupTransaction,
        {"consumed": True},
        SetupTransaction.token_hash == token_hash,
        SetupTransaction.consumed.is_(False),
        SetupTransaction.expires_at > now_iso(),
    ):
        raise BizError(AuthErr.TOKEN_INVALID, "Setup token not found, already used, or expired")

    txn = db.query(SetupTransaction).filter(SetupTransaction.token_hash == token_hash).first()
    if not txn or txn.user_id != user_id:
        raise BizError(AuthErr.TOKEN_INVALID)

    result_dict = service_2fa.setup_2fa_complete(db, user_id, code) # type: ignore[arg-type]
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        result_dict["access_token"], result_dict["refresh_token"] = _issue_admin_setup_tokens(db, user)
    return result_dict


def _issue_admin_setup_tokens(db: Session, user) -> tuple[str, str]:
    from app.modules.auth.security import create_access_token
    from app.modules.auth.service_auth import _generate_refresh_token, _store_refresh_token
    access_token = create_access_token(
        user_id=user.id,
        account_level=user.account_level,
        role="admin",
        token_version=user.token_version,
    )
    raw_refresh = _generate_refresh_token()
    _store_refresh_token(db, user.id, raw_refresh, mfa_verified=True)
    return access_token, raw_refresh


@router.post("/setup/complete", response_model=ApiResp[TOTPSetupCompleteData])
@respond
def setup_2fa_complete(
    body: TOTPSetupCompleteRequest,
    db: Annotated[Session, Depends(get_session)],
    cur: CurrentUser = RequireLevel("normal"),
):
    """通过验证 TOTP 码完成 TOTP 设置。返回恢复码。"""
    result = service_2fa.setup_2fa_complete(db, cur.id, body.code)
    return result

@router.post("/setup/confirm", response_model=ApiResp[TOTPConfirmResponse])
@respond
def confirm_recovery_codes(
    db: Annotated[Session, Depends(get_session)],
    cur: CurrentUser = RequireLevel("normal"),
):
    """确认用户已保存其恢复码。"""
    return service_2fa.confirm_recovery_codes_saved(db, cur.id)

@router.post("/verify", response_model=ApiResp[TOTPVerifyResponse])
@respond
def verify_2fa(
    body: TOTPVerifyRequest,
    db: Annotated[Session, Depends(get_session)],
):
    """在登录时使用临时令牌和 TOTP / 恢复码验证 2FA。"""
    from app.modules.auth.service_verify import check_code_rate_limit
    check_code_rate_limit("2fa:verify:global", max_count=10, window=3600)
    result = service_2fa.verify_2fa(
        db,
        temp_token=body.temp_token,
        code=body.code,
        recovery_code=body.recovery_code,
        trust_device=body.trust_device,
    )
    return result

@router.delete("", response_model=ApiResp[TOTPDisableResponse])
@respond
def disable_2fa(
    body: TOTPDisableRequest,
    db: Annotated[Session, Depends(get_session)],
    cur: CurrentUser = RequireLevel("normal"),
):
    """为当前用户禁用 2FA。需要有效的 TOTP 码。"""
    result = service_2fa.disable_2fa(db, cur.id, body.code)
    return result
