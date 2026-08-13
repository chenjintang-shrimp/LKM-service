"""Passkey (WebAuthn) HTTP 端点。

POST   /auth/passkey/register/begin     RequireLevel("normal")  开始 Passkey 注册
POST   /auth/passkey/register/complete  RequireLevel("normal")  完成 Passkey 注册
POST   /auth/passkey/login/begin        public                  开始 Passkey 登录
POST   /auth/passkey/login/complete     public                  完成 Passkey 登录
GET    /auth/passkey/credentials        get_current_user        列出 Passkey 凭据
DELETE /auth/passkey/{cred_id}          get_current_user        删除 Passkey 凭据
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.err import respond
from app.db.session import get_session
from app.modules.auth import service_passkey
from app.modules.auth.deps import CurrentUser, get_current_user
from app.modules.auth.schemas import (
    AuthTokenData,
    MessageResponse,
    PasskeyCredentialItem,
    PasskeyLoginCompleteRequest,
    PasskeyLoginOptionsResponse,
    PasskeyRegisterCompleteRequest,
    PasskeyRegisterCompleteResponse,
    PasskeyRegistrationOptionsResponse,
)
from app.modules.common import ApiResp

router = APIRouter(prefix="/auth/passkey", tags=["auth-passkey"])

@router.post("/register/begin", response_model=ApiResp[PasskeyRegistrationOptionsResponse])
@respond
def begin_passkey_registration(
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """开始 Passkey 注册。返回 PublicKeyCredentialCreationOptions。"""
    result = service_passkey.begin_passkey_registration(db, cur.id)
    return result

@router.post("/register/complete", response_model=ApiResp[PasskeyRegisterCompleteResponse])
@respond
def complete_passkey_registration(
    body: PasskeyRegisterCompleteRequest,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """使用客户端传来的凭据完成 Passkey 注册。"""
    result = service_passkey.complete_passkey_registration(db, cur.id, body.model_dump())
    return result

@router.post("/login/begin", response_model=ApiResp[PasskeyLoginOptionsResponse])
@respond
def begin_passkey_login(
    db: Annotated[Session, Depends(get_session)],
):
    """开始 Passkey 登录。返回 PublicKeyCredentialRequestOptions。"""
    result = service_passkey.begin_passkey_login(db)
    return result

@router.post("/login/complete", response_model=ApiResp[AuthTokenData])
@respond
def complete_passkey_login(
    body: PasskeyLoginCompleteRequest,
    db: Annotated[Session, Depends(get_session)],
):
    """使用客户端传来的凭据完成 Passkey 登录。"""
    result = service_passkey.complete_passkey_login(db, body.model_dump())
    return result

@router.get("/credentials", response_model=ApiResp[list[PasskeyCredentialItem]])
@respond
def list_credentials(
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """列出当前用户的所有 Passkey 凭据。"""
    result = service_passkey.list_credentials(db, cur.id)
    return result

@router.delete("/{cred_id}", response_model=ApiResp[MessageResponse])
@respond
def delete_credential(
    cred_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """通过数据库 ID 删除一个 Passkey 凭据。"""
    result = service_passkey.delete_credential(db, cur.id, cred_id)
    return result
