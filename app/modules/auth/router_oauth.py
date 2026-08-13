"""Github OAuth 路由 – 登录重定向、回调、绑定。"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.err import respond
from app.db.session import get_session
from app.modules.auth import service_oauth
from app.modules.auth.deps import CurrentUser, get_current_user
from app.modules.auth.schemas import (
    AuthTokenData,
    MessageResponse,
    OAuthRedirectResponse,
)
from app.modules.common import ApiResp

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])


@router.get("/github/login")
def github_login(db: Annotated[Session, Depends(get_session)]):
    """将用户重定向到 Github OAuth 授权页面。"""
    url = service_oauth.get_github_auth_url(db, purpose="login")
    return RedirectResponse(url=url)


@router.get("/github/callback", response_model=ApiResp[AuthTokenData])
@respond
async def github_callback(
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
    db: Annotated[Session, Depends(get_session)],
):
    """处理 Github OAuth 回调。验证状态令牌，交换授权码，查找或创建用户，并返回认证令牌。"""
    return await service_oauth.handle_github_callback(db, code, state)


@router.post("/github/login/redirect", response_model=ApiResp[OAuthRedirectResponse])
@respond
def github_bind_redirect(_cur: Annotated[CurrentUser, Depends(get_current_user)], db: Annotated[Session, Depends(get_session)]):
    """返回用于绑定的 OAuth 授权 URL（从 JS 客户端调用）。"""
    url = service_oauth.get_github_auth_url(db, purpose="bind")
    return {"url": url}


@router.get("/github/bind-callback", response_model=ApiResp[MessageResponse])
@respond
async def github_bind_callback(
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    """处理用于账号绑定的 Github OAuth 回调。"""
    return await service_oauth.bind_github(db, cur.id, code, state)
