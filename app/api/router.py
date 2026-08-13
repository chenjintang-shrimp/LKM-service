from fastapi import APIRouter

from app.modules.auth.router import router as auth_router
from app.modules.auth.router_2fa import router as auth_2fa_router
from app.modules.auth.router_oauth import router as auth_oauth_router
from app.modules.auth.router_passkey import router as auth_passkey_router
from app.modules.auth.router_recovery import router as auth_recovery_router
from app.modules.auth.router_settings import router as auth_settings_router
from app.modules.blog.git_http import git_router
from app.modules.blog.router import router as blog_router
from app.modules.boards.router import router as boards_router
from app.modules.columns.router import router as columns_router
from app.modules.files.router import router as files_router
from app.modules.forum.router import router as forum_router
from app.modules.health.router import router as health_router
from app.modules.members.router import router as members_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(members_router)
api_router.include_router(auth_router)
api_router.include_router(auth_2fa_router)
api_router.include_router(auth_oauth_router)
api_router.include_router(auth_passkey_router)
api_router.include_router(auth_recovery_router)
api_router.include_router(auth_settings_router)
api_router.include_router(boards_router)
api_router.include_router(columns_router)
api_router.include_router(forum_router)
api_router.include_router(files_router)
api_router.include_router(blog_router)
api_router.include_router(git_router)
