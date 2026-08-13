import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.api.router import api_router
from app.core.config import settings
from app.core.err import BizError, map_err, resp_json
from app.db.init_db import init_db


def _verify_production_secrets() -> None:
    """
    仅显式测试环境 (LKM_ENV=test 或 PYTEST_RUNNING) 允许使用弱密钥继续运行。
    其他所有模式都必须为 JWT_SECRET 和 TOTP 加密密钥设置强且非默认的值。
    """
    import os

    if os.environ.get("LKM_ENV") == "test" or os.environ.get("PYTEST_RUNNING"):
        return

    if settings.jwt_secret.startswith("change-me") or len(settings.jwt_secret) < 32:
        print(
            "ERROR: Default or weak JWT secret detected. "
            "Set LKM_JWT_SECRET to a random 64+ character value.",
            file=sys.stderr,
        )
        sys.exit(1)

    # JWT 签名密钥必须与 TOTP 加密密钥分开
    if settings.jwt_secret == getattr(settings, "totp_encryption_key", None):
        print(
            "ERROR: JWT_SECRET must be different from TOTP encryption key.",
            file=sys.stderr,
        )
        sys.exit(1)

    # TOTP 加密密钥不得使用默认值
    totp_key = getattr(settings, "totp_encryption_key", "")
    if not totp_key or totp_key.startswith("change-me") or len(totp_key) < 32:
        print(
            "ERROR: Default or weak TOTP encryption key detected. "
            "Set LKM_TOTP_ENCRYPTION_KEY to a random 64+ character value.",
            file=sys.stderr,
        )
        sys.exit(1)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    import asyncio

    _verify_production_secrets()
    init_db()

    from app.modules.auth.service_passkey import cleanup_expired_challenges
    cleanup_task = asyncio.create_task(cleanup_expired_challenges())

    yield  # type: ignore[redefined-outer-name]

    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    from app.db.session import dispose_engine
    dispose_engine()


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )
    application.include_router(api_router, prefix=settings.api_prefix)
    application.add_exception_handler(BizError, _on_err)
    application.add_exception_handler(RequestValidationError, _on_err)

    @application.get("/")
    async def root() -> dict[str, str]:
        return {"message": "OK"}

    return application


async def _on_err(_request, exc):
    _, errcode, detail = map_err(exc)
    return resp_json(errcode, detail=detail)


app = create_app()
