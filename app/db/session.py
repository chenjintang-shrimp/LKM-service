from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def get_engine() -> Engine | None:
    global _engine
    if _engine is None:
        connect_args: dict = {}
        if settings.db_driver == "sqlite":
            connect_args["check_same_thread"] = False
        _engine = create_engine(
            settings.database_url,
            echo=False,
            connect_args=connect_args,
        )
        # 启用 SQLite 外键支持（必须按连接设置）
        from sqlalchemy import event

        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            if settings.db_driver == "sqlite":
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys = ON")
                cursor.close()
    return _engine


def _get_session_local() -> sessionmaker | None:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine(),
        )
    return _SessionLocal


def get_session():
    factory = _get_session_local()
    assert factory is not None
    db = factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        import sys

        from sqlalchemy.exc import IntegrityError
        exc_value = sys.exc_info()[1]
        if exc_value is not None and isinstance(exc_value, IntegrityError):
            from app.core.err import BizError
            from app.modules.auth.errors import AuthErr
            raise BizError(AuthErr.ALREADY_REGISTERED, "Resource already exists") from exc_value
        raise
    finally:
        db.close()


def new_session():
    """创建独立会话，与主会话共享同一引擎（数据库连接池）但使用独立事务。"""
    factory = _get_session_local()
    assert factory is not None
    return factory(bind=get_engine())


def dispose_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionLocal = None
