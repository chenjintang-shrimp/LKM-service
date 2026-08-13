import app.modules.auth.models  # noqa: F401  确保认证表被注册
from app.db.models import Base
from app.db.session import get_engine


def init_db() -> None:
    # 开发环境自动建表。生产环境使用 Alembic。
    engine = get_engine()
    assert engine is not None
    Base.metadata.create_all(bind=engine)
