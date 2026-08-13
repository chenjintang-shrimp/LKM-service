import app.modules.auth.models
from app.db.models import Base
from app.db.session import get_engine


def init_db() -> None:
    # 开发环境自动建表。生产环境使用 Alembic。
    engine = get_engine()
    assert engine is not None
    Base.metadata.create_all(bind=engine)
