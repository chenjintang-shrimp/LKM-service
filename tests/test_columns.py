import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.err import BizError, CommonErr
from app.modules.columns.errors import ColumnErr
from app.db.models import Base
from app.db.models import User
from app.modules.columns.models import ColumnApplicationStatus
from app.modules.columns.schemas import (
    ColumnApplicationCreate,
    ColumnApplicationReview,
    ColumnPostCreate,
)
from app.modules.columns.service import (
    create_application,
    create_post,
    get_application,
    get_column,
    get_post,
    list_applications,
    list_columns,
    list_posts,
    review_application,
)
#以下是为user请求头校验新增的导入
import app.modules.auth.models  # noqa: F401 ensure auth tables registered
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import get_session
from app.modules.auth.security import create_access_token, hashpwd
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal: sessionmaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

@pytest.fixture
def client(db):
    def override_get_session():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_session] = override_get_session
    
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


def _user(db, username="alice", email="alice@example.com"):
    from app.db.models import Profile
    user = User(
        username=username, email=email,
        hashed_password=hashpwd("secret123456"), account_level="normal",
    )
    db.add(user)
    db.flush()
    db.add(Profile(user_id=user.id))
    db.flush()
    return user.id


def _application(db, user_id=1):
    return create_application(
        db,
        ColumnApplicationCreate(
            user_id=user_id,
            title="数学思维训练",
            description="面向高中生的数学思维和解题方法专栏。",
            reason="希望长期整理数学学习笔记。",
        ),
    )


def _approved_column(db, user_id=1):
    application = _application(db, user_id=user_id)
    result = review_application(
        db,
        application.id,
        ColumnApplicationReview(
            reviewer_id=user_id,
            status=ColumnApplicationStatus.APPROVED,
            review_note="方向明确，允许开设。",
        ),
    )
    return result["column"]


def _post(db, column_id=1, author_id=1):
    return create_post(
        db,
        column_id,
        ColumnPostCreate(
            author_id=author_id,
            title="如何建立函数思想",
            summary="从变量关系和图像理解入门函数思想。",
            content="函数思想的核心，是用变化关系理解问题。",
        ),
    )


class TestColumnApplications:
    def should_create_application(self, db):
        user_id = _user(db)

        application = _application(db, user_id=user_id)

        assert application.id == 1
        assert application.user_id == user_id
        assert application.status == ColumnApplicationStatus.PENDING

    def should_list_applications(self, db):
        user_id = _user(db)
        _application(db, user_id=user_id)

        applications = list_applications(db)

        assert len(applications) == 1
        assert applications[0].title == "数学思维训练"

    def should_get_application(self, db):
        user_id = _user(db)
        application = _application(db, user_id=user_id)

        found = get_application(db, application.id)

        assert found.id == application.id

    def should_reject_nonexistent_application(self, db):
        with pytest.raises(BizError) as exc:
            get_application(db, 999)

        assert exc.value.errcode == ColumnErr.APPLICATION_NOT_FOUND


class TestColumnReview:
    def should_create_column_when_application_is_approved(self, db):
        user_id = _user(db)
        application = _application(db, user_id=user_id)

        result = review_application(
            db,
            application.id,
            ColumnApplicationReview(
                reviewer_id=user_id,
                status=ColumnApplicationStatus.APPROVED,
            ),
        )

        assert result["application"]["status"] == ColumnApplicationStatus.APPROVED
        assert result["column"]["id"] == 1
        assert result["column"]["owner_id"] == user_id
        assert result["column"]["application_id"] == application.id

    def should_not_create_column_when_application_is_rejected(self, db):
        user_id = _user(db)
        application = _application(db, user_id=user_id)

        result = review_application(
            db,
            application.id,
            ColumnApplicationReview(
                reviewer_id=user_id,
                status=ColumnApplicationStatus.REJECTED,
                review_note="内容方向还不够清晰。",
            ),
        )

        assert result["application"]["status"] == ColumnApplicationStatus.REJECTED
        assert result["column"] is None
        assert list_columns(db) == []

    def should_not_duplicate_column_when_approving_twice(self, db):
        user_id = _user(db)
        application = _application(db, user_id=user_id)
        review = ColumnApplicationReview(
            reviewer_id=user_id,
            status=ColumnApplicationStatus.APPROVED,
        )

        first = review_application(db, application.id, review)
        second = review_application(db, application.id, review)

        assert first["column"]["id"] == second["column"]["id"]
        assert len(list_columns(db)) == 1


class TestColumns:
    def should_list_columns(self, db):
        user_id = _user(db)
        _approved_column(db, user_id=user_id)

        columns = list_columns(db)

        assert len(columns) == 1
        assert columns[0].title == "数学思维训练"

    def should_get_column(self, db):
        user_id = _user(db)
        column = _approved_column(db, user_id=user_id)

        found = get_column(db, column["id"])

        assert found.id == column["id"]

    def should_reject_nonexistent_column(self, db):
        with pytest.raises(BizError) as exc:
            get_column(db, 999)

        assert exc.value.errcode == ColumnErr.NOT_FOUND


class TestColumnPosts:
    def should_create_post(self, db):
        user_id = _user(db)
        column = _approved_column(db, user_id=user_id)

        post = _post(db, column_id=column["id"], author_id=user_id)

        assert post.id == 1
        assert post.column_id == column["id"]
        assert post.author_id == user_id
        assert post.status == "published"

    def should_list_posts_under_column(self, db):
        user_id = _user(db)
        column = _approved_column(db, user_id=user_id)
        _post(db, column_id=column["id"], author_id=user_id)

        posts = list_posts(db, column["id"])

        assert len(posts) == 1
        assert posts[0].title == "如何建立函数思想"

    def should_get_post_with_column_scope(self, db):
        user_id = _user(db)
        column = _approved_column(db, user_id=user_id)
        post = _post(db, column_id=column["id"], author_id=user_id)

        found = get_post(db, post.id, column_id=column["id"])

        assert found.id == post.id

    def should_reject_post_from_wrong_column_scope(self, db):
        user_id = _user(db)
        column = _approved_column(db, user_id=user_id)
        post = _post(db, column_id=column["id"], author_id=user_id)

        with pytest.raises(BizError) as exc:
            get_post(db, post.id, column_id=999)

        assert exc.value.errcode == ColumnErr.POST_NOT_FOUND

    def should_reject_post_for_nonexistent_column(self, db):
        user_id = _user(db)

        with pytest.raises(BizError) as exc:
            _post(db, column_id=999, author_id=user_id)

        assert exc.value.errcode == ColumnErr.NOT_FOUND
class TestColumnRoutes:
    def _setup_user(self, db):
        """Create a user in DB and return (user_id, bearer_token)."""
        user_id = _user(db, username="testuser", email="test@example.com")
        token = create_access_token(user_id=user_id, account_level="normal", role="member")
        return user_id, token

    def should_reject_application_without_auth_header(self, client, db):
        self._setup_user(db)
        application_data = {
            "user_id": 1,
            "title": "数学思维训练",
            "description": "面向高中生的数学思维和解题方法专栏。",
            "reason": "希望长期整理数学学习笔记。",
        }

        response = client.post(
            "/api/v1/columns/applications",
            json=application_data)

        assert response.status_code == 403
        assert response.json()["code"] == CommonErr.FORBIDDEN

    def should_reject_application_when_token_user_mismatches_body_user(self, client, db):
        user_id_1, token = self._setup_user(db)
        # Create a second user so token for user_id=2 is valid
        _user(db, username="other", email="other@example.com")
        token_2 = create_access_token(user_id=2, account_level="normal", role="member")
        resp = client.post(
            "/api/v1/columns/applications",
            headers={"Authorization": f"Bearer {token_2}"},
            json={
                "user_id": user_id_1,
                "title": "数学专栏",
                "description": "整理数学学习内容。",
                "reason": "长期输出学习笔记。",
            },
        )

        assert resp.status_code == 403
        assert resp.json()["code"] == CommonErr.FORBIDDEN

    def should_accept_application_when_token_user_matches_body_user(self, client, db):
        user_id, token = self._setup_user(db)
        resp = client.post(
            "/api/v1/columns/applications",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "user_id": user_id,
                "title": "数学专栏",
                "description": "整理数学学习内容。",
                "reason": "长期输出学习笔记。",
            },
        )

        assert resp.status_code == 200
        assert resp.json()["code"] == 0
        assert resp.json()["data"]["user_id"] == user_id

def should_test():
    pass