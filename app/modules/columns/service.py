from sqlalchemy.orm import Session

from app.db.models import Column, ColumnApplication, ColumnPost, now_iso
from app.db.repo import get_or_raise
from app.modules.columns.errors import ColumnErr
from app.modules.columns.models import (
    COLUMN_TABLE_PLAN,
    ColumnApplicationStatus,
    ColumnPostStatus,
)
from app.modules.columns.schemas import (
    ColumnApplicationCreate,
    ColumnApplicationInfo,
    ColumnApplicationReview,
    ColumnInfo,
    ColumnPostCreate,
    ColumnPostInfo,
)


def get_column_plan() -> dict:
    return {
        "status": "implemented_minimal",
        "tables": COLUMN_TABLE_PLAN,
        "next_steps": [
            "Add authentication before write operations",
            "Restrict review APIs to administrators",
            "Add pagination, search, and board relation",
        ],
    }


def create_application(
    db: Session, info: ColumnApplicationCreate
) -> ColumnApplicationInfo:
    app = ColumnApplication(
        user_id=info.user_id,
        title=info.title,
        description=info.description,
        reason=info.reason,
    )
    db.add(app)
    db.flush()
    db.refresh(app)
    return ColumnApplicationInfo.model_validate(app)


def list_applications(db: Session) -> list[ColumnApplicationInfo]:
    apps = (
        db.query(ColumnApplication)
        .order_by(ColumnApplication.id.desc())
        .all()
    )
    return [ColumnApplicationInfo.model_validate(a) for a in apps]


def get_application(db: Session, application_id: int) -> ColumnApplicationInfo:
    return ColumnApplicationInfo.model_validate(get_or_raise(
        db, ColumnApplication, ColumnErr.APPLICATION_NOT_FOUND,
        ColumnApplication.id == application_id,
    ))


def review_application(
    db: Session, application_id: int, info: ColumnApplicationReview
) -> dict:
    app = get_or_raise(
        db, ColumnApplication, ColumnErr.APPLICATION_NOT_FOUND,
        ColumnApplication.id == application_id,
    )

    app.status = info.status
    app.reviewer_id = info.reviewer_id
    app.review_note = info.review_note
    app.reviewed_at = now_iso()
    db.flush()
    db.refresh(app)

    column = None
    if info.status == ColumnApplicationStatus.APPROVED:
        column = _ensure_column_for_application(db, app)

    return {
        "application": ColumnApplicationInfo.model_validate(app).model_dump(),
        "column": column.model_dump() if column else None,
    }


def list_columns(db: Session) -> list[ColumnInfo]:
    cols = db.query(Column).order_by(Column.id.desc()).all()
    return [ColumnInfo.model_validate(c) for c in cols]


def get_column(db: Session, column_id: int) -> ColumnInfo:
    return ColumnInfo.model_validate(get_or_raise(
        db, Column, ColumnErr.NOT_FOUND, Column.id == column_id,
    ))


def create_post(
    db: Session, column_id: int, info: ColumnPostCreate
) -> ColumnPostInfo:
    get_or_raise(db, Column, ColumnErr.NOT_FOUND, Column.id == column_id)

    post = ColumnPost(
        column_id=column_id,
        author_id=info.author_id,
        title=info.title,
        summary=info.summary,
        content=info.content,
        status=ColumnPostStatus.PUBLISHED,
        published_at=now_iso(),
    )
    db.add(post)
    db.flush()
    db.refresh(post)
    return ColumnPostInfo.model_validate(post)


def list_posts(db: Session, column_id: int) -> list[ColumnPostInfo]:
    get_or_raise(db, Column, ColumnErr.NOT_FOUND, Column.id == column_id)
    posts = (
        db.query(ColumnPost)
        .filter(ColumnPost.column_id == column_id)
        .order_by(ColumnPost.id.desc())
        .all()
    )
    return [ColumnPostInfo.model_validate(p) for p in posts]


def get_post(
    db: Session, post_id: int, column_id: int | None = None
) -> ColumnPostInfo:
    filters = [ColumnPost.id == post_id]
    if column_id is not None:
        filters.append(ColumnPost.column_id == column_id)
    return ColumnPostInfo.model_validate(get_or_raise(
        db, ColumnPost, ColumnErr.POST_NOT_FOUND, *filters,
    ))


def _ensure_column_for_application(
    db: Session, application: ColumnApplication
) -> ColumnInfo:
    col = (
        db.query(Column)
        .filter(Column.application_id == application.id)
        .first()
    )
    if col:
        return ColumnInfo.model_validate(col)

    col = Column(
        owner_id=application.user_id,
        application_id=application.id,
        title=application.title,
        description=application.description,
    )
    db.add(col)
    db.flush()
    db.refresh(col)
    return ColumnInfo.model_validate(col)
