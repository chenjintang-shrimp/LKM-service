from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.err import BizError, CommonErr, respond
from app.db.session import get_session
from app.modules.auth.deps import CurrentUser, get_current_user
from app.modules.columns.schemas import (
    ColumnApplicationCreate,
    ColumnApplicationInfo,
    ColumnApplicationReview,
    ColumnInfo,
    ColumnPlanData,
    ColumnPostCreate,
    ColumnPostInfo,
    ReviewResultData,
)
from app.modules.columns.service import (
    create_application,
    create_post,
    get_application,
    get_column,
    get_column_plan,
    get_post,
    list_applications,
    list_columns,
    list_posts,
    review_application,
)
from app.modules.common import ApiResp, ListData, ModuleStatus
from typing import Annotated

router = APIRouter(prefix="/columns", tags=["columns"])


@router.get("/status")
def columns_status() -> ModuleStatus:
    return ModuleStatus(
        module="columns",
        status="implemented_minimal",
        responsibility="Handle column applications, approved columns, and column posts.",
        next_steps=[
            "Add authentication before write operations",
            "Restrict review APIs to administrators",
            "Add pagination, search, and board relation",
        ],
    )


@router.get("/plan", response_model=ApiResp[ColumnPlanData])
@respond
def column_plan():
    return get_column_plan()


@router.post("/applications", response_model=ApiResp[ColumnApplicationInfo])
@respond
def apply_column(
    info: ColumnApplicationCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    if cur.id != info.user_id:
        raise BizError(CommonErr.FORBIDDEN)
    return create_application(db, info)


@router.get("/applications", response_model=ApiResp[ListData[ColumnApplicationInfo]])
@respond
def get_applications(db: Annotated[Session, Depends(get_session)]):
    return {"items": list_applications(db)}


@router.get("/applications/{application_id}", response_model=ApiResp[ColumnApplicationInfo])
@respond
def get_application_detail(application_id: int, db: Annotated[Session, Depends(get_session)]):
    return get_application(db, application_id)


@router.post("/applications/{application_id}/review", response_model=ApiResp[ReviewResultData])
@respond
def review_column_application(
    application_id: int,
    info: ColumnApplicationReview,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    if cur.id != info.reviewer_id:
        raise BizError(CommonErr.FORBIDDEN)
    return review_application(db, application_id, info)


@router.get("", response_model=ApiResp[ListData[ColumnInfo]])
@respond
def get_columns(db: Annotated[Session, Depends(get_session)]):
    return {"items": list_columns(db)}


@router.get("/{column_id}", response_model=ApiResp[ColumnInfo])
@respond
def get_column_detail(column_id: int, db: Annotated[Session, Depends(get_session)]):
    return get_column(db, column_id)


@router.post("/{column_id}/posts", response_model=ApiResp[ColumnPostInfo])
@respond
def publish_column_post(
    column_id: int,
    info: ColumnPostCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    if cur.id != info.author_id:
        raise BizError(CommonErr.FORBIDDEN)
    return create_post(db, column_id, info)


@router.get("/{column_id}/posts", response_model=ApiResp[ListData[ColumnPostInfo]])
@respond
def get_column_posts(column_id: int, db: Annotated[Session, Depends(get_session)]):
    return {"items": list_posts(db, column_id)}


@router.get("/{column_id}/posts/{post_id}", response_model=ApiResp[ColumnPostInfo])
@respond
def get_column_post_detail(column_id: int, post_id: int, db: Annotated[Session, Depends(get_session)]):
    return get_post(db, post_id, column_id=column_id)
