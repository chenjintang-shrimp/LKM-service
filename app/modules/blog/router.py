from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.err import respond
from app.db.session import get_session
from app.modules.auth.deps import CurrentUser, get_current_user, get_optional_user
from app.modules.blog.schemas import (
    BlogCommentCreate,
    BlogCommentInfo,
    BlogSeriesCreate,
    BlogSeriesDetail,
    BlogSeriesInfo,
    BlogSeriesUpdate,
    BlogStarStatus,
    GitFileContent,
)
from app.modules.blog.service import (
    create_comment,
    create_series,
    delete_comment,
    delete_series,
    get_file_content,
    get_series,
    list_comments,
    list_series,
    toggle_star,
    update_series,
)
from app.modules.common import ApiResp, ListData
from typing import Annotated

router = APIRouter(prefix="/blog", tags=["blog"])


# ---- Series ----


@router.post("/series", response_model=ApiResp[BlogSeriesInfo])
@respond
def create_blog_series(
    info: BlogSeriesCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return create_series(db, cur.id, info)


@router.get("/series", response_model=ApiResp[ListData[BlogSeriesInfo]])
@respond
def list_blog_series(
    db: Annotated[Session, Depends(get_session)],
    cur: Annotated[CurrentUser | None, Depends(get_optional_user)],
):
    user_id = cur.id if cur else None
    return {"items": list_series(db, current_user_id=user_id)}


@router.get("/series/{series_id}", response_model=ApiResp[BlogSeriesDetail])
@respond
def get_blog_series(
    series_id: int,
    db: Annotated[Session, Depends(get_session)],
    cur: Annotated[CurrentUser | None, Depends(get_optional_user)],
):
    user_id = cur.id if cur else None
    return get_series(db, series_id, current_user_id=user_id)


@router.put("/series/{series_id}", response_model=ApiResp[BlogSeriesInfo])
@respond
def update_blog_series(
    series_id: int,
    info: BlogSeriesUpdate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return update_series(db, series_id, cur.id, info)


@router.delete("/series/{series_id}")
@respond
def delete_blog_series(
    series_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    delete_series(db, series_id, cur.id)
    return None


# ---- Files ----


@router.get(
    "/series/{series_id}/files/{filepath:path}",
    response_model=ApiResp[GitFileContent],
)
@respond
def get_blog_file(
    series_id: int,
    filepath: str,
    db: Annotated[Session, Depends(get_session)],
):
    return get_file_content(db, series_id, filepath)


# ---- Stars ----


@router.post("/series/{series_id}/star", response_model=ApiResp[BlogStarStatus])
@respond
def star_blog_series(
    series_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return toggle_star(db, series_id, cur.id)


# ---- Comments ----


@router.post(
    "/series/{series_id}/comments",
    response_model=ApiResp[BlogCommentInfo],
)
@respond
def create_blog_comment(
    series_id: int,
    info: BlogCommentCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return create_comment(db, series_id, cur.id, info)


@router.get(
    "/series/{series_id}/comments",
    response_model=ApiResp[ListData[BlogCommentInfo]],
)
@respond
def list_blog_comments(
    series_id: int,
    db: Annotated[Session, Depends(get_session)],
):
    return {"items": list_comments(db, series_id)}


@router.delete("/series/{series_id}/comments/{comment_id}")
@respond
def delete_blog_comment(
    series_id: int,
    comment_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    delete_comment(db, series_id, comment_id, cur.id)
    return None
