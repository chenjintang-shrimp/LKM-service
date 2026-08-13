from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.err import respond
from app.db.session import get_session
from app.modules.auth.deps import CurrentUser, get_current_user
from app.modules.common import ApiResp, ModuleStatus
from app.modules.forum.schemas import (
    CommentCreate,
    CommentInfo,
    PageData,
    PostCreate,
    PostInfo,
)
from app.modules.forum.service import (
    create_comment,
    get_forum_plan,
    get_post,
    list_comments,
    list_posts,
)
from app.modules.forum.service import (
    create_post as create_post_service,
)
from app.modules.forum.service import (
    delete_post as delete_post_service,
)
from app.modules.forum.service import (
    like_post as like_post_service,
)

router = APIRouter(prefix="/forum", tags=["forum"])


@router.get("/status")
def forum_status() -> ModuleStatus:
    return ModuleStatus(
        module="forum",
        status="implemented_minimal",
        responsibility="Manage community forum posts and comments.",
        next_steps=get_forum_plan()["next_steps"],
    )


@router.get("/posts", response_model=ApiResp[PageData[PostInfo]])
@respond
def get_posts(
    db: Annotated[Session, Depends(get_session)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    category_id: Annotated[str | None, Query(max_length=50)] = None,
):
    return list_posts(db, page=page, limit=limit, category_id=category_id)


@router.post("/posts", response_model=ApiResp[PostInfo])
@respond
def create_forum_post(
    info: PostCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return create_post_service(db, cur.id, info)


@router.get("/posts/{post_id}", response_model=ApiResp[PostInfo])
@respond
def get_post_detail(post_id: int, db: Annotated[Session, Depends(get_session)]):
    return get_post(db, post_id, bump_view=True)


@router.post("/posts/{post_id}/like", response_model=ApiResp[dict])
@respond
def like_forum_post(
    post_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return {"like_count": like_post_service(db, post_id)}


@router.delete("/posts/{post_id}", response_model=ApiResp[dict])
@respond
def delete_forum_post(
    post_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    delete_post_service(db, post_id, cur.id)
    return {"ok": True}


@router.get("/posts/{post_id}/comments", response_model=ApiResp[PageData[CommentInfo]])
@respond
def get_post_comments(
    post_id: int,
    db: Annotated[Session, Depends(get_session)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    return list_comments(db, post_id, page=page, limit=limit)


@router.post("/posts/{post_id}/comments", response_model=ApiResp[CommentInfo])
@respond
def create_post_comment(
    post_id: int,
    info: CommentCreate,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return create_comment(db, post_id, cur.id, info)
