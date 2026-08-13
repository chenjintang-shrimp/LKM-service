from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.err import BizError, CommonErr
from app.db.models import BlogComment, BlogSeries, BlogStar, Profile, now_iso
from app.db.repo import get_or_raise
from app.modules.auth.schemas import ProfileInfo
from app.modules.blog import git_svc
from app.modules.blog.errors import BlogErr
from app.modules.blog.schemas import (
    BlogCommentCreate,
    BlogCommentInfo,
    BlogSeriesCreate,
    BlogSeriesDetail,
    BlogSeriesInfo,
    BlogSeriesUpdate,
    BlogStarStatus,
)

# ---- private converters ----


def _series_to_info(
    s: BlogSeries, star_count: int = 0, is_starred: bool = False
) -> BlogSeriesInfo:
    return BlogSeriesInfo.model_validate(s).model_copy(
        update={"star_count": star_count, "is_starred": is_starred}
    )


def _comment_to_info(c: BlogComment, profile: ProfileInfo | None = None) -> BlogCommentInfo:
    return BlogCommentInfo.model_validate(c).model_copy(update={"profile": profile})


# ---- star helpers ----


def _star_count(db: Session, series_id: int) -> int:
    return (
        db.query(func.count(BlogStar.user_id))
        .filter(BlogStar.series_id == series_id)
        .scalar()
        or 0
    )


def _is_starred(db: Session, series_id: int, user_id: int) -> bool:
    return (
        db.query(BlogStar)
        .filter(BlogStar.series_id == series_id, BlogStar.user_id == user_id)
        .first()
        is not None
    )


def _get_profile(db: Session, user_id: int) -> ProfileInfo | None:
    profile = db.query(Profile).filter(Profile.user_id == user_id).first()
    if profile:
        return ProfileInfo.model_validate(profile)
    return None


# ---- series CRUD ----


def create_series(db: Session, user_id: int, info: BlogSeriesCreate) -> BlogSeriesInfo:
    existing = (
        db.query(BlogSeries).filter(BlogSeries.repo_name == info.repo_name).first()
    )
    if existing:
        raise BizError(CommonErr.INVALID_INPUT, "Repository name already taken")

    git_svc.init_bare_repo(info.repo_name)

    series = BlogSeries(
        owner_id=user_id,
        title=info.title,
        description=info.description,
        cover_url=info.cover_url,
        repo_name=info.repo_name,
    )
    db.add(series)
    db.flush()
    db.refresh(series)
    return _series_to_info(series)


def list_series(
    db: Session, current_user_id: int | None = None
) -> list[BlogSeriesInfo]:
    items = db.query(BlogSeries).order_by(BlogSeries.id.desc()).all()
    result = []
    for s in items:
        sc = _star_count(db, s.id)
        starred = _is_starred(db, s.id, current_user_id) if current_user_id else False
        result.append(_series_to_info(s, star_count=sc, is_starred=starred))
    return result


def get_series(
    db: Session, series_id: int, current_user_id: int | None = None
) -> BlogSeriesDetail:
    series = get_or_raise(
        db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id,
    )

    sc = _star_count(db, series_id)
    starred = (
        _is_starred(db, series_id, current_user_id) if current_user_id else False
    )

    file_tree = None
    if git_svc.ensure_repo_has_commits(series.repo_name):
        file_tree = git_svc.get_file_tree(series.repo_name)

    return BlogSeriesDetail.model_validate(series).model_copy(
        update={"star_count": sc, "is_starred": starred, "file_tree": file_tree}
    )


def update_series(
    db: Session, series_id: int, user_id: int, info: BlogSeriesUpdate
) -> BlogSeriesInfo:
    series = get_or_raise(
        db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id,
    )
    if series.owner_id != user_id:
        raise BizError(CommonErr.FORBIDDEN)

    if info.title is not None:
        series.title = info.title
    if info.description is not None:
        series.description = info.description
    if info.cover_url is not None:
        series.cover_url = info.cover_url
    if info.status is not None:
        series.status = info.status
    series.updated_at = now_iso()

    db.flush()
    db.refresh(series)
    return _series_to_info(series)


def delete_series(db: Session, series_id: int, user_id: int) -> None:
    series = get_or_raise(
        db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id,
    )
    if series.owner_id != user_id:
        raise BizError(CommonErr.FORBIDDEN)

    git_svc.delete_repo(series.repo_name)
    db.delete(series)
    db.flush()


# ---- star toggle ----


def toggle_star(db: Session, series_id: int, user_id: int) -> BlogStarStatus:
    get_or_raise(db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id)

    existing = (
        db.query(BlogStar)
        .filter(BlogStar.series_id == series_id, BlogStar.user_id == user_id)
        .first()
    )

    if existing:
        db.delete(existing)
        db.flush()
        return BlogStarStatus(starred=False, star_count=_star_count(db, series_id))

    star = BlogStar(user_id=user_id, series_id=series_id)
    db.add(star)
    db.flush()
    return BlogStarStatus(starred=True, star_count=_star_count(db, series_id))


# ---- comments ----


def create_comment(
    db: Session, series_id: int, user_id: int, info: BlogCommentCreate
) -> BlogCommentInfo:
    get_or_raise(db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id)

    if info.parent_id is not None:
        parent = get_or_raise(
            db, BlogComment, CommonErr.INVALID_INPUT,
            BlogComment.id == info.parent_id,
        )
        if parent.series_id != series_id:
            raise BizError(CommonErr.INVALID_INPUT, "Parent comment not found")

    comment = BlogComment(
        user_id=user_id,
        series_id=series_id,
        content=info.content,
        parent_id=info.parent_id,
    )
    db.add(comment)
    db.flush()
    db.refresh(comment)
    return _comment_to_info(comment, profile=_get_profile(db, user_id))


def list_comments(db: Session, series_id: int) -> list[BlogCommentInfo]:
    get_or_raise(db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id)

    comments = (
        db.query(BlogComment)
        .filter(BlogComment.series_id == series_id)
        .order_by(BlogComment.created_at.asc())
        .all()
    )

    user_ids = {c.user_id for c in comments}
    profiles: dict[int, ProfileInfo | None] = {}
    for uid in user_ids:
        profiles[uid] = _get_profile(db, uid)

    comment_map: dict[int, BlogCommentInfo] = {}
    roots: list[BlogCommentInfo] = []

    for c in comments:
        info = _comment_to_info(c, profile=profiles.get(c.user_id))
        comment_map[c.id] = info

    for c in comments:
        info = comment_map[c.id]
        if c.parent_id is not None and c.parent_id in comment_map:
            comment_map[c.parent_id].replies.append(info)
        else:
            roots.append(info)

    return roots


def delete_comment(db: Session, series_id: int, comment_id: int, user_id: int) -> None:
    comment = get_or_raise(
        db, BlogComment, BlogErr.COMMENT_NOT_FOUND,
        BlogComment.id == comment_id,
        BlogComment.series_id == series_id,
    )
    if comment.user_id != user_id:
        raise BizError(CommonErr.FORBIDDEN)
    db.delete(comment)
    db.flush()


# ---- files ----


def get_file_content(db: Session, series_id: int, filepath: str) -> dict:
    series = get_or_raise(
        db, BlogSeries, BlogErr.SERIES_NOT_FOUND, BlogSeries.id == series_id,
    )
    content = git_svc.read_file(series.repo_name, filepath)
    return {"filepath": filepath, "content": content}
