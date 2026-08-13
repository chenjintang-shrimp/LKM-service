from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.modules.blog.models import BlogSeriesStatus
from app.modules.columns.models import (
    ColumnApplicationStatus,
    ColumnPostStatus,
    ColumnStatus,
)

if TYPE_CHECKING:
    from app.modules.auth.models import (
        TOTP,
        PasskeyCredential,
        RecoveryCode,
        RefreshToken,
        UserOAuth,
    )



class Base(DeclarativeBase):
    pass


def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def expires_at(days: float = 0, minutes: float = 0) -> str:
    """从现在起 days/minutes 后的 ISO 时间戳。"""
    return (
        datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(days=days, minutes=minutes)
    ).isoformat()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(200), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(20), unique=True, nullable=True)
    account_level: Mapped[str] = mapped_column(String(10), nullable=False, default="local")
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    locked_until: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    profile: Mapped[Profile] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    column_applications: Mapped[list[ColumnApplication]] = relationship(
        back_populates="user", foreign_keys="ColumnApplication.user_id"
    )
    owned_columns: Mapped[list[Column]] = relationship(back_populates="owner")
    posts: Mapped[list[ColumnPost]] = relationship(back_populates="author")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(back_populates="user")
    oauth_bindings: Mapped[list[UserOAuth]] = relationship(back_populates="user")
    totp: Mapped[TOTP | None] = relationship(back_populates="user", uselist=False)
    recovery_codes: Mapped[list[RecoveryCode]] = relationship(back_populates="user")
    passkey_credentials: Mapped[list[PasskeyCredential]] = relationship(back_populates="user")
    blog_series: Mapped[list[BlogSeries]] = relationship(back_populates="owner")
    forum_posts: Mapped[list[ForumPost]] = relationship(back_populates="author")
    forum_comments: Mapped[list[ForumComment]] = relationship(back_populates="user")
    uploaded_files: Mapped[list[LibraryFile]] = relationship(back_populates="uploader")


class Profile(Base):
    __tablename__ = "profiles"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), primary_key=True
    )
    nickname: Mapped[str | None] = mapped_column(String(100), nullable=True)
    avatar: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="member")

    user: Mapped[User] = relationship(back_populates="profile")


class ColumnApplication(Base):
    __tablename__ = "column_applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[ColumnApplicationStatus] = mapped_column(
        String(20), nullable=False, default=ColumnApplicationStatus.PENDING
    )
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    reviewed_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    user: Mapped[User] = relationship(
        foreign_keys=[user_id], back_populates="column_applications"
    )
    reviewer: Mapped[User | None] = relationship(foreign_keys=[reviewer_id])
    column: Mapped[Column | None] = relationship(
        back_populates="application", uselist=False
    )




class Column(Base):
    __tablename__ = "columns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    application_id: Mapped[int | None] = mapped_column(
        ForeignKey("column_applications.id"), unique=True, nullable=True
    )
    title: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False)
    cover_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ColumnStatus] = mapped_column(
        String(20), nullable=False, default=ColumnStatus.ACTIVE
    )
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    owner: Mapped[User] = relationship(back_populates="owned_columns")
    application: Mapped[ColumnApplication | None] = relationship(back_populates="column")
    posts: Mapped[list[ColumnPost]] = relationship(
        back_populates="column", cascade="all, delete-orphan"
    )


class ColumnPost(Base):
    __tablename__ = "column_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    column_id: Mapped[int] = mapped_column(ForeignKey("columns.id"), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(300), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ColumnPostStatus] = mapped_column(
        String(20), nullable=False, default=ColumnPostStatus.PUBLISHED
    )
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    published_at: Mapped[str | None] = mapped_column(Text, nullable=True)

    column: Mapped[Column] = relationship(back_populates="posts")
    author: Mapped[User] = relationship(back_populates="posts")


class ForumPost(Base):
    __tablename__ = "forum_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    category_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    excerpt: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_featured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    like_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    comment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bookmark_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    author: Mapped[User] = relationship(back_populates="forum_posts")
    comments: Mapped[list[ForumComment]] = relationship(
        back_populates="post", cascade="all, delete-orphan"
    )


class ForumComment(Base):
    __tablename__ = "forum_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    post_id: Mapped[int] = mapped_column(ForeignKey("forum_posts.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    floor_number: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("forum_comments.id"), nullable=True
    )
    like_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    post: Mapped[ForumPost] = relationship(back_populates="comments")
    user: Mapped[User] = relationship(back_populates="forum_comments")
    parent: Mapped[ForumComment | None] = relationship(
        remote_side=[id], back_populates="replies"
    )
    replies: Mapped[list[ForumComment]] = relationship(
        back_populates="parent", cascade="all, delete-orphan"
    )


class LibraryFile(Base):
    __tablename__ = "library_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uploader_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False, default="application/octet-stream")
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    category_id: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    uploader: Mapped[User] = relationship(back_populates="uploaded_files")


class BlogSeries(Base):
    __tablename__ = "blog_series"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cover_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    status: Mapped[BlogSeriesStatus] = mapped_column(
        String(20), nullable=False, default=BlogSeriesStatus.ACTIVE
    )
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    owner: Mapped[User] = relationship(back_populates="blog_series")
    comments: Mapped[list[BlogComment]] = relationship(
        back_populates="series", cascade="all, delete-orphan"
    )
    stars: Mapped[list[BlogStar]] = relationship(
        back_populates="series", cascade="all, delete-orphan"
    )


class BlogStar(Base):
    __tablename__ = "blog_stars"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    series_id: Mapped[int] = mapped_column(ForeignKey("blog_series.id"), primary_key=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    user: Mapped[User] = relationship()
    series: Mapped[BlogSeries] = relationship(back_populates="stars")


class BlogComment(Base):
    __tablename__ = "blog_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    series_id: Mapped[int] = mapped_column(ForeignKey("blog_series.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("blog_comments.id"), nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False, default=now_iso)

    user: Mapped[User] = relationship()
    series: Mapped[BlogSeries] = relationship(back_populates="comments")
    parent: Mapped[BlogComment | None] = relationship(
        remote_side=[id], back_populates="replies"
    )
    replies: Mapped[list[BlogComment]] = relationship(
        back_populates="parent", cascade="all, delete-orphan"
    )