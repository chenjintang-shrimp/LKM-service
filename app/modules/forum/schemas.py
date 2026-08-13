import json

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PostCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=120)
    content: str = Field(..., min_length=1)
    category_id: str = Field(..., min_length=1, max_length=50)
    tags: list[str] = Field(default_factory=list)


class PostInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    excerpt: str
    content: str
    author_id: int
    author_name: str = ""
    category_id: str
    tags: list[str]
    is_pinned: bool
    is_featured: bool
    view_count: int
    like_count: int
    comment_count: int
    bookmark_count: int
    created_at: str

    @field_validator("tags", mode="before")
    @classmethod
    def _parse_tags(cls, v):
        if isinstance(v, list):
            return v
        try:
            return json.loads(v)
        except (json.JSONDecodeError, TypeError):
            return []


class CommentCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)
    parent_id: int | None = Field(default=None, ge=1)


class CommentInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    post_id: int
    author_id: int = Field(validation_alias="user_id")
    author_name: str = ""
    content: str
    floor_number: int
    parent_id: int | None = None
    like_count: int
    created_at: str


class PageData[T](BaseModel):
    items: list[T]
    total: int
    page: int
    pages: int
