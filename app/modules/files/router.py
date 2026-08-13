from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from sqlalchemy.orm import Session

from app.core.err import respond
from app.db.session import get_session
from app.modules.auth.deps import CurrentUser, get_current_user
from app.modules.common import ApiResp, ModuleStatus
from app.modules.files.schemas import FileCreate, FileInfo, PageData
from app.modules.files.service import (
    bump_download,
    get_file,
    get_files_plan,
    list_files,
)
from app.modules.files.service import (
    create_file as create_file_service,
)

router = APIRouter(prefix="/files", tags=["files"])


@router.get("/status")
def files_status() -> ModuleStatus:
    return ModuleStatus(
        module="files",
        status="implemented_minimal",
        responsibility="Manage shared academic files and downloads.",
        next_steps=get_files_plan()["next_steps"],
    )


@router.get("", response_model=ApiResp[PageData[FileInfo]])
@respond
def get_files(
    db: Annotated[Session, Depends(get_session)],
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    category_id: Annotated[str | None, Query(max_length=50)] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
    sort: Annotated[str, Query()] = "newest",
):
    return list_files(db, page=page, limit=limit, category_id=category_id, status=status, sort=sort)


@router.post("", response_model=ApiResp[FileInfo])
@respond
def upload_file(
    file: Annotated[UploadFile, File()],
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
    category_id: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    tags: Annotated[str, Form()] = "[]",
):
    import json

    try:
        tags_list = json.loads(tags) if tags else []
    except json.JSONDecodeError:
        tags_list = []

    info = FileCreate(
        original_name=file.filename or "untitled",
        mime_type=file.content_type or "application/octet-stream",
        category_id=category_id,
        description=description,
        tags=tags_list,
    )
    return create_file_service(db, cur.id, info, file.file)


@router.get("/{file_id}", response_model=ApiResp[FileInfo])
@respond
def get_file_detail(file_id: int, db: Annotated[Session, Depends(get_session)]):
    return get_file(db, file_id, bump_view=True)


@router.post("/{file_id}/download", response_model=ApiResp[dict])
@respond
def download_file(
    file_id: int,
    cur: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_session)],
):
    return {"download_count": bump_download(db, file_id)}
