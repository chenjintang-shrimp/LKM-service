import json
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.err import BizError
from app.db.models import LibraryFile, User
from app.db.repo import get_or_raise
from app.modules.files.errors import FileErr
from app.modules.files.models import FILES_TABLE_PLAN
from app.modules.files.schemas import FileCreate, FileInfo, PageData


def get_files_plan() -> dict:
    return {
        "status": "implemented_minimal",
        "tables": FILES_TABLE_PLAN,
        "next_steps": [
            "Add review approval workflow",
            "Add duplicate / plagiarism detection",
            "Add file serving with presigned URL",
        ],
    }


def _uploader_name(user: User) -> str:
    if user.profile and user.profile.nickname:
        return user.profile.nickname
    return user.username


def _file_to_schema(f: LibraryFile, uploader_name: str) -> FileInfo:
    return FileInfo.model_validate(f).model_copy(update={"uploader_name": uploader_name})


def _uploader_map(db: Session, user_ids: list[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    users = db.query(User).filter(User.id.in_(set(user_ids))).all()
    return {u.id: _uploader_name(u) for u in users}


def _store_dir() -> Path:
    path = Path(settings.files_store_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _make_stored_name(original_name: str) -> str:
    suffix = Path(original_name).suffix[:32]
    return f"{uuid.uuid4().hex}{suffix}"


def list_files(
    db: Session,
    page: int = 1,
    limit: int = 20,
    category_id: str | None = None,
    status: str | None = None,
    sort: str = "newest",
) -> PageData[FileInfo]:
    query = db.query(LibraryFile)
    if category_id:
        query = query.filter(LibraryFile.category_id == category_id)
    if status:
        query = query.filter(LibraryFile.status == status)

    total = query.count()
    order = LibraryFile.download_count.desc() if sort == "downloads" else LibraryFile.id.desc()
    files = (
        query.order_by(order)
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    names = _uploader_map(db, [f.uploader_id for f in files])
    items = [_file_to_schema(f, names.get(f.uploader_id, "")) for f in files]
    return PageData(items=items, total=total, page=page, pages=(total + limit - 1) // limit)


def get_file(db: Session, file_id: int, bump_view: bool = False) -> FileInfo:
    f = get_or_raise(db, LibraryFile, FileErr.NOT_FOUND, LibraryFile.id == file_id)

    if bump_view:
        f.view_count += 1
        db.flush()

    names = _uploader_map(db, [f.uploader_id])
    return _file_to_schema(f, names.get(f.uploader_id, ""))


_CHUNK = 1024 * 1024  # 分块读写，避免整文件载入内存


def create_file(
    db: Session,
    uploader_id: int,
    info: FileCreate,
    stream,
    max_bytes: int | None = None,
) -> FileInfo:
    """把上传流分块落盘并登记元数据。

    ``stream`` 需提供 ``read(n)``。累计超过 ``max_bytes``（默认取配置值）
    立即中止并抛 ``FILE_TOO_LARGE``，不留下磁盘文件。
    """
    limit = max_bytes or settings.max_upload_bytes
    stored_name = _make_stored_name(info.original_name)
    dest = None

    total = 0
    try:
        dest = _store_dir() / stored_name
        with dest.open("wb") as out:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise BizError(
                        FileErr.TOO_LARGE,
                        detail=f"Upload exceeds {limit} byte limit",
                    )
                out.write(chunk)
    except BizError:
        if dest is not None:
            dest.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if dest is not None:
            dest.unlink(missing_ok=True)
        raise BizError(FileErr.STORE_ERROR, detail=f"Failed to store file: {exc}") from exc

    try:
        f = LibraryFile(
            uploader_id=uploader_id,
            original_name=info.original_name,
            stored_name=stored_name,
            mime_type=info.mime_type,
            size=total,
            category_id=info.category_id,
            description=info.description,
            tags=json.dumps(info.tags, ensure_ascii=False),
        )
        db.add(f)
        db.flush()
        db.refresh(f)
    except Exception:
        dest.unlink(missing_ok=True)
        raise

    names = _uploader_map(db, [f.uploader_id])
    return _file_to_schema(f, names.get(f.uploader_id, ""))


def bump_download(db: Session, file_id: int) -> int:
    f = get_or_raise(db, LibraryFile, FileErr.NOT_FOUND, LibraryFile.id == file_id)
    f.download_count += 1
    db.flush()
    return f.download_count
