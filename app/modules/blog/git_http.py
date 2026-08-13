import base64
import os
import subprocess

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.config import settings
from app.db.models import User
from app.db.session import new_session
from app.modules.auth.security import verifypwd

git_router = APIRouter(prefix="/blog/git", tags=["blog-git"])


@git_router.api_route("/{repo_name}.git/{rest:path}", methods=["GET", "POST"])
async def git_http_backend(repo_name: str, rest: str, request: Request):
    root = os.path.abspath(settings.blog_repo_dir)
    repo_path = os.path.join(root, f"{repo_name}.git")

    if not os.path.isdir(repo_path):
        raise HTTPException(status_code=404, detail="Repository not found")

    env = os.environ.copy()
    env["GIT_PROJECT_ROOT"] = root
    env["GIT_HTTP_EXPORT_ALL"] = "1"
    env["PATH_INFO"] = f"/{repo_name}.git/{rest}"
    env["REQUEST_METHOD"] = request.method
    env["CONTENT_TYPE"] = request.headers.get("Content-Type", "")
    env["CONTENT_LENGTH"] = request.headers.get("Content-Length", "0")
    qs = str(request.url.query) if request.url.query else ""
    env["QUERY_STRING"] = qs

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
            db = new_session()
            try:
                user = db.query(User).filter(User.username == username).first()
                if user and verifypwd(password, user.hashed_password):
                    env["REMOTE_USER"] = username
            finally:
                db.close()
        except Exception:  # noqa: BLE001  认证解析失败时静默降级为未认证请求
            pass

    body = await request.body()

    try:
        proc = subprocess.Popen(
            ["git", "http-backend"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, _ = proc.communicate(input=body, timeout=120)
    except subprocess.TimeoutExpired as e:
        proc.kill()
        raise HTTPException(status_code=504, detail="Git operation timed out") from e
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail="git executable not found") from e

    header_end = stdout.find(b"\r\n\r\n")
    if header_end != -1:
        header_section = stdout[:header_end].decode("utf-8", errors="replace")
        response_body = stdout[header_end + 4:]
    else:
        header_section = ""
        response_body = stdout

    status_code = 200
    content_type = "application/octet-stream"
    response_headers: dict[str, str] = {}

    for line in header_section.split("\r\n"):
        if line.lower().startswith("status:"):
            try:
                status_code = int(line.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
        elif ":" in line:
            key, value = line.split(":", 1)
            response_headers[key.strip()] = value.strip()

    content_type = response_headers.pop("Content-Type", content_type)

    return Response(
        content=response_body,
        status_code=status_code,
        media_type=content_type,
        headers=response_headers,
    )
