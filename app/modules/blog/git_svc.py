import os
import shutil
import subprocess

from app.core.config import settings
from app.core.err import BizError, CommonErr
from app.modules.blog.errors import BlogErr


def _repo_path(repo_name: str) -> str:
    base = os.path.abspath(settings.blog_repo_dir)
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"{repo_name}.git")


def _run_git(repo_name: str, *args: str) -> str:
    path = _repo_path(repo_name)
    cmd = ["git", "--git-dir", path] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            check=True,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        detail = e.stderr.decode("utf-8", errors="replace").strip() or str(e)
        raise BizError(BlogErr.GIT_ERROR, detail)
    except FileNotFoundError:
        raise BizError(BlogErr.GIT_ERROR, "git executable not found")


def init_bare_repo(repo_name: str) -> str:
    path = _repo_path(repo_name)
    if os.path.exists(path):
        raise BizError(BlogErr.GIT_ERROR, f"Repository '{repo_name}' already exists")
    try:
        subprocess.run(
            ["git", "init", "--bare", path],
            capture_output=True,
            timeout=10,
            check=True,
        )
        subprocess.run(
            ["git", "--git-dir", path, "config", "http.receivepack", "true"],
            capture_output=True,
            timeout=10,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        detail = e.stderr.decode("utf-8", errors="replace").strip() or str(e)
        raise BizError(BlogErr.GIT_ERROR, detail)
    return path


def delete_repo(repo_name: str) -> None:
    path = _repo_path(repo_name)
    if os.path.exists(path):
        shutil.rmtree(path)


def ensure_repo_has_commits(repo_name: str) -> bool:
    try:
        _run_git(repo_name, "rev-parse", "HEAD")
        return True
    except BizError:
        return False


def get_file_tree(repo_name: str) -> list[dict]:
    out = _run_git(repo_name, "ls-tree", "-r", "--name-only", "HEAD")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines:
        return []

    root: dict[str, dict | str] = {}
    for line in lines:
        parts = line.split("/")
        cur = root
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                cur[part] = "__BLOB__"
            else:
                if part not in cur:
                    cur[part] = {}
                child = cur[part]
                if child == "__BLOB__":
                    cur[part] = {"__self__": "__BLOB__"}
                    child = cur[part]
                cur = child

    def _to_list(node: dict | str) -> list[dict]:
        if node == "__BLOB__":
            return []
        result = []
        for name, val in sorted(node.items()):
            if name == "__self__":
                continue
            if val == "__BLOB__":
                result.append({"name": name, "type": "blob"})
            else:
                result.append({"name": name, "type": "tree", "children": _to_list(val)})
        return result

    return _to_list(root)


def read_file(repo_name: str, filepath: str) -> str:
    filepath = filepath.lstrip("/")
    if ".." in filepath.split("/"):
        raise BizError(CommonErr.INVALID_INPUT, "Invalid file path")
    return _run_git(repo_name, "show", f"HEAD:{filepath}")


def get_readme(repo_name: str) -> str | None:
    try:
        return read_file(repo_name, "README.md")
    except BizError:
        return None
