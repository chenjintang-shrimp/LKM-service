import functools
import inspect
from enum import IntEnum

from fastapi.exceptions import RequestValidationError


class Namespace:
    """Error-code namespace: encodes ns_id<<16 | local so modules stay collision-free."""

    def __init__(self, ns_id: int, prefix: str):
        self.ns_id = ns_id
        self.prefix = prefix

    def err(self, local: int) -> int:
        return (self.ns_id << 16) | local


class ErrCode(IntEnum):
    """Base type for every module error-code enum."""


NS_COMMON  = Namespace(0, "common")
NS_AUTH    = Namespace(1, "auth")
NS_COLUMNS = Namespace(2, "columns")
NS_BLOG    = Namespace(3, "blog")
NS_FORUM   = Namespace(4, "forum")
NS_FILES   = Namespace(5, "files")
NS_MEMBERS = Namespace(6, "members")


class CommonErr(ErrCode):
    OK = 0
    INVALID_INPUT = NS_COMMON.err(1)
    FORBIDDEN = NS_COMMON.err(2)
    INTERNAL_ERROR = NS_COMMON.err(3)


ERRTABLE: dict[ErrCode, tuple[int, str]] = {}


def register(errors: dict[ErrCode, tuple[int, str]]) -> None:
    for code, info in errors.items():
        if code in ERRTABLE:
            raise ValueError(f"Duplicate error code: {code!r}")
        ERRTABLE[code] = info


register(
    {
        CommonErr.OK:             (200, "OK"),
        CommonErr.INVALID_INPUT:  (422, "Invalid input"),
        CommonErr.FORBIDDEN:      (403, "Forbidden"),
        CommonErr.INTERNAL_ERROR: (500, "Internal server error"),
    }
)


class BizError(Exception):
    def __init__(self, errcode: ErrCode, detail: str | None = None):
        self.errcode = errcode
        self.detail = detail or ERRTABLE[errcode][1]


def map_err(exc: Exception) -> tuple[int, ErrCode, str]:
    if isinstance(exc, BizError):
        status, _ = ERRTABLE[exc.errcode]
        return status, exc.errcode, exc.detail

    if isinstance(exc, RequestValidationError):
        msgs = []
        for err in exc.errors():
            field = ".".join(str(loc) for loc in err["loc"] if loc != "body")
            msgs.append(f"{field}: {err['msg']}")
        detail = "; ".join(msgs)
        status, _ = ERRTABLE[CommonErr.INVALID_INPUT]
        return status, CommonErr.INVALID_INPUT, detail

    status, msg = ERRTABLE[CommonErr.INTERNAL_ERROR]
    return status, CommonErr.INTERNAL_ERROR, msg


def resp_json(errcode: ErrCode, *, data=None, detail=None):
    status, msg = ERRTABLE[errcode]
    from fastapi.responses import JSONResponse

    from app.modules.common import ApiResp

    return JSONResponse(
        status_code=status,
        content=ApiResp(code=errcode, msg=detail or msg, data=data).model_dump(),
    )


def respond(func):
    """装饰器：将返回值通过 ERRTABLE 包装。 """

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            return _wrap_result(result)

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return _wrap_result(result)

    return sync_wrapper


def _wrap_result(result):
    if isinstance(result, tuple) and isinstance(result[0], ErrCode):
        errcode, payload = result
        if isinstance(payload, str):
            return resp_json(errcode, detail=payload)
        return resp_json(errcode, data=payload)
    return resp_json(CommonErr.OK, data=result)
