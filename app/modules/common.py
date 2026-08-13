from pydantic import BaseModel


class ApiResp[T](BaseModel):
    code: int
    msg: str
    data: T | None = None


class ListData[T](BaseModel):
    items: list[T]

class ModuleStatus(BaseModel):
    module: str
    status: str = "planned"
    responsibility: str
    next_steps: list[str]
