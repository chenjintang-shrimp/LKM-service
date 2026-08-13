from fastapi import APIRouter, Query

from app.core.err import respond
from app.modules.common import ApiResp, ListData
from app.modules.members.models import ALL_TYPES
from app.modules.members.schemas import Member
from app.modules.members.service import get_members
from typing import Annotated

router = APIRouter(prefix="/members", tags=["members"])


@router.get("", response_model=ApiResp[ListData[Member]])
@respond
def get_member_list(
    type: Annotated[str, Query(description=f"数据组标识，可选：{', '.join(ALL_TYPES)}")],
    group: Annotated[str | None, Query(description="子组标识，仅 subGroupMaps 需要")] = None,
):
    return get_members(type, group).model_dump()
