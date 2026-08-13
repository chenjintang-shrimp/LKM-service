from app.core.err import BizError
from app.modules.common import ListData
from app.modules.members.errors import MemberErr
from app.modules.members.models import ALL_TYPES, MEMBER_LISTS, SUB_GROUP_MAPS
from app.modules.members.schemas import Member


def get_members(type: str, group: str | None = None) -> ListData[Member]:
    """根据 type 和可选的 group 查询成员列表。"""
    # 1) 直接成员列表
    if type in MEMBER_LISTS:
        return ListData(items=MEMBER_LISTS[type])

    # 2) 子组映射
    sg_map = SUB_GROUP_MAPS.get(type)
    if sg_map is not None:
        if group is None:
            all_members: list[Member] = []
            for sg in sg_map.values():
                all_members.extend(sg.members)
            return ListData(items=all_members)
        sg = sg_map.get(group)
        if sg is None:
            raise BizError(
                MemberErr.GROUP_NOT_FOUND,
                detail=f"未知子组: {group}（{type} 下可用：{', '.join(sg_map.keys())}）",
            )
        return ListData(items=sg.members)

    # 3) 未知 type
    raise BizError(
        MemberErr.GROUP_NOT_FOUND,
        detail=f"未知数据组: {type}，可用：{', '.join(ALL_TYPES)}",
    )
