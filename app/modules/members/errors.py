from app.core.err import NS_MEMBERS, ErrCode, register


class MemberErr(ErrCode):
    GROUP_NOT_FOUND = NS_MEMBERS.err(1)


register(
    {
        MemberErr.GROUP_NOT_FOUND: (404, "Member group not found"),
    }
)
