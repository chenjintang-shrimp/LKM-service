from app.core.err import NS_FORUM, ErrCode, register


class ForumErr(ErrCode):
    POST_NOT_FOUND = NS_FORUM.err(1)
    COMMENT_NOT_FOUND = NS_FORUM.err(2)


register(
    {
        ForumErr.POST_NOT_FOUND:    (404, "Forum post not found"),
        ForumErr.COMMENT_NOT_FOUND: (404, "Forum comment not found"),
    }
)
