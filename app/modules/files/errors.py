from app.core.err import NS_FILES, ErrCode, register


class FileErr(ErrCode):
    NOT_FOUND = NS_FILES.err(1)
    STORE_ERROR = NS_FILES.err(2)
    TOO_LARGE = NS_FILES.err(3)


register(
    {
        FileErr.NOT_FOUND:    (404, "File not found"),
        FileErr.STORE_ERROR:  (500, "File storage operation failed"),
        FileErr.TOO_LARGE:    (413, "File exceeds upload size limit"),
    }
)
