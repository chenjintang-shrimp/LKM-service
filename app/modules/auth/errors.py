from app.core.err import NS_AUTH, ErrCode, register


class AuthErr(ErrCode):
    ALREADY_REGISTERED = NS_AUTH.err(1)
    INVALID_CREDENTIALS = NS_AUTH.err(2)
    USER_NOT_FOUND = NS_AUTH.err(3)
    ACCOUNT_LOCKED = NS_AUTH.err(4)
    ACCOUNT_LEVEL_INSUFFICIENT = NS_AUTH.err(5)
    VERIFICATION_CODE_INVALID = NS_AUTH.err(6)
    VERIFICATION_CODE_EXPIRED = NS_AUTH.err(7)
    VERIFICATION_CODE_RATE_LIMIT = NS_AUTH.err(8)
    TOKEN_EXPIRED = NS_AUTH.err(9)
    TOKEN_INVALID = NS_AUTH.err(10)
    REFRESH_TOKEN_REVOKED = NS_AUTH.err(11)
    TOTP_NOT_ENABLED = NS_AUTH.err(12)
    TOTP_ALREADY_ENABLED = NS_AUTH.err(13)
    TOTP_SETUP_REQUIRED = NS_AUTH.err(14)
    TOTP_CODE_INVALID = NS_AUTH.err(15)
    RECOVERY_CODE_INVALID = NS_AUTH.err(16)
    RECOVERY_CODE_USED = NS_AUTH.err(17)
    OAUTH_CANCELED = NS_AUTH.err(18)
    OAUTH_PROVIDER_ERROR = NS_AUTH.err(19)
    OAUTH_EMAIL_TAKEN = NS_AUTH.err(20)
    PASSKEY_REGISTRATION_FAILED = NS_AUTH.err(21)
    PASSKEY_VERIFICATION_FAILED = NS_AUTH.err(22)
    RECOVERY_NOT_SUPPORTED = NS_AUTH.err(23)
    RECOVERY_METHOD_UNAVAILABLE = NS_AUTH.err(24)


register(
    {
        AuthErr.ALREADY_REGISTERED:           (400, "Username or email already registered"),
        AuthErr.INVALID_CREDENTIALS:          (401, "Invalid username or password"),
        AuthErr.USER_NOT_FOUND:               (401, "User not found"),
        AuthErr.ACCOUNT_LOCKED:               (423, "Account is locked"),
        AuthErr.ACCOUNT_LEVEL_INSUFFICIENT:   (403, "Account level insufficient"),
        AuthErr.VERIFICATION_CODE_INVALID:    (400, "Verification code invalid"),
        AuthErr.VERIFICATION_CODE_EXPIRED:    (400, "Verification code expired"),
        AuthErr.VERIFICATION_CODE_RATE_LIMIT: (429, "Verification code rate limit exceeded"),
        AuthErr.TOKEN_EXPIRED:                (401, "Token expired"),
        AuthErr.TOKEN_INVALID:                (401, "Token invalid"),
        AuthErr.REFRESH_TOKEN_REVOKED:        (401, "Refresh token revoked"),
        AuthErr.TOTP_NOT_ENABLED:             (400, "TOTP not enabled"),
        AuthErr.TOTP_ALREADY_ENABLED:         (400, "TOTP already enabled"),
        AuthErr.TOTP_SETUP_REQUIRED:          (400, "TOTP setup required"),
        AuthErr.TOTP_CODE_INVALID:            (400, "TOTP code invalid"),
        AuthErr.RECOVERY_CODE_INVALID:        (400, "Recovery code invalid"),
        AuthErr.RECOVERY_CODE_USED:           (400, "Recovery code already used"),
        AuthErr.OAUTH_CANCELED:               (400, "OAuth login canceled"),
        AuthErr.OAUTH_PROVIDER_ERROR:         (502, "OAuth provider error"),
        AuthErr.OAUTH_EMAIL_TAKEN:            (409, "OAuth email already taken"),
        AuthErr.PASSKEY_REGISTRATION_FAILED:  (400, "Passkey registration failed"),
        AuthErr.PASSKEY_VERIFICATION_FAILED:  (400, "Passkey verification failed"),
        AuthErr.RECOVERY_NOT_SUPPORTED:       (400, "Recovery not supported"),
        AuthErr.RECOVERY_METHOD_UNAVAILABLE:  (400, "Recovery method unavailable"),
    }
)
