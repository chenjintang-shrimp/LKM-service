from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "LKM_"}

    app_name: str = "LKM-API"
    app_version: str = "0.0.1"
    api_prefix: str = "/api/v1"

    db_driver: str = "sqlite"
    # 生产环境改为：db_driver: str = "postgresql" 或编写.env
    db_path: str = "lkm.db"
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "lkm"
    db_user: str = "postgres"
    db_password: str = ""

    # JWT 签名密钥 — 所有非测试环境必须覆盖此值
    jwt_secret: str = "change-me-to-a-random-secret-thats-at-least-32-bytes-long"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # TOTP / 敏感数据加密密钥 — 必须与 jwt_secret 分开设置
    totp_encryption_key: str = "change-me-totp-encryption-key-at-least-32-bytes"

    # 验证码 HMAC 盐值 — 必须与 totp_encryption_key 和 jwt_secret 分开设置
    verification_code_pepper: str = "change-me-verification-code-pepper-at-least-32-bytes"

    # OAuth (GitHub)
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:8000/api/v1/auth/oauth/github/callback"
    frontend_callback: str = "http://localhost:5173/login/success"

    # Passkey (WebAuthn)
    rp_id: str = "localhost"
    rp_name: str = "LKM Service"
    origin: str = "http://localhost:5173"

    blog_repo_dir: str = "blog_repos"
    files_store_dir: str = "files_store"
    max_upload_bytes: int = 100 * 1024 * 1024  # 单文件上传上限 100MB

    @property
    def database_url(self) -> str:
        if self.db_driver == "postgresql":
            return (
                f"postgresql+psycopg2://{self.db_user}:{self.db_password}"
                f"@{self.db_host}:{self.db_port}/{self.db_name}"
            )
        return f"sqlite:///{self.db_path}"


settings = Settings()
