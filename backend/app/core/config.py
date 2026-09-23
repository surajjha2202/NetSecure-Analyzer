from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "NetSecure Analyzer"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    DATABASE_URL: str = (
        "postgresql+psycopg://netsecure:netsecure@localhost:5432/netsecure"
    )

    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    PASSWORD_RESET_EXPIRE_MINUTES: int = 15
    FRONTEND_BASE_URL: str = "http://localhost:5173"
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
