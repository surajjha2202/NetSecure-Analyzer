from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "NetSecure Analyzer"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"

    DATABASE_URL: str = (
        "postgresql+psycopg://netsecure:netsecure@localhost:5432/netsecure"
    )

    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "CHANGE_THIS_IN_PRODUCTION"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()