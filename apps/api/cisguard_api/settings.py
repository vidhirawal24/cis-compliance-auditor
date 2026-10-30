from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[1] / ".env",
        env_file_encoding="utf-8", extra="ignore",
    )
    environment: str = "development"
    enable_synthetic_fixtures: bool = False
    database_url: SecretStr = SecretStr("postgresql+psycopg://localhost/cisguard")
    migration_database_url: SecretStr | None = None
    database_role: str = "cisguard_api"
    database_sslmode: str = "require"
    supabase_url: str = "https://unconfigured.supabase.co"
    supabase_anon_key: SecretStr = SecretStr("")
    # Optional, deliberately not required by this foundation and never returned to clients.
    supabase_service_role_key: SecretStr = SecretStr("")
    redis_url: SecretStr = SecretStr("redis://127.0.0.1:6380/0")
    celery_broker_url: SecretStr = SecretStr("redis://127.0.0.1:6380/0")
    celery_result_backend: SecretStr = SecretStr("redis://127.0.0.1:6380/1")
    cursor_signing_key: SecretStr = SecretStr("")
    device_engine_url: str = "http://mock-device-engine:8090"
    openbao_addr: str = "http://127.0.0.1:8201"
    openbao_role_id: SecretStr = SecretStr("")
    openbao_secret_id: SecretStr = SecretStr("")
    openbao_kv_mount: str = "secret"

    @field_validator("database_role")
    @classmethod
    def role_is_fixed(cls, value):
        if value != "cisguard_api":
            raise ValueError("Runtime must use the restricted cisguard_api role")
        return value

    @field_validator("supabase_url")
    @classmethod
    def fixed_auth_origin(cls, value):
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("Supabase Auth must use a configured HTTPS origin")
        if parsed.path not in ("", "/"):
            raise ValueError("Supabase URL must not contain a path")
        return value.rstrip("/")


@lru_cache
def get_settings():
    return Settings()
