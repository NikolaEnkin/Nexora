from functools import lru_cache
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="NEXORA_",
        extra="ignore",
        frozen=True,
    )

    environment: Environment = "development"
    database_url: str = (
        "postgresql+psycopg://nexora_runtime:local-runtime-only@127.0.0.1:54329/nexora"
    )
    redis_url: str = "redis://127.0.0.1:63799/0"
    session_hash_pepper: SecretStr = SecretStr("local-session-pepper-change-me")
    rls_context_secret: SecretStr = SecretStr("local-rls-context-secret-change-me")
    fake_identity_enabled: bool = True
    auth0_issuer: AnyHttpUrl | None = None
    auth0_audience: str | None = None
    auth0_client_id: str | None = None
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    @model_validator(mode="after")
    def enforce_environment_boundary(self) -> Self:
        if self.environment == "production":
            if self.fake_identity_enabled:
                raise ValueError("fake identity adapter is forbidden in production")
            missing = [
                name
                for name, value in (
                    ("auth0_issuer", self.auth0_issuer),
                    ("auth0_audience", self.auth0_audience),
                    ("auth0_client_id", self.auth0_client_id),
                )
                if value is None
            ]
            if missing:
                raise ValueError(
                    f"production identity configuration is incomplete: {', '.join(missing)}"
                )
            if self.session_hash_pepper.get_secret_value() == "local-session-pepper-change-me":
                raise ValueError("production session hash pepper must be replaced")
            if len(self.session_hash_pepper.get_secret_value()) < 32:
                raise ValueError(
                    "production session hash pepper must contain at least 32 characters"
                )
            if self.rls_context_secret.get_secret_value() == "local-rls-context-secret-change-me":
                raise ValueError("production RLS context secret must be replaced")
            if len(self.rls_context_secret.get_secret_value()) < 32:
                raise ValueError(
                    "production RLS context secret must contain at least 32 characters"
                )
            local_markers = ("127.0.0.1", "localhost", "local-runtime-only", "local-migrator-only")
            if any(marker in self.database_url for marker in local_markers):
                raise ValueError(
                    "production database configuration cannot use local fixture values"
                )
            if "127.0.0.1" in self.redis_url or "localhost" in self.redis_url:
                raise ValueError("production Redis configuration cannot use a loopback fixture")
            raise ValueError(
                "production startup is disabled until the OIDC HTTP boundary is implemented"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


class MigrationSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="NEXORA_",
        extra="ignore",
        frozen=True,
    )

    migration_database_url: str = (
        "postgresql+psycopg://nexora_migrator:local-migrator-only@127.0.0.1:54329/nexora"
    )
    rls_context_secret: SecretStr = SecretStr("local-rls-context-secret-change-me")


@lru_cache(maxsize=1)
def get_migration_settings() -> MigrationSettings:
    return MigrationSettings()
