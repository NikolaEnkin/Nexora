from functools import lru_cache
from typing import Literal, Self

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]

# Base64 of b"local-checkpoint-key-change-me00" (exactly 32 bytes). Local/fake only.
#
# The production guard for this value lives in `app.agent.crypto`, not here, for two
# reasons. It fails closed wherever a cipher is constructed rather than only at
# settings load, and adding another required production field to this validator would
# change which error the Phase-01 production-boundary test observes.
LOCAL_CHECKPOINT_KEY = "bG9jYWwtY2hlY2twb2ludC1rZXktY2hhbmdlLW1lMDA="
CHECKPOINT_KEY_BYTES = 32


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
    # Same-origin check for state-changing requests (ADR-001). The production
    # guard lives in `app.api.auth`, not here: adding another required field to
    # this validator would change which error the Phase-01 production-boundary
    # test observes — the defect recorded as Phase-02 finding R-04.
    allowed_origin: str = "http://127.0.0.1:8091"
    session_hash_pepper: SecretStr = SecretStr("local-session-pepper-change-me")
    rls_context_secret: SecretStr = SecretStr("local-rls-context-secret-change-me")
    # Base64 of exactly 32 bytes. Reached only through CheckpointCipherPort so the
    # key source can be replaced by a managed service without touching call sites.
    checkpoint_encryption_key: SecretStr = SecretStr(LOCAL_CHECKPOINT_KEY)
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
