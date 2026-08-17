import pytest
from pydantic import ValidationError

from app.config import Settings
from app.identity.fake import FakeIdentityAdapter


@pytest.mark.unit
def test_production_rejects_fake_identity() -> None:
    with pytest.raises(ValidationError, match="fake identity adapter is forbidden"):
        Settings(environment="production", fake_identity_enabled=True)


@pytest.mark.unit
def test_production_names_missing_keys_without_values() -> None:
    with pytest.raises(ValidationError) as captured:
        Settings(
            environment="production",
            fake_identity_enabled=False,
            session_hash_pepper="not-the-local-default",
        )
    message = str(captured.value)
    assert "auth0_issuer" in message
    assert "auth0_audience" in message
    assert "auth0_client_id" in message
    assert "not-the-local-default" not in message


@pytest.mark.unit
def test_fake_adapter_is_test_only() -> None:
    with pytest.raises(ValidationError):
        production = Settings(environment="production", fake_identity_enabled=True)
        FakeIdentityAdapter(production)


@pytest.mark.unit
def test_production_rejects_short_secrets_and_local_dependencies() -> None:
    common = {
        "environment": "production",
        "fake_identity_enabled": False,
        "auth0_issuer": "https://example.auth0.com/",
        "auth0_audience": "https://api.example.test",
        "auth0_client_id": "public-client-id",
        "rls_context_secret": "r" * 32,
        "database_url": "postgresql+psycopg://runtime:secret@db.example.test/nexora",
        "redis_url": "rediss://redis.example.test/0",
    }
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(**common, session_hash_pepper="short")
    with pytest.raises(ValidationError, match="local fixture"):
        Settings(
            **(
                common
                | {
                    "session_hash_pepper": "p" * 32,
                    "database_url": (
                        "postgresql+psycopg://nexora_runtime:local-runtime-only@"
                        "127.0.0.1:54329/nexora"
                    ),
                }
            )
        )


@pytest.mark.unit
def test_production_cannot_be_enabled_by_configuration_assertion() -> None:
    with pytest.raises(ValidationError, match="OIDC HTTP boundary is implemented"):
        Settings(
            environment="production",
            fake_identity_enabled=False,
            auth0_issuer="https://example.auth0.com/",
            auth0_audience="https://api.example.test",
            auth0_client_id="public-client-id",
            session_hash_pepper="p" * 32,
            rls_context_secret="r" * 32,
            database_url="postgresql+psycopg://runtime:secret@db.example.test/nexora",
            redis_url="rediss://redis.example.test/0",
        )


@pytest.mark.unit
def test_runtime_settings_do_not_retain_migration_credentials() -> None:
    runtime = Settings()
    assert not hasattr(runtime, "migration_database_url")
