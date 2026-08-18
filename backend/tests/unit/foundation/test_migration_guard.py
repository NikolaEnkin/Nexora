import pytest
from scripts.codex.migration_check import _guard_local_database


@pytest.mark.unit
def test_destructive_migration_guard_requires_exact_fixture_and_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_url = "postgresql+psycopg://nexora_migrator:local@127.0.0.1:54329/nexora"
    monkeypatch.delenv("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK", raising=False)
    monkeypatch.setenv("NEXORA_ENVIRONMENT", "test")
    with pytest.raises(RuntimeError, match="explicit opt-in"):
        _guard_local_database(fixture_url)
    monkeypatch.setenv("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK", "true")
    with pytest.raises(RuntimeError, match="non-fixture"):
        _guard_local_database("postgresql+psycopg://nexora_migrator:local@127.0.0.1:5432/nexora")
    _guard_local_database(fixture_url)
