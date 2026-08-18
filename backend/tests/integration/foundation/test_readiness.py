import pytest

from app.config import Settings
from app.db.health import DependencyReadiness


@pytest.mark.integration
def test_real_postgres_and_redis_readiness_adapters() -> None:
    settings = Settings(environment="test")
    assert DependencyReadiness.from_settings(settings).is_ready()
    unavailable = Settings(environment="test", redis_url="redis://127.0.0.1:63998/0")
    assert not DependencyReadiness.from_settings(unavailable).is_ready()
