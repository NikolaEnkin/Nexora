import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


class FixedReadiness:
    def __init__(self, ready: bool) -> None:
        self.ready = ready

    def is_ready(self) -> bool:
        return self.ready


@pytest.mark.unit
def test_liveness_is_exact_and_dependency_free() -> None:
    client = TestClient(create_app(Settings(environment="test"), FixedReadiness(False)))
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.unit
def test_readiness_is_safe_when_dependency_is_unavailable() -> None:
    client = TestClient(create_app(Settings(environment="test"), FixedReadiness(False)))
    response = client.get(
        "/health/ready", headers={"X-Correlation-ID": "90000000-0000-0000-0000-000000000001"}
    )
    assert response.status_code == 503
    assert response.json() == {
        "version": "1",
        "code": "DEPENDENCY_UNAVAILABLE",
        "message": "A required dependency is unavailable.",
        "correlation_id": "90000000-0000-0000-0000-000000000001",
        "retryable": True,
        "details": {},
    }
    assert "postgres" not in response.text.lower()
    assert "redis" not in response.text.lower()


@pytest.mark.unit
def test_readiness_success_is_exact() -> None:
    client = TestClient(create_app(Settings(environment="test"), FixedReadiness(True)))
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
