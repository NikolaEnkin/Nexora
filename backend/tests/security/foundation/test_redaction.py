import json
from pathlib import Path

import pytest
import structlog
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    FIXED_NOW,
    TENANT_A,
    migration_engine,
    owner_actor,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import set_request_context
from app.errors import ApplicationError
from app.events import FoundationMutationService
from app.identity.session_store import SessionCredentials
from app.logging import REDACTED, configure_logging, redact_data
from app.main import AlwaysReady, create_app


@pytest.mark.security
def test_secret_never_reaches_log_audit_or_error(capsys: pytest.CaptureFixture[str]) -> None:
    fixture = json.loads(Path("backend/tests/fixtures/security/fake-secret.json").read_text())
    secret = fixture["secret"]
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    service = FoundationMutationService(sessions)
    service.execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="redaction-key-001",
        arguments={"note": f"never expose {secret}", "api_token": secret},
        now=FIXED_NOW,
        secret_values=(secret,),
    )
    simulated_log = redact_data(
        {"event": f"invalid value {secret}", "authorization": secret}, (secret,)
    )
    assert secret not in json.dumps(simulated_log)
    assert REDACTED in json.dumps(simulated_log)
    configure_logging(secret_values=(secret,))
    structlog.get_logger("redaction-test").info(
        f"invalid value {secret}", ordinary_value=f"prefix-{secret}", api_token=secret
    )
    credentials = SessionCredentials(
        raw_session_token=f"dynamic-session-{secret}",
        csrf_token=f"dynamic-csrf-{secret}",
        idle_expires_at=FIXED_NOW,
        absolute_expires_at=FIXED_NOW,
    )
    structlog.get_logger("redaction-test").info("dynamic_credentials", credentials=credentials)
    emitted = capsys.readouterr()
    assert secret not in emitted.out + emitted.err
    assert REDACTED in emitted.out + emitted.err
    error = ApplicationError("INPUT_INVALID", "Input is invalid.", 422, details={"input": secret})
    assert secret not in str(error)
    app = create_app(readiness=AlwaysReady())

    @app.get("/test-invalid")
    async def invalid() -> None:
        raise error

    response = TestClient(app).get("/test-invalid")
    assert response.status_code == 422
    assert secret not in response.text
    assert response.json()["details"] == {}

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        metadata = session.execute(text("SELECT metadata FROM audit_events")).scalar_one()
        assert secret not in json.dumps(metadata)
        assert set(metadata) == {
            "operation",
            "request_hash",
            "event_id",
            "idempotency_record_id",
            "outcome",
        }
