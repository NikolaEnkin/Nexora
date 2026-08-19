"""P02-007 — a secret in a message is protected in every Phase-02 sink.

The message content itself is legitimately sensitive, so the assertions are
asymmetric on purpose: the checkpoint must hold it as *ciphertext* (the runtime
needs it back), while traces, logs, errors and evidence must not hold it at all.

The authorized adapter is also asserted to still restore the state, so "protected"
is not accidentally achieved by losing the data.
"""

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import structlog
from backend.tests.integration.agent.support import (
    FIXED_NOW,
    actor_for,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.agent.checkpointer import agent_state_from_checkpoint
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.model import DeterministicModelAdapter
from app.agent.wiring import build_agent_composition
from app.config import Settings
from app.contracts import ActorContext
from app.logging import REDACTED, configure_logging
from app.main import create_app
from app.observability.ports import ALLOWED_SPAN_FIELDS, FORBIDDEN_SPAN_FIELDS

FIXTURE = Path("backend/tests/fixtures/agent/agent-secret-message.json")
EVIDENCE_DIR = Path("artifacts/validation/phase-02")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


class _AlwaysReady:
    def is_ready(self) -> bool:
        return True


def _app(composition: Any, actor: ActorContext) -> FastAPI:
    app = create_app(Settings(environment="test"), readiness=_AlwaysReady(), agent=composition)

    @app.middleware("http")
    async def inject_actor(request: Request, call_next: Any) -> Any:
        request.state.actor = actor
        return await call_next(request)

    return app


@pytest.mark.security
def test_secret_is_protected_in_checkpoint_trace_and_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _fixture()
    secret = fixture["secret"]
    message = fixture["message_template"].format(secret=secret)

    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)

    settings = Settings(environment="test")
    configure_logging(
        settings.log_level,
        secret_values=(
            settings.session_hash_pepper.get_secret_value(),
            settings.rls_context_secret.get_secret_value(),
            settings.checkpoint_encryption_key.get_secret_value(),
            secret,
        ),
    )
    composition = build_agent_composition(
        settings,
        clock=lambda: FIXED_NOW,
        model=DeterministicModelAdapter(settings),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        sessions=runtime_sessions(),
    )
    composition.trace.secret_values = (*composition.trace.secret_values, secret)

    actor = actor_for(UUID(fixture["tenant_id"]), UUID(fixture["actor_id"]))

    with TestClient(_app(composition, actor)) as client:
        submitted = client.post(
            "/chat",
            json={"message": message, "client_request_id": fixture["client_request_id"]},
        )
        assert submitted.status_code == 202
        composition.scheduler.wait()
        operation_id = UUID(submitted.json()["operation_id"])
        stream = client.get(submitted.json()["stream_url"])
        # A guessed id must not leak either.
        missing = client.get("/chat/ffffffff-ffff-4fff-8fff-ffffffffffff/events")

    operation = composition.operations.load(actor=actor, operation_id=operation_id)

    # --- 1. checkpoint: ciphertext at rest, in every payload column ---
    with admin.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        checkpoint_rows = connection.execute(
            text(
                """SELECT checkpoint_ciphertext, metadata_ciphertext
                FROM nexora_agent.agent_checkpoints WHERE thread_id = :thread_id"""
            ),
            {"thread_id": operation.thread_id},
        ).all()
        write_rows = connection.execute(
            text(
                """SELECT value_ciphertext FROM nexora_agent.agent_checkpoint_writes
                WHERE thread_id = :thread_id"""
            ),
            {"thread_id": operation.thread_id},
        ).all()
        event_rows = (
            connection.execute(
                text(
                    """SELECT data_ciphertext FROM nexora_agent.agent_operation_events
                    WHERE operation_id = :id"""
                ),
                {"id": operation_id},
            )
            .scalars()
            .all()
        )
        connection.execute(text("RESET ROLE"))

    assert checkpoint_rows, "the run must have produced checkpoints"
    for checkpoint_blob, metadata_blob in checkpoint_rows:
        assert secret.encode() not in bytes(checkpoint_blob)
        assert secret.encode() not in bytes(metadata_blob)
    for (value_blob,) in write_rows:
        assert secret.encode() not in bytes(value_blob)
    # The event ledger carries the same message text, so it is sealed too. Leaving
    # it as plaintext JSONB would have kept readable at rest exactly what
    # agent_checkpoints deliberately encrypts.
    assert event_rows, "the run must have produced events"
    for event_blob in event_rows:
        assert secret.encode() not in bytes(event_blob)

    # --- 2. the authorized adapter still restores the state, secret intact ---
    restored = agent_state_from_checkpoint(
        composition.runtime._saver(actor)
        .get_tuple({"configurable": {"thread_id": operation.thread_id}})
        .checkpoint
    )
    assert any(secret in item.content for item in restored.messages), (
        "protection must come from encryption, not from losing the message"
    )

    # --- 3. traces: allowlisted fields only, and no secret anywhere ---
    assert composition.trace.spans, "the run must have produced spans"
    assert composition.trace.field_names() <= ALLOWED_SPAN_FIELDS
    assert not composition.trace.field_names() & FORBIDDEN_SPAN_FIELDS
    for forbidden in fixture["forbidden_span_fields"]:
        assert forbidden not in composition.trace.field_names()
    rendered = composition.trace.rendered()
    assert secret not in rendered
    assert message not in rendered
    assert settings.checkpoint_encryption_key.get_secret_value() not in rendered

    # --- 4. structured logs ---
    # First the real control: the runtime's own logging, emitted during the run
    # above, never carried the message or the secret at all.
    runtime_logs = capsys.readouterr()
    assert secret not in runtime_logs.out + runtime_logs.err
    assert message not in runtime_logs.out + runtime_logs.err

    # Then the second layer: a configured secret is scrubbed even from a field a
    # careless caller invents. `create_app` reconfigured logging from settings, so
    # the fixture secret is registered again here as a deployment would register a
    # real one.
    configure_logging(settings.log_level, secret_values=(secret,))
    structlog.get_logger("agent-runtime").info(
        "agent_operation", operation_id=str(operation_id), api_token=secret, note=f"see {secret}"
    )
    emitted = capsys.readouterr()
    assert secret not in emitted.out + emitted.err
    assert REDACTED in emitted.out + emitted.err

    # --- 5. errors: neither the stream nor a not-found leaks anything ---
    assert secret not in missing.text
    assert missing.json()["details"] == {}
    assert secret not in stream.text.replace(message, "")

    # --- 6. evidence ---
    if EVIDENCE_DIR.exists():
        for path in EVIDENCE_DIR.rglob("*"):
            if path.is_file():
                assert secret not in path.read_text(errors="ignore"), path


@pytest.mark.security
def test_trace_drops_forbidden_fields_even_when_a_caller_passes_them() -> None:
    """The allowlist is the control; redaction is the second layer behind it."""
    fixture = _fixture()
    secret = fixture["secret"]
    from app.observability.trace import DeterministicTraceSink

    sink = DeterministicTraceSink(secret_values=(secret,))
    span = sink.record(
        "agent.node",
        operation_id="b0000000-0000-0000-0000-000000000001",
        route="ECHO",
        latency_ms=12,
        # None of the following may survive.
        message=f"my token is {secret}",
        messages=[{"content": secret}],
        checkpoint={"channel_values": secret},
        session_token=secret,
        api_key=secret,
        database_url="postgresql://user:pw@host/db",
    )

    assert set(span.fields) == {"operation_id", "route", "latency_ms"}
    assert secret not in json.dumps(dict(span.fields))
    assert sink.field_names() <= ALLOWED_SPAN_FIELDS

    # And a secret that reaches an allowlisted field is still redacted.
    leaky = sink.record("agent.node", error_code=f"INTERNAL {secret}")
    assert secret not in str(leaky.fields["error_code"])
    assert REDACTED in str(leaky.fields["error_code"])


@pytest.mark.security
def test_allowlist_and_denylist_do_not_overlap() -> None:
    assert not ALLOWED_SPAN_FIELDS & FORBIDDEN_SPAN_FIELDS
