"""`POST /chat` and the live SSE endpoint, driven through the real application.

These go through `create_app`, so the router registration, error handlers,
correlation middleware and the Phase-01 health endpoints are all exercised
together rather than in isolation.
"""

import json
from typing import Any
from uuid import UUID

import pytest
from backend.tests.integration.agent.support import (
    ACTOR_A,
    ACTOR_B,
    FIXED_NOW,
    TENANT_A,
    TENANT_B,
    actor_for,
    count_all,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.agent.contracts import StreamEventType
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.identity import derive_event_id, derive_operation_id
from app.agent.model import DeterministicModelAdapter
from app.agent.state import OperationState
from app.agent.wiring import build_agent_composition
from app.config import Settings
from app.contracts import ActorContext
from app.main import create_app


class _AlwaysReady:
    def is_ready(self) -> bool:
        return True


def _composition() -> Any:
    settings = Settings(environment="test")
    return build_agent_composition(
        settings,
        clock=lambda: FIXED_NOW,
        model=DeterministicModelAdapter(settings),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        sessions=runtime_sessions(),
    )


def _app(composition: Any, actor: ActorContext) -> FastAPI:
    app = create_app(Settings(environment="test"), readiness=_AlwaysReady(), agent=composition)

    @app.middleware("http")
    async def inject_actor(request: Request, call_next: Any) -> Any:
        request.state.actor = actor
        return await call_next(request)

    return app


def _parse_frames(stream: str) -> list[dict[str, Any]]:
    frames = []
    for block in stream.split("\n\n"):
        if not block:
            continue
        lines = block.split("\n")
        assert len(lines) == 3
        frames.append(
            {
                "id": lines[0].removeprefix("id: "),
                "event": lines[1].removeprefix("event: "),
                "data": json.loads(lines[2].removeprefix("data: ")),
            }
        )
    return frames


@pytest.fixture
def prepared() -> None:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)


@pytest.mark.integration
def test_submit_returns_exact_202_and_streams_to_completion(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    with TestClient(_app(composition, actor)) as client:
        response = client.post(
            "/chat",
            json={"message": "status of the runtime", "client_request_id": "api-001"},
        )
        assert response.status_code == 202
        body = response.json()
        assert body == {
            "version": "1",
            "operation_id": str(derive_operation_id(TENANT_A, ACTOR_A, "api-001")),
            "stream_url": f"/chat/{derive_operation_id(TENANT_A, ACTOR_A, 'api-001')}/events",
        }

        composition.scheduler.wait()

        stream = client.get(body["stream_url"])
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.headers["cache-control"] == "no-store"

    frames = _parse_frames(stream.text)
    assert frames[0]["event"] == StreamEventType.OPERATION_STARTED.value
    assert frames[-1]["event"] == StreamEventType.STREAM_COMPLETED.value
    assert sum(1 for f in frames if f["event"] == StreamEventType.STREAM_COMPLETED.value) == 1
    completed = [f for f in frames if f["event"] == StreamEventType.MESSAGE_COMPLETED.value]
    assert len(completed) == 1
    assert completed[0]["data"]["data"]["text"] == "echo: status of the runtime"

    # Phase-01 health is unaffected by the new router.
    with TestClient(_app(composition, actor)) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}


@pytest.mark.integration
def test_reconnect_replays_only_later_events_and_creates_nothing(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    with TestClient(_app(composition, actor)) as client:
        body = client.post(
            "/chat",
            json={"message": "status of the runtime", "client_request_id": "api-reconnect"},
        ).json()
        composition.scheduler.wait()
        operation_id = UUID(body["operation_id"])

        full = _parse_frames(client.get(body["stream_url"]).text)
        boundary = 2
        reconnected = client.get(
            body["stream_url"],
            headers={"Last-Event-ID": str(derive_event_id(operation_id, boundary))},
        )

    replayed = _parse_frames(reconnected.text)
    assert [frame["data"]["sequence"] for frame in replayed] == [
        frame["data"]["sequence"] for frame in full if frame["data"]["sequence"] > boundary
    ]
    # No delta at or before the boundary is repeated.
    assert all(frame["data"]["sequence"] > boundary for frame in replayed)
    assert sum(1 for f in replayed if f["event"] == StreamEventType.STREAM_COMPLETED.value) == 1

    # Reconnecting created neither an operation nor an event.
    assert count_all(migration_engine(), "agent_operations") == 1
    assert count_all(migration_engine(), "agent_operation_events") == len(full)


@pytest.mark.integration
def test_duplicate_submission_returns_the_same_operation(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    with TestClient(_app(composition, actor)) as client:
        first = client.post(
            "/chat", json={"message": "status of the runtime", "client_request_id": "api-dup"}
        )
        composition.scheduler.wait()
        second = client.post(
            "/chat", json={"message": "status of the runtime", "client_request_id": "api-dup"}
        )
        composition.scheduler.wait()

    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    assert count_all(migration_engine(), "agent_operations") == 1


@pytest.mark.integration
def test_client_cannot_select_tenant_actor_roles_or_permissions(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    escalations = (
        {"tenant_id": str(TENANT_B)},
        {"actor_id": str(ACTOR_B)},
        {"roles": ["OWNER"]},
        {"permissions": ["tenant.manage"]},
        {"assurance": "step_up"},
        {"status": "COMPLETED"},
        {"version": "2"},
    )
    with TestClient(_app(composition, actor)) as client:
        for extra in escalations:
            response = client.post(
                "/chat",
                json={
                    "message": "status of the runtime",
                    "client_request_id": "api-escalate",
                    **extra,
                },
            )
            assert response.status_code == 422, extra
            body = response.json()
            assert body["code"] == "INPUT_INVALID"
            # The rejection must not confirm which privileged field names exist.
            for key in extra:
                assert key not in body["message"]
            assert body["details"] == {}

    # Nothing was created by any attempt.
    assert count_all(migration_engine(), "agent_operations") == 0


@pytest.mark.integration
def test_invalid_input_returns_an_error_envelope(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    with TestClient(_app(composition, actor)) as client:
        for payload in (
            {},
            {"message": ""},
            {"message": "x" * 9000, "client_request_id": "too-long"},
            {"message": "hello there", "client_request_id": ""},
            {"client_request_id": "no-message"},
        ):
            response = client.post("/chat", json=payload)
            assert response.status_code == 422, payload
            body = response.json()
            assert set(body) == {
                "version",
                "code",
                "message",
                "correlation_id",
                "retryable",
                "details",
            }
            assert body["version"] == "1"
            assert body["code"] == "INPUT_INVALID"

    assert count_all(migration_engine(), "agent_operations") == 0


@pytest.mark.integration
def test_chat_can_be_feature_disabled_while_health_keeps_serving(prepared: None) -> None:
    """Rollback drops `/chat` without touching liveness or readiness (packet §17)."""
    app = create_app(Settings(environment="test"), readiness=_AlwaysReady(), enable_chat=False)

    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}
        assert client.post("/chat", json={"message": "hi there"}).status_code == 404


@pytest.mark.integration
def test_no_business_row_is_written_by_a_full_request(prepared: None) -> None:
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)

    with TestClient(_app(composition, actor)) as client:
        body = client.post(
            "/chat", json={"message": "status of the runtime", "client_request_id": "api-effects"}
        ).json()
        composition.scheduler.wait()
        client.get(body["stream_url"])

    from sqlalchemy import text

    from app.db import set_request_context

    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in ("foundation_mutations", "domain_events", "outbox_events", "audit_events"):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0, table

    final = composition.operations.load(actor=actor, operation_id=UUID(body["operation_id"]))
    assert final.state is OperationState.COMPLETED
