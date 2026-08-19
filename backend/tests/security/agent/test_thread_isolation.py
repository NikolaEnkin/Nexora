"""P02-006 — a guessed foreign operation discloses nothing.

The strong form of the claim is tested: the response for tenant A's real
operation, viewed as tenant B, must be *byte-identical* to the response for an
identifier that never existed. Anything weaker leaks existence.
"""

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from backend.tests.integration.agent.support import (
    FIXED_NOW,
    actor_for,
    count_all,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.model import DeterministicModelAdapter
from app.agent.wiring import build_agent_composition
from app.config import Settings
from app.contracts import ActorContext
from app.main import create_app

FIXTURE = Path("backend/tests/fixtures/agent/two-actors-two-tenants.json")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


def _app(composition: Any, actor: ActorContext) -> FastAPI:
    """The real application, with only the trusted actor injected."""
    settings = Settings(environment="test")
    app = create_app(
        settings,
        readiness=type("Ready", (), {"is_ready": staticmethod(lambda: True)})(),
        agent=composition,
    )

    @app.middleware("http")
    async def inject_actor(request: Request, call_next: Any) -> Any:
        request.state.actor = actor
        return await call_next(request)

    return app


def _composition() -> Any:
    settings = Settings(environment="test")
    return build_agent_composition(
        settings,
        clock=lambda: FIXED_NOW,
        model=DeterministicModelAdapter(settings),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        sessions=runtime_sessions(),
    )


@pytest.fixture
def owned() -> tuple[dict[str, Any], Any, Any]:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)

    fixture = _fixture()
    composition = _composition()
    owner = actor_for(UUID(fixture["tenant_a"]), UUID(fixture["actor_a"]))
    operation = composition.operations.create_or_restore(
        actor=owner,
        client_request_id=fixture["client_request_id"],
        conversation_id=None,
        now=FIXED_NOW,
    ).operation
    composition.runtime.execute(actor=owner, operation=operation, message=fixture["message"])
    return fixture, composition, operation


@pytest.mark.security
def test_guessed_operation_is_non_disclosing(owned: tuple[dict[str, Any], Any, Any]) -> None:
    fixture, composition, operation = owned
    intruder = actor_for(UUID(fixture["tenant_b"]), UUID(fixture["actor_b"]))

    events_before = len(
        composition.events.read(
            actor=actor_for(UUID(fixture["tenant_a"]), UUID(fixture["actor_a"])),
            operation_id=operation.operation_id,
        )
    )

    with TestClient(_app(composition, intruder), raise_server_exceptions=False) as client:
        guessed = client.get(f"/chat/{operation.operation_id}/events")
        absent = client.get(f"/chat/{fixture['never_existed_operation_id']}/events")

    assert guessed.status_code == fixture["expected_status"]
    assert absent.status_code == fixture["expected_status"]

    guessed_body = guessed.json()
    absent_body = absent.json()
    assert guessed_body["code"] == fixture["expected_error_code"]
    assert guessed_body["details"] == fixture["expected_details"]
    assert guessed_body["retryable"] is False

    # The decisive assertion: a real foreign object and a nonexistent one are
    # indistinguishable once the per-request correlation id is set aside.
    del guessed_body["correlation_id"], absent_body["correlation_id"]
    assert guessed_body == absent_body

    # No fragment of tenant A's world appears in either response.
    for body in (guessed.text, absent.text):
        for fragment in fixture["forbidden_response_fragments"]:
            assert fragment not in body, fragment

    # Tenant A's state is untouched by the probing.
    owner = actor_for(UUID(fixture["tenant_a"]), UUID(fixture["actor_a"]))
    assert (
        len(composition.events.read(actor=owner, operation_id=operation.operation_id))
        == events_before
    )
    assert (
        composition.operations.load(actor=owner, operation_id=operation.operation_id).operation_id
        == operation.operation_id
    )
    assert count_all(migration_engine(), "agent_operations") == 1


@pytest.mark.security
def test_foreign_thread_and_checkpoint_ids_disclose_nothing(
    owned: tuple[dict[str, Any], Any, Any],
) -> None:
    fixture, composition, operation = owned
    intruder = actor_for(UUID(fixture["tenant_b"]), UUID(fixture["actor_b"]))

    # The intruder holds the exact thread key and still sees no checkpoint.
    saver = composition.runtime._saver(intruder)
    config = {"configurable": {"thread_id": operation.thread_id}}
    assert saver.get_tuple(config) is None
    assert list(saver.list(config)) == []

    # And no events, and no terminal event.
    assert composition.events.read(actor=intruder, operation_id=operation.operation_id) == []
    assert (
        composition.events.terminal_event(actor=intruder, operation_id=operation.operation_id)
        is None
    )

    # The owner's checkpoints are still there, so the zeros above are the boundary
    # refusing rather than an empty database.
    owner = actor_for(UUID(fixture["tenant_a"]), UUID(fixture["actor_a"]))
    assert composition.runtime._saver(owner).get_tuple(config) is not None
    assert count_all(migration_engine(), "agent_checkpoints") > 0


@pytest.mark.security
def test_intruder_cannot_advance_or_terminate_a_foreign_operation(
    owned: tuple[dict[str, Any], Any, Any],
) -> None:
    fixture, composition, operation = owned
    intruder = actor_for(UUID(fixture["tenant_b"]), UUID(fixture["actor_b"]))
    owner = actor_for(UUID(fixture["tenant_a"]), UUID(fixture["actor_a"]))

    before = composition.operations.load(actor=owner, operation_id=operation.operation_id)
    events_before = composition.events.read(actor=owner, operation_id=operation.operation_id)

    from app.agent.errors import OperationNotFound
    from app.agent.state import OperationState

    with pytest.raises(OperationNotFound):
        composition.operations.load(actor=intruder, operation_id=operation.operation_id)
    with pytest.raises(OperationNotFound):
        composition.operations.transition(
            actor=intruder,
            operation_id=operation.operation_id,
            target=OperationState.CANCELLED,
            now=FIXED_NOW,
        )
    with pytest.raises(OperationNotFound):
        composition.runtime.execute(actor=intruder, operation=operation, message="take this over")

    # Zero protected side effects.
    after = composition.operations.load(actor=owner, operation_id=operation.operation_id)
    assert after == before
    assert composition.events.read(actor=owner, operation_id=operation.operation_id) == (
        events_before
    )
    assert count_all(migration_engine(), "agent_operations") == 1
