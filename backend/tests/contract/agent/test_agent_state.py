"""P02-001 — `AgentState v1` round-trip, unknown-major rejection, and closed shape.

Every rejection case below is an exact payload from the fixture, not a synthesized
string, so the test proves the contract rather than restating the implementation.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.agent.contracts import (
    EVENT_DATA_MODELS,
    TERMINAL_EVENT_TYPE,
    StreamEvent,
    StreamEventType,
)
from app.agent.errors import RuntimeErrorCode, StateVersionUnsupported
from app.agent.state import (
    ACTIVE_STATES,
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    AgentState,
    OperationState,
    is_allowed_transition,
    parse_agent_state_v1,
)

STATE_FIXTURE = Path("backend/tests/fixtures/agent/agent-state-v1.json")
EVENT_FIXTURE = Path("backend/tests/fixtures/agent/stream-event-v1.json")


def _state_fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(STATE_FIXTURE.read_text())
    return loaded


def _event_fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(EVENT_FIXTURE.read_text())
    return loaded


@pytest.mark.contract
def test_v1_roundtrip_and_unknown_major_rejection() -> None:
    fixture = _state_fixture()
    payload = fixture["agent_state_v1"]

    parsed = parse_agent_state_v1(payload)
    dumped = parsed.model_dump(mode="json")

    # Exact round-trip: no field loss, no added field, no coerced value.
    assert dumped == payload
    assert set(dumped) == set(payload)
    assert parsed.schema_version == 1
    assert parsed.checkpoint_seq == payload["checkpoint_seq"]
    assert len(parsed.messages) == len(payload["messages"])

    # Re-parsing the dump is stable, so a checkpoint survives store/load unchanged.
    assert parse_agent_state_v1(dumped).model_dump(mode="json") == payload

    # An unknown major fails closed before any validation or coercion.
    unsupported = fixture["unsupported_major"]
    with pytest.raises(StateVersionUnsupported) as captured:
        parse_agent_state_v1(unsupported)
    assert captured.value.code == RuntimeErrorCode.STATE_VERSION_UNSUPPORTED
    assert captured.value.status_code == 409
    assert captured.value.retryable is False
    assert captured.value.details == {"supported_major": "1"}

    # The rejected v2 payload is not silently migrated: the original is untouched.
    assert unsupported["schema_version"] == 2
    assert parse_agent_state_v1(payload).model_dump(mode="json") == payload


@pytest.mark.contract
def test_state_rejects_credentials_tools_permissions_and_presentation_fields() -> None:
    fixture = _state_fixture()
    baseline = fixture["agent_state_v1"]

    assert fixture["rejected_states"], "the rejection fixture must not be empty"
    for name, override in fixture["rejected_states"].items():
        candidate = {**baseline, **override}
        with pytest.raises(ValidationError, match=r".*"):
            parse_agent_state_v1(candidate)
        assert parse_agent_state_v1(baseline).model_dump(mode="json") == baseline, name


@pytest.mark.contract
def test_lifecycle_is_closed_and_terminal_states_never_reactivate() -> None:
    assert set(OperationState) == ACTIVE_STATES | TERMINAL_STATES
    assert ACTIVE_STATES.isdisjoint(TERMINAL_STATES)
    assert set(ALLOWED_TRANSITIONS) == set(OperationState)

    for terminal in TERMINAL_STATES:
        assert ALLOWED_TRANSITIONS[terminal] == frozenset()
        for target in OperationState:
            assert is_allowed_transition(terminal, target) is False

    assert is_allowed_transition(OperationState.RECEIVED, OperationState.RUNNING) is True
    assert is_allowed_transition(OperationState.RUNNING, OperationState.WAITING) is True
    assert is_allowed_transition(OperationState.WAITING, OperationState.RUNNING) is True
    assert is_allowed_transition(OperationState.RECEIVED, OperationState.COMPLETED) is False


@pytest.mark.contract
def test_stream_event_registry_is_closed_and_data_is_typed() -> None:
    fixture = _event_fixture()

    assert [item.value for item in StreamEventType] == fixture["registered_types"]
    assert [item.value for item in OperationState] == fixture["registered_lifecycle_states"]
    assert set(EVENT_DATA_MODELS) == set(StreamEventType)
    assert TERMINAL_EVENT_TYPE is StreamEventType.STREAM_COMPLETED

    valid = fixture["valid_event"]
    event = StreamEvent.model_validate(valid)
    assert event.model_dump(mode="json") == valid

    for name, override in fixture["rejected_events"].items():
        candidate = {**valid, **override}
        with pytest.raises(ValidationError):
            StreamEvent.model_validate(candidate)
        assert name


@pytest.mark.contract
def test_agent_state_requires_tenant_and_actor() -> None:
    fixture = _state_fixture()
    baseline = fixture["agent_state_v1"]

    for required in ("tenant_id", "actor_id", "operation_id", "conversation_id", "correlation_id"):
        candidate = {key: value for key, value in baseline.items() if key != required}
        with pytest.raises(ValidationError):
            AgentState.model_validate(candidate)
