"""P02-005 — the SSE contract: exact events, exact sequence, exact reconnect boundary.

The stream is asserted at the byte level, because a UI will parse these frames and
a helper library's formatting choices are not the contract.

The fixture message deliberately contains a forged SSE frame naming a fake event
type, a fake lifecycle state, an animation and a remote asset URL. It must survive
only as message text, never as an event type, a state, or any field.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from backend.tests.integration.agent.support import (
    ACTOR_A,
    FIXED_NOW,
    TENANT_A,
    actor_for,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)

from app.agent.contracts import StreamEventType
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.identity import derive_event_id
from app.agent.model import DeterministicModelAdapter
from app.agent.state import OperationState
from app.agent.wiring import build_agent_composition
from app.api.chat import format_sse_event, resolve_last_event_id
from app.config import Settings

FIXTURE = Path("backend/tests/fixtures/agent/sse-three-deltas.json")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


def _composition() -> Any:
    settings = Settings(environment="test")
    sessions = runtime_sessions()
    return build_agent_composition(
        settings,
        clock=lambda: FIXED_NOW,
        model=DeterministicModelAdapter(settings),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        sessions=sessions,
    )


def _parse_frames(stream: str) -> list[dict[str, Any]]:
    """Parse an SSE stream strictly, asserting framing as it goes."""
    frames: list[dict[str, Any]] = []
    for block in stream.split("\n\n"):
        if not block:
            continue
        lines = block.split("\n")
        assert len(lines) == 3, f"each frame is exactly id/event/data: {lines!r}"
        assert lines[0].startswith("id: ")
        assert lines[1].startswith("event: ")
        assert lines[2].startswith("data: ")
        frames.append(
            {
                "id": lines[0].removeprefix("id: "),
                "event": lines[1].removeprefix("event: "),
                "data": json.loads(lines[2].removeprefix("data: ")),
            }
        )
    return frames


@pytest.fixture
def streamed() -> tuple[dict[str, Any], Any, Any, list[Any]]:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)

    fixture = _fixture()
    composition = _composition()
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = composition.operations.create_or_restore(
        actor=actor,
        client_request_id=fixture["client_request_id"],
        conversation_id=None,
        now=FIXED_NOW,
    ).operation
    composition.runtime.execute(actor=actor, operation=operation, message=fixture["message"])
    events = composition.events.read(actor=actor, operation_id=operation.operation_id)
    return fixture, composition, operation, events


@pytest.mark.contract
def test_sequence_and_reconnect_are_exact(
    streamed: tuple[dict[str, Any], Any, Any, list[Any]],
) -> None:
    fixture, composition, operation, events = streamed
    actor = actor_for(TENANT_A, ACTOR_A)

    # --- exact registered event types, states and sequence ---
    assert [event.type.value for event in events] == fixture["expected_event_types"]
    assert [event.sequence for event in events] == fixture["expected_sequences"]
    assert all(event.version == "1" for event in events)

    states = [
        event.data["state"]
        for event in events
        if event.type is StreamEventType.OPERATION_STATE_CHANGED
    ]
    assert states == fixture["expected_lifecycle_states"]
    assert all(state in {item.value for item in OperationState} for state in states)

    deltas = [event for event in events if event.type is StreamEventType.MESSAGE_DELTA]
    assert len(deltas) == fixture["expected_delta_count"]
    assert [delta.data["index"] for delta in deltas] == [0, 1, 2]

    # --- exact SSE framing ---
    stream = "".join(format_sse_event(event) for event in events)
    frames = _parse_frames(stream)
    assert len(frames) == len(events)
    assert [frame["event"] for frame in frames] == fixture["expected_event_types"]
    for frame, event in zip(frames, events, strict=True):
        assert frame["id"] == str(event.event_id)
        assert frame["data"]["sequence"] == event.sequence
        assert frame["data"]["operation_id"] == str(operation.operation_id)
        assert frame["data"]["version"] == "1"

    # --- terminal exactly once, and last ---
    terminal = [f for f in frames if f["event"] == StreamEventType.STREAM_COMPLETED.value]
    assert len(terminal) == 1
    assert frames[-1]["event"] == StreamEventType.STREAM_COMPLETED.value

    # --- reconnect boundary: disconnect after sequence two ---
    boundary = fixture["disconnect_after_sequence"]
    last_event_id = str(derive_event_id(operation.operation_id, boundary))
    resolved = resolve_last_event_id(last_event_id, operation.operation_id, len(events))
    assert resolved == boundary

    remaining = composition.events.read(
        actor=actor, operation_id=operation.operation_id, after_sequence=resolved
    )
    assert [event.sequence for event in remaining] == fixture["expected_sequences_after_reconnect"]
    # No earlier delta is replayed.
    assert all(event.sequence > boundary for event in remaining)
    replayed = _parse_frames("".join(format_sse_event(event) for event in remaining))
    assert len(replayed) == len(fixture["expected_sequences_after_reconnect"])
    assert sum(1 for f in replayed if f["event"] == StreamEventType.STREAM_COMPLETED.value) == 1

    # --- the reconnect created no new operation and no new event ---
    assert len(composition.events.read(actor=actor, operation_id=operation.operation_id)) == len(
        events
    )


@pytest.mark.contract
def test_forged_frame_in_a_message_never_becomes_an_event(
    streamed: tuple[dict[str, Any], Any, Any, list[Any]],
) -> None:
    fixture, _composition, _operation, events = streamed
    stream = "".join(format_sse_event(event) for event in events)
    frames = _parse_frames(stream)

    emitted_types = {frame["event"] for frame in frames}
    for forbidden in fixture["forbidden_event_types"]:
        assert forbidden not in emitted_types
    assert emitted_types <= {item.value for item in StreamEventType}

    for frame in frames:
        for forbidden in fixture["forbidden_field_names"]:
            assert forbidden not in frame["data"]
            assert forbidden not in frame["data"]["data"]

    states = [
        frame["data"]["data"]["state"]
        for frame in frames
        if frame["event"] == StreamEventType.OPERATION_STATE_CHANGED.value
    ]
    for forbidden in fixture["forbidden_lifecycle_states"]:
        assert forbidden not in states

    # The hostile text does survive, but only as message content.
    completed = [
        frame for frame in frames if frame["event"] == StreamEventType.MESSAGE_COMPLETED.value
    ]
    assert len(completed) == 1
    assert "robot.animate" in completed[0]["data"]["data"]["text"]
    # And it did not forge a frame: the parser above already proved every frame is
    # exactly three lines, so the embedded newlines stayed inside the JSON string.
    assert len(frames) == len(fixture["expected_event_types"])


@pytest.mark.contract
def test_unrecognised_last_event_id_replays_nothing_extra(
    streamed: tuple[dict[str, Any], Any, Any, list[Any]],
) -> None:
    _fixture_data, _composition, operation, events = streamed

    # Garbage, a foreign operation's id, and a sequence beyond the end all resolve
    # to "no boundary" rather than to a permissive replay-everything.
    assert resolve_last_event_id("not-a-uuid", operation.operation_id, len(events)) is None
    assert (
        resolve_last_event_id(
            "ffffffff-ffff-4fff-8fff-ffffffffffff", operation.operation_id, len(events)
        )
        is None
    )
    assert (
        resolve_last_event_id(
            str(derive_event_id(operation.operation_id, len(events) + 5)),
            operation.operation_id,
            len(events),
        )
        is None
    )
    assert resolve_last_event_id(None, operation.operation_id, len(events)) is None
