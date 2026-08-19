"""`OperationRef v1`, `StreamEvent v1` and the `/chat` request/response contracts.

`StreamEvent` is the only path by which anything reaches a client stream, and its
`type` is a closed enum whose `data` must validate against a registered
`extra="forbid"` model. That combination is what stops message or model text from
inventing an event type, a lifecycle state, an animation name, an asset URL, a
CSS class or a navigation command: there is no field for it to land in, and no
unregistered type to carry it.

The event payloads are presentation-neutral by construction. Phase 08 owns the
mapping from these values to `RobotVisualState v1`; Phase 02 must not anticipate it.
"""

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from app.agent.errors import RuntimeErrorCode
from app.agent.identity import derive_event_id
from app.agent.state import MAX_MESSAGE_LENGTH, AgentRoute, OperationState, ReasonCode
from app.contracts.foundation import FrozenContract

MAX_CLIENT_REQUEST_ID_LENGTH = 200


class StreamEventType(StrEnum):
    """The complete registry. An unregistered type cannot be constructed."""

    OPERATION_STARTED = "operation.started"
    OPERATION_STATE_CHANGED = "operation.state_changed"
    MESSAGE_DELTA = "message.delta"
    MESSAGE_COMPLETED = "message.completed"
    OPERATION_FAILED = "operation.failed"
    STREAM_COMPLETED = "stream.completed"


TERMINAL_EVENT_TYPE = StreamEventType.STREAM_COMPLETED


class OperationStartedData(FrozenContract):
    conversation_id: UUID


class StateChangedData(FrozenContract):
    state: OperationState
    reason_code: ReasonCode | None = None


class MessageDeltaData(FrozenContract):
    message_id: UUID
    index: int = Field(ge=0)
    text: str = Field(max_length=MAX_MESSAGE_LENGTH)


class MessageCompletedData(FrozenContract):
    message_id: UUID
    text: str = Field(max_length=MAX_MESSAGE_LENGTH)


class OperationFailedData(FrozenContract):
    error_code: RuntimeErrorCode


class StreamCompletedData(FrozenContract):
    final_state: OperationState


EVENT_DATA_MODELS: Mapping[StreamEventType, type[FrozenContract]] = {
    StreamEventType.OPERATION_STARTED: OperationStartedData,
    StreamEventType.OPERATION_STATE_CHANGED: StateChangedData,
    StreamEventType.MESSAGE_DELTA: MessageDeltaData,
    StreamEventType.MESSAGE_COMPLETED: MessageCompletedData,
    StreamEventType.OPERATION_FAILED: OperationFailedData,
    StreamEventType.STREAM_COMPLETED: StreamCompletedData,
}


class StreamEvent(FrozenContract):
    """`StreamEvent v1`."""

    version: Literal["1"] = "1"
    event_id: UUID
    sequence: int = Field(ge=1)
    operation_id: UUID
    type: StreamEventType
    data: dict[str, Any]
    emitted_at: datetime

    @model_validator(mode="after")
    def data_matches_registered_type(self) -> Self:
        """Reject any payload shape the registry does not declare for this type."""
        EVENT_DATA_MODELS[self.type].model_validate(self.data)
        return self

    @model_validator(mode="after")
    def event_id_is_derived(self) -> Self:
        """`event_id` must be the derived value for (operation, sequence)."""
        if self.event_id != derive_event_id(self.operation_id, self.sequence):
            raise ValueError("event_id must be derived from operation_id and sequence")
        return self


def build_stream_event(
    *,
    operation_id: UUID,
    sequence: int,
    event_type: StreamEventType,
    data: FrozenContract,
    emitted_at: datetime,
) -> StreamEvent:
    """Construct a registered event with a derived, stable identifier."""
    expected = EVENT_DATA_MODELS[event_type]
    if not isinstance(data, expected):
        raise TypeError(f"{event_type} requires {expected.__name__}")
    return StreamEvent(
        event_id=derive_event_id(operation_id, sequence),
        sequence=sequence,
        operation_id=operation_id,
        type=event_type,
        data=data.model_dump(mode="json"),
        emitted_at=emitted_at,
    )


class OperationRef(FrozenContract):
    """`OperationRef v1` — immutable tenant/actor/operation/thread identity and lifecycle."""

    version: Literal["1"] = "1"
    operation_id: UUID
    tenant_id: UUID
    actor_id: UUID
    conversation_id: UUID
    thread_id: str = Field(min_length=32, max_length=32)
    state: OperationState
    route: AgentRoute | None = None
    checkpoint_seq: int = Field(ge=0)
    error_code: RuntimeErrorCode | None = None


class ChatRequest(FrozenContract):
    """`ChatRequest v1`.

    `extra="forbid"` is the security control: a client cannot smuggle `tenant_id`,
    `actor_id`, `roles`, `permissions`, `assurance` or an authorization result into
    the request body. The actor comes from the trusted Phase-01 boundary only.
    """

    version: Literal["1"] = "1"
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    conversation_id: UUID | None = None
    client_request_id: str = Field(min_length=1, max_length=MAX_CLIENT_REQUEST_ID_LENGTH)


class ChatAccepted(FrozenContract):
    """`202` body for an accepted submission."""

    version: Literal["1"] = "1"
    operation_id: UUID
    stream_url: str
