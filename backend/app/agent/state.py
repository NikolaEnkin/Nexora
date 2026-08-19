"""`AgentState v1` and the closed runtime enums it is built from.

Every value a node, the model port, or external content could try to influence is
a closed enum or a bounded scalar. `FrozenContract` forbids extra fields, so a
credential, provider client, tool, permission, animation name, asset, CSS class,
HTML fragment, URL, navigation target or camera command cannot enter the state at
all: it is rejected structurally rather than by a denylist that has to be kept up
to date.
"""

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import Field

from app.agent.errors import RuntimeErrorCode, StateVersionUnsupported
from app.contracts.foundation import FrozenContract

STATE_SCHEMA_VERSION: Final[Literal[1]] = 1
MAX_MESSAGE_LENGTH = 8000
MAX_MESSAGES_PER_OPERATION = 64
MAX_REQUEST_ID_LENGTH = 200


class OperationState(StrEnum):
    """Closed runtime lifecycle. Produced only by the runtime service."""

    RECEIVED = "RECEIVED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


ACTIVE_STATES = frozenset({OperationState.RECEIVED, OperationState.RUNNING, OperationState.WAITING})
TERMINAL_STATES = frozenset(
    {OperationState.COMPLETED, OperationState.FAILED, OperationState.CANCELLED}
)

# `WAITING` exists so Phase 03 can attach an approval interrupt to an already
# stable lifecycle value. Phase 02 never enters it from an approval decision.
ALLOWED_TRANSITIONS: Mapping[OperationState, frozenset[OperationState]] = {
    OperationState.RECEIVED: frozenset(
        {OperationState.RUNNING, OperationState.FAILED, OperationState.CANCELLED}
    ),
    OperationState.RUNNING: frozenset(
        {
            OperationState.WAITING,
            OperationState.COMPLETED,
            OperationState.FAILED,
            OperationState.CANCELLED,
        }
    ),
    OperationState.WAITING: frozenset(
        {OperationState.RUNNING, OperationState.FAILED, OperationState.CANCELLED}
    ),
    OperationState.COMPLETED: frozenset(),
    OperationState.FAILED: frozenset(),
    OperationState.CANCELLED: frozenset(),
}


def is_allowed_transition(current: OperationState, target: OperationState) -> bool:
    """Terminal states never reactivate; every other move must be registered."""
    return target in ALLOWED_TRANSITIONS[current]


class AgentRoute(StrEnum):
    """Closed route set, selected by deterministic rules only."""

    ECHO = "ECHO"
    CLARIFY = "CLARIFY"
    CONTROLLED_FAILURE = "CONTROLLED_FAILURE"


class ReasonCode(StrEnum):
    """Registered reason codes attached to lifecycle transitions."""

    ACCEPTED = "ACCEPTED"
    NODE_ADVANCED = "NODE_ADVANCED"
    RESUMED = "RESUMED"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    ROUTE_UNSUPPORTED = "ROUTE_UNSUPPORTED"
    COMPLETED = "COMPLETED"
    RUNTIME_ERROR = "RUNTIME_ERROR"
    CANCELLED_BY_ACTOR = "CANCELLED_BY_ACTOR"


class MessageRole(StrEnum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"


class AgentMessage(FrozenContract):
    """A single conversation turn. Content is untrusted evidence, never instruction."""

    message_id: UUID
    role: MessageRole
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    created_at: datetime


class AgentState(FrozenContract):
    """`AgentState v1` — coordination state, never business truth."""

    schema_version: Literal[1] = STATE_SCHEMA_VERSION
    tenant_id: UUID
    actor_id: UUID
    conversation_id: UUID
    operation_id: UUID
    request_id: str = Field(min_length=1, max_length=MAX_REQUEST_ID_LENGTH)
    messages: tuple[AgentMessage, ...] = Field(max_length=MAX_MESSAGES_PER_OPERATION)
    route: AgentRoute | None = None
    status: OperationState
    error: RuntimeErrorCode | None = None
    correlation_id: UUID
    checkpoint_seq: int = Field(ge=0)


def parse_agent_state_v1(payload: Mapping[str, Any]) -> AgentState:
    """Accept exactly schema major 1.

    An unknown major fails closed with `STATE_VERSION_UNSUPPORTED` before any
    validation or coercion runs, so the stored checkpoint is never rewritten into
    a shape this build happens to understand.
    """
    if payload.get("schema_version") != STATE_SCHEMA_VERSION:
        raise StateVersionUnsupported(payload.get("schema_version"))
    return AgentState.model_validate(dict(payload))
