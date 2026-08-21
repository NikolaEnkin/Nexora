"""`ToolCallEnvelope v1` and `ToolResult v1`.

The envelope carries **no identity**. There is no `tenant_id`, no `actor_id`, no
`roles`, no `permissions` and no `assurance` field, so a caller cannot supply one
— not because a check rejects it, but because the contract has nowhere to put it.
The gateway injects the trusted `ActorContext` from the session boundary.

`audience` is declared by the caller but never *trusted* by it: the gateway
verifies that the audience it was authenticated for matches, and that the tool is
exposed to that audience. A forged audience string selects nothing.
"""

from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.contracts.foundation import FrozenContract

TOOL_CONTRACT_VERSION = 1
MAX_TOOL_NAME_LENGTH = 64
MAX_IDEMPOTENCY_KEY_LENGTH = 255


class ToolAudience(StrEnum):
    """Closed set. A tool is reachable only from an audience that declares it."""

    AGENT = "agent"
    OPERATOR_UI = "operator_ui"


class ToolOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENIED = "DENIED"
    FAILED = "FAILED"


class ToolCallEnvelope(FrozenContract):
    """`ToolCallEnvelope v1`."""

    version: Literal["1"] = "1"
    request_id: UUID
    tool_name: str = Field(min_length=1, max_length=MAX_TOOL_NAME_LENGTH)
    tool_version: int = Field(ge=1)
    audience: ToolAudience
    typed_arguments: dict[str, Any]
    idempotency_key: str | None = Field(default=None, max_length=MAX_IDEMPOTENCY_KEY_LENGTH)
    operation_id: UUID | None = None


class ToolError(FrozenContract):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ToolResult(FrozenContract):
    """`ToolResult v1`.

    `replayed` is part of the contract rather than an implementation detail: a
    caller must be able to tell "this happened now" from "this already happened
    and here is the durable result", or it will retry a write that succeeded.
    """

    version: Literal["1"] = "1"
    request_id: UUID
    tool_name: str
    tool_version: int
    outcome: ToolOutcome
    resource: dict[str, Any] | None = None
    resource_version: int | None = None
    replayed: bool = False
    error: ToolError | None = None
    event_ref: str | None = None
    audit_ref: str | None = None
