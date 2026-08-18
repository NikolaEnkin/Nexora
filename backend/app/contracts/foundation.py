from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ActorContext(FrozenContract):
    version: Literal["1"] = "1"
    tenant_id: UUID
    actor_id: UUID
    subject: str = Field(min_length=1, max_length=255)
    auth_method: Literal["auth0_oidc", "test_fixture"]
    assurance: Literal["standard", "step_up"] = "standard"
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    correlation_id: UUID


class AuthorizationEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationDecision(FrozenContract):
    version: Literal["1"] = "1"
    effect: AuthorizationEffect
    permission: str
    object_scope: str
    reason_code: str


class DomainEvent(FrozenContract):
    version: Literal["1"] = "1"
    id: UUID
    tenant_id: UUID
    aggregate_type: str
    aggregate_id: UUID
    aggregate_version: int = Field(ge=1)
    event_type: str
    event_version: Literal[1] = 1
    occurred_at: datetime
    correlation_id: UUID
    causation_id: UUID | None = None
    payload_ref: str
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")


class AuditEvent(FrozenContract):
    version: Literal["1"] = "1"
    id: UUID
    tenant_id: UUID
    actor_id: UUID
    action: str
    target_type: str
    target_id: UUID
    result: str
    reason: str
    correlation_id: UUID
    metadata: dict[str, Any]
    occurred_at: datetime


class IdempotencyState(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED_FINAL = "FAILED_FINAL"


class IdempotencyRecord(FrozenContract):
    version: Literal["1"] = "1"
    id: UUID
    tenant_id: UUID
    actor_id: UUID
    operation: str
    key: str
    request_hash: str = Field(pattern="^[a-f0-9]{64}$")
    state: IdempotencyState
    stored_result: dict[str, Any] | None = None
    stored_error: dict[str, Any] | None = None


class ErrorEnvelope(FrozenContract):
    version: Literal["1"] = "1"
    code: str
    message: str
    correlation_id: UUID | str
    retryable: bool
    details: dict[str, Any] = Field(default_factory=dict)


def parse_v1[ContractT: BaseModel](model: type[ContractT], payload: dict[str, Any]) -> ContractT:
    from app.errors import ContractVersionUnsupported

    if payload.get("version") != "1":
        raise ContractVersionUnsupported(payload.get("version"))
    return model.model_validate(payload)
