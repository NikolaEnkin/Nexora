"""`ActionDescriptor v1` and `PolicyDecision v1`.

Both are `extra="forbid"` frozen contracts for the same reason `ChatRequest` is:
there is no field for message text, a model-supplied risk level, an `approved`
flag or a permission grant to land in. A caller cannot describe an action as
lower-risk than the catalogue says, because `risk` is not accepted as input at
all — `ActionDescriptor` carries what is being attempted, and the evaluator
supplies the classification from versioned data.
"""

from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.contracts.foundation import FrozenContract

POLICY_VERSION = 1
MAX_ACTION_KEY_LENGTH = 100
MAX_IDEMPOTENCY_KEY_LENGTH = 255


class RiskLevel(StrEnum):
    """Closed risk ladder. Assigned by the catalogue, never by input or model text."""

    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class PolicyEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class Assurance(StrEnum):
    """Mirrors `ActorContext.assurance`; `step_up` is Auth0 MFA under `ADR-004` §4."""

    STANDARD = "standard"
    STEP_UP = "step_up"


class PolicyReasonCode(StrEnum):
    ALLOWED = "ALLOWED"
    ACTION_UNKNOWN = "ACTION_UNKNOWN"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    PERMISSION_MISSING = "PERMISSION_MISSING"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"


class ActionDescriptor(FrozenContract):
    """`ActionDescriptor v1` — what is being attempted, not what it is permitted to do."""

    version: Literal["1"] = "1"
    action_type: str = Field(min_length=1, max_length=MAX_ACTION_KEY_LENGTH)
    target_type: str = Field(min_length=1, max_length=MAX_ACTION_KEY_LENGTH)
    target_id: UUID
    normalized_arguments: dict[str, Any]
    idempotency_key: str = Field(min_length=1, max_length=MAX_IDEMPOTENCY_KEY_LENGTH)


class PolicyDecision(FrozenContract):
    """`PolicyDecision v1` — the deterministic verdict for one descriptor and actor."""

    version: Literal["1"] = "1"
    effect: PolicyEffect
    risk: RiskLevel
    reason_code: PolicyReasonCode
    required_permission: str
    required_assurance: Assurance
    policy_version: int = Field(ge=1)
    catalogue_version: int = Field(ge=1)
    normalization_version: int = Field(ge=1)
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")
    # Present only when `effect` is APPROVAL_REQUIRED. Each entry names one valid
    # approver composition from `ADR-004` §2; anything not listed executes nothing.
    approval_path_ids: tuple[int, ...] = ()
