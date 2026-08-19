"""`ApprovalRequest v1` and `ApprovalGrant v1`.

An approval request is immutable in everything that describes *what* is being
approved. Only `status`, `satisfied_path_id`, `updated_at` and `terminal_at` ever
change, and a database trigger enforces that independently of this module. That is
what makes a stored request mean the same thing to the approver who reads it and
to the executor that later consumes it.

`ApprovalGrant` is derived rather than stored: it is the answer to "is this
approval currently usable for this exact payload", computed from the request, its
decisions and the server clock. Storing a grant would create a second source of
truth that could drift from the decisions it summarizes.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.contracts.foundation import FrozenContract
from app.policy.contracts import Assurance, RiskLevel


class ApprovalStatus(StrEnum):
    """Packet §10, verbatim. Terminal states are immutable."""

    DRAFT = "DRAFT"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    CONSUMING = "CONSUMING"
    CONSUMED = "CONSUMED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"
    REVOKED = "REVOKED"
    FAILED_FINAL = "FAILED_FINAL"


NONTERMINAL_STATUSES = frozenset(
    {
        ApprovalStatus.DRAFT,
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
        ApprovalStatus.CONSUMING,
    }
)
TERMINAL_STATUSES = frozenset(ApprovalStatus) - NONTERMINAL_STATUSES


class DecisionType(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ApprovalRequest(FrozenContract):
    """`ApprovalRequest v1`."""

    version: Literal["1"] = "1"
    approval_id: UUID
    tenant_id: UUID
    requester_id: UUID
    operation_id: UUID | None = None
    action_key: str = Field(min_length=1, max_length=100)
    target_type: str = Field(min_length=1, max_length=100)
    target_id: UUID
    payload: dict[str, Any]
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")
    risk: RiskLevel
    normalization_version: int = Field(ge=1)
    policy_version: int = Field(ge=1)
    catalogue_version: int = Field(ge=1)
    open_path_ids: tuple[int, ...]
    required_assurance: Assurance
    status: ApprovalStatus
    satisfied_path_id: int | None = None
    expires_at: datetime
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None = None


class ApprovalDecisionRecord(FrozenContract):
    """One append-only decision. `roles` is captured at decision time."""

    version: Literal["1"] = "1"
    decision_id: UUID
    approval_id: UUID
    tenant_id: UUID
    actor_id: UUID
    decision: DecisionType
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")
    assurance: Assurance
    roles: tuple[str, ...]
    created_at: datetime


class ApprovalGrant(FrozenContract):
    """`ApprovalGrant v1` — a currently usable approval, derived not stored."""

    version: Literal["1"] = "1"
    approval_id: UUID
    tenant_id: UUID
    requester_id: UUID
    approver_ids: tuple[UUID, ...]
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")
    satisfied_path_id: int
    granted_at: datetime
    expires_at: datetime
    required_assurance: Assurance
    # Single-use metadata: the consumption row keyed on `approval_id` is what
    # actually enforces it, and this records the identity that will be written.
    single_use_key: str = Field(min_length=1, max_length=255)
