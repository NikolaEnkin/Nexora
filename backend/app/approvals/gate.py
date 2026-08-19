"""The protected-action boundary.

Order is the contract, and it is the same order every time:

    rate limit → authorization → policy → approval → effect

Nothing downstream can re-open something upstream refused. A rate-limited call
never reaches policy, so it never costs a model invocation (`P03-008`). A denied
authorization never reaches the approval stage, so no approval request exists for
an unauthorized actor to later have signed (`P03-002`). An approval is resolved
against the *current* payload hash before any effect, so a material edit cannot
ride a previous grant (`P03-005`).

The effect itself is deliberately fake: incrementing a durable counter. Phase 03
owns the boundary, not the business action, and a counter is what lets a security
negative assert "the protected side effect count is zero" against the database
rather than against a mock.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from app.approvals.audit import ApprovalAuditLog
from app.approvals.composition import (
    approval_ttl,
    is_at_or_above_threshold,
    parse_roles,
    requester_kind,
)
from app.approvals.contracts import ApprovalRequest
from app.approvals.errors import ApprovalRequired
from app.approvals.repository import ApprovalRepository
from app.approvals.runtime import ApprovalRuntimeSignal
from app.approvals.service import ApprovalService
from app.contracts import ActorContext
from app.errors import AuthorizationDenied
from app.policy.catalogue import lookup
from app.policy.contracts import (
    ActionDescriptor,
    PolicyDecision,
    PolicyEffect,
    PolicyReasonCode,
    RiskLevel,
)
from app.policy.errors import PolicyDenied, RateLimited
from app.policy.evaluator import evaluate
from app.rate_limit import RateLimitPort


class GateOutcome(StrEnum):
    EXECUTED = "EXECUTED"
    ALLOWED_WITHOUT_APPROVAL = "ALLOWED_WITHOUT_APPROVAL"
    REPLAYED = "REPLAYED"


@dataclass(frozen=True, slots=True)
class GateResult:
    outcome: GateOutcome
    decision: PolicyDecision
    approval: ApprovalRequest | None
    result_ref: str | None


@dataclass(slots=True)
class ProtectedActionGate:
    approvals: ApprovalService
    repository: ApprovalRepository
    limiter: RateLimitPort
    audit: ApprovalAuditLog
    clock: Callable[[], datetime]
    signal: ApprovalRuntimeSignal | None = None

    def execute(
        self,
        *,
        actor: ActorContext,
        descriptor: ActionDescriptor,
        operation_id: UUID | None = None,
        object_tenant_id: UUID | None = None,
    ) -> GateResult:
        now = self.clock()
        tenant = object_tenant_id if object_tenant_id is not None else actor.tenant_id

        # 1. Rate limit, before any model or action call.
        self._enforce_rate_limit(actor, descriptor, now)

        # 2 and 3. Authorization then policy, in that order, inside `evaluate`.
        decision = evaluate(actor=actor, descriptor=descriptor, object_tenant_id=tenant)

        if decision.effect is PolicyEffect.DENY:
            self._audit_denial(actor, descriptor, decision, now)
            if decision.reason_code in (
                PolicyReasonCode.AUTHORIZATION_DENIED,
                PolicyReasonCode.PERMISSION_MISSING,
            ):
                raise AuthorizationDenied
            raise PolicyDenied

        if decision.effect is PolicyEffect.ALLOW:
            # R1: authorization was enough. No approval, and no protected effect.
            return GateResult(
                outcome=GateOutcome.ALLOWED_WITHOUT_APPROVAL,
                decision=decision,
                approval=None,
                result_ref=None,
            )

        # 4. Approval.
        return self._resolve_approval(actor, descriptor, decision, operation_id, now)

    # -- stages ----------------------------------------------------------

    def _enforce_rate_limit(
        self, actor: ActorContext, descriptor: ActionDescriptor, now: datetime
    ) -> None:
        entry = lookup(descriptor.action_type)
        # An unclassified action is rate limited at the strictest tier. It will be
        # denied by policy a moment later; limiting it first stops an unbounded
        # probe of the catalogue.
        risk = entry.risk if entry is not None else RiskLevel.R3
        verdict = self.limiter.check(
            tenant_id=actor.tenant_id,
            actor_id=actor.actor_id,
            operation=descriptor.action_type,
            risk=risk,
            now=now,
        )
        if not verdict.allowed:
            raise RateLimited(verdict.retry_after_seconds)

    def _resolve_approval(
        self,
        actor: ActorContext,
        descriptor: ActionDescriptor,
        decision: PolicyDecision,
        operation_id: UUID | None,
        now: datetime,
    ) -> GateResult:
        entry = lookup(descriptor.action_type)
        assert entry is not None  # unclassified actions were denied above
        expires_at = now + approval_ttl(
            risk=decision.risk,
            requester=requester_kind(parse_roles(actor.roles)),
            at_or_above_threshold=is_at_or_above_threshold(entry, descriptor.normalized_arguments),
        )
        request, _created = self.approvals.open_request(
            actor=actor,
            descriptor=descriptor,
            decision=decision,
            operation_id=operation_id,
            expires_at=expires_at,
        )

        try:
            grant = self.approvals.current_grant(
                actor=actor,
                approval_id=request.approval_id,
                payload_hash=decision.payload_hash,
            )
        except ApprovalRequired:
            # Durable wait. The registered lifecycle signal is emitted by the
            # adapter, never by anything that read message content.
            if self.signal is not None and operation_id is not None:
                self.signal.signal_waiting(actor=actor, operation_id=operation_id, now=now)
            raise

        # 5. Effect. The consumption row and the counter commit together.
        consumption = self.repository.consume_and_apply(
            actor=actor,
            approval_id=request.approval_id,
            operation_id=operation_id,
            action_key=descriptor.action_type,
            target_id=descriptor.target_id,
            payload_hash=decision.payload_hash,
            result_ref=grant.single_use_key,
            now=now,
        )
        if not consumption.created:
            # A concurrent worker already consumed this grant. Durable no-op.
            return GateResult(
                outcome=GateOutcome.REPLAYED,
                decision=decision,
                approval=request,
                result_ref=consumption.result_ref,
            )

        consumed = self.approvals.mark_consumed(actor=actor, approval_id=request.approval_id)
        if self.signal is not None and operation_id is not None:
            self.signal.signal_resumed(actor=actor, operation_id=operation_id, now=now)
        self.audit.record(
            actor=actor,
            action="approval.consumed",
            target_id=request.approval_id,
            result="SUCCEEDED",
            reason="GRANT_CONSUMED",
            metadata={
                "approval_id": str(request.approval_id),
                "action_key": descriptor.action_type,
                "risk": decision.risk.value,
                "path_id": grant.satisfied_path_id,
                "payload_hash": decision.payload_hash,
            },
            now=now,
        )
        return GateResult(
            outcome=GateOutcome.EXECUTED,
            decision=decision,
            approval=consumed,
            result_ref=consumption.result_ref,
        )

    def _audit_denial(
        self,
        actor: ActorContext,
        descriptor: ActionDescriptor,
        decision: PolicyDecision,
        now: datetime,
    ) -> None:
        self.audit.record(
            actor=actor,
            action="policy.denied",
            target_id=descriptor.target_id,
            result="DENIED",
            reason=decision.reason_code.value,
            metadata={
                "action_key": descriptor.action_type,
                "risk": decision.risk.value,
                "result_code": decision.reason_code.value,
                "policy_version": decision.policy_version,
                "catalogue_version": decision.catalogue_version,
            },
            now=now,
        )
