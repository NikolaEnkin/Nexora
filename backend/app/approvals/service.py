"""The approval lifecycle — packet §10 and `ADR-004` §2.

This service alone transitions approval state. Three ordering rules carry the
security weight, and each is placed before anything that could be influenced by
what comes after it:

1. **Expiry is evaluated against the server clock before every read of a grant
   and before every decision.** A request that has run out of time is closed
   first, so a partial composition can never be completed after the fact, and a
   grant can never be issued from a stale row.
2. **Authorization precedes the decision.** Holding `approval.decide` is checked
   before a decision row is written, so an unauthorized actor never leaves a
   decision that a later composition pass could count.
3. **The payload hash is compared before anything else about the request is
   used.** A material edit makes the stored approval stale, and stale means the
   request is closed rather than merely refused, so the old grant cannot be
   reused against the new payload.

`ADR-004` §2: one rejection is terminal, and a partial composition executes
nothing. Both are implemented here rather than at the call site, because a call
site that forgets either produces a silent authorization bypass.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.approvals.audit import ApprovalAuditLog
from app.approvals.composition import (
    ApprovalPath,
    ApproverDecision,
    execution_ttl,
    parse_roles,
    satisfied_path,
)
from app.approvals.contracts import (
    TERMINAL_STATUSES,
    ApprovalGrant,
    ApprovalRequest,
    ApprovalStatus,
    DecisionType,
)
from app.approvals.errors import (
    ApprovalExpired,
    ApprovalNotAuthorized,
    ApprovalNotFound,
    ApprovalReplayed,
    ApprovalRevoked,
    ApprovalStale,
)
from app.approvals.identity import derive_approval_id
from app.approvals.repository import ApprovalRepository
from app.contracts import ActorContext
from app.policy.canonical import hashes_match
from app.policy.contracts import ActionDescriptor, PolicyDecision, RiskLevel

DECIDE_PERMISSION = "approval.decide"
DECIDE_HIGH_PERMISSION = "approval.decide.high"

_PATHS_BY_ID: dict[int, ApprovalPath] = {}


def _path_registry() -> dict[int, ApprovalPath]:
    if not _PATHS_BY_ID:
        from app.approvals import composition

        for path in (
            composition.PATH_R2,
            composition.PATH_1_OWNER,
            composition.PATH_2_DEPUTY_OWN,
            composition.PATH_3_DEPUTY_SMALL,
            composition.PATH_4_TWO_OPERATORS,
            composition.PATH_5_TWO_OPERATORS_DEPUTY,
        ):
            _PATHS_BY_ID[path.path_id] = path
    return _PATHS_BY_ID


def applicable_deadline(request: ApprovalRequest) -> datetime:
    """The deadline that currently governs this approval — `ADR-004` §3 as amended.

    Two windows, one at a time. Before the composition is satisfied the deadline is
    the collection window stored in `expires_at`. The moment it is satisfied,
    `approved_at` is stamped and the deadline becomes the short execution window.

    The switch is what makes collecting three signatures cheap and staying loaded
    expensive: a request approved on minute 5 of an eight-hour collection window
    closes on minute 15, not minute 480.
    """
    if request.approved_at is None:
        return request.expires_at
    return request.approved_at + execution_ttl(request.risk)


def may_decide(actor: ActorContext, risk: RiskLevel) -> bool:
    """Whether this actor may record *any* decision — `ADR-004` §2.

    `approval.decide.high` is **not** a gate on R3. Paths 4 and 5 are satisfied by
    `OPERATOR` decisions on R3 actions, so treating `.high` as an R3 requirement
    would make two of the five approval paths unreachable. What `.high` does is
    imply `.decide`: `ADR-004` grants it to `OWNER` and `DEPUTY` precisely so that
    "a CFO holding only `DEPUTY` could approve a two-million-euro payment but not
    a €500 draft" cannot happen.

    What actually restricts R3 is the *composition*: which roles may fill which
    slots, how many are needed, and that every R3 approver presents step-up. That
    lives in `app.approvals.composition`, and `risk` is carried here so the caller
    and the audit record agree on what was being decided.
    """
    return DECIDE_HIGH_PERMISSION in actor.permissions or DECIDE_PERMISSION in actor.permissions


@dataclass(slots=True)
class ApprovalService:
    repository: ApprovalRepository
    audit: ApprovalAuditLog
    clock: Callable[[], datetime]

    # -- creation --------------------------------------------------------

    def open_request(
        self,
        *,
        actor: ActorContext,
        descriptor: ActionDescriptor,
        decision: PolicyDecision,
        operation_id: UUID | None,
        expires_at: datetime,
    ) -> tuple[ApprovalRequest, bool]:
        """Create, or return, the single pending request for this submission."""
        approval_id = derive_approval_id(
            actor.tenant_id, actor.actor_id, descriptor.action_type, descriptor.idempotency_key
        )
        now = self.clock()
        request, created = self.repository.create_or_get(
            actor=actor,
            approval_id=approval_id,
            request={
                "tenant_id": actor.tenant_id,
                "requester_id": actor.actor_id,
                "operation_id": operation_id,
                "action_key": descriptor.action_type,
                "target_type": descriptor.target_type,
                "target_id": descriptor.target_id,
                "payload": _payload_json(descriptor),
                "payload_hash": decision.payload_hash,
                "risk": decision.risk.value,
                "normalization_version": decision.normalization_version,
                "policy_version": decision.policy_version,
                "catalogue_version": decision.catalogue_version,
                "open_path_ids": list(decision.approval_path_ids),
                "required_assurance": decision.required_assurance.value,
                "idempotency_key": descriptor.idempotency_key,
                "correlation_id": actor.correlation_id,
                "expires_at": expires_at,
            },
            now=now,
        )
        if created:
            self.audit.record(
                actor=actor,
                action="approval.requested",
                target_id=request.approval_id,
                result="PENDING",
                reason="APPROVAL_REQUIRED",
                metadata={
                    "approval_id": str(request.approval_id),
                    "action_key": request.action_key,
                    "risk": request.risk.value,
                    "payload_hash": request.payload_hash,
                    "policy_version": request.policy_version,
                    "catalogue_version": request.catalogue_version,
                    "normalization_version": request.normalization_version,
                },
                now=now,
            )
        elif not hashes_match(request.payload_hash, decision.payload_hash):
            # The same submission identity now describes a different action.
            # `BR-03-004`: the prior approval is invalidated, not reused.
            self._invalidate(actor, request, reason="PAYLOAD_CHANGED")
            raise ApprovalStale
        return request, created

    # -- decisions -------------------------------------------------------

    def decide(
        self,
        *,
        actor: ActorContext,
        approval_id: UUID,
        decision: DecisionType,
        payload_hash: str,
        idempotency_key: str,
    ) -> ApprovalRequest:
        """Record one decision and recompute the composition."""
        now = self.clock()
        request = self.repository.load(actor=actor, approval_id=approval_id)
        if request is None:
            raise ApprovalNotFound

        request = self._close_if_expired(actor, request, now)
        self._refuse_if_not_current(request)

        # A decision that does not describe the current payload is stale, and a
        # stale decision closes the request rather than being ignored.
        if not hashes_match(request.payload_hash, payload_hash):
            self._invalidate(actor, request, reason="PAYLOAD_CHANGED")
            raise ApprovalStale

        if not may_decide(actor, request.risk):
            self._audit_refusal(actor, request, "APPROVAL_NOT_AUTHORIZED", now)
            raise ApprovalNotAuthorized

        record, created = self.repository.record_decision(
            actor=actor,
            approval_id=approval_id,
            decision=decision,
            payload_hash=payload_hash,
            idempotency_key=idempotency_key,
            now=now,
        )
        if not created:
            # A replay of the same decision is a durable no-op.
            return self.repository.load(actor=actor, approval_id=approval_id) or request

        self.audit.record(
            actor=actor,
            action="approval.decided",
            target_id=approval_id,
            result=record.decision.value,
            reason="DECISION_RECORDED",
            metadata={
                "approval_id": str(approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "decision": record.decision.value,
                "payload_hash": request.payload_hash,
            },
            now=now,
        )

        if decision is DecisionType.REJECTED:
            # `ADR-004` §2: one rejection is terminal.
            return self.repository.set_status(
                actor=actor,
                approval_id=approval_id,
                status=ApprovalStatus.REJECTED,
                now=now,
            )

        return self._recompute_composition(actor, approval_id, request, now)

    def _recompute_composition(
        self,
        actor: ActorContext,
        approval_id: UUID,
        request: ApprovalRequest,
        now: datetime,
    ) -> ApprovalRequest:
        decisions = self.repository.decisions_for(actor=actor, approval_id=approval_id)
        approvals = [
            ApproverDecision(
                actor_id=item.actor_id,
                roles=parse_roles(item.roles),
                assurance=item.assurance,
            )
            for item in decisions
            if item.decision is DecisionType.APPROVED
        ]
        registry = _path_registry()
        open_paths = tuple(
            registry[path_id] for path_id in request.open_path_ids if path_id in registry
        )
        matched = satisfied_path(
            paths=open_paths,
            decisions=approvals,
            requester_id=request.requester_id,
            risk=request.risk,
        )
        if matched is None:
            # Partial composition: still PENDING, and the effect counter stays at
            # zero because no grant exists to consume.
            return self.repository.load(actor=actor, approval_id=approval_id) or request

        updated = self.repository.set_status(
            actor=actor,
            approval_id=approval_id,
            status=ApprovalStatus.APPROVED,
            now=now,
            satisfied_path_id=matched.path_id,
        )
        self.audit.record(
            actor=actor,
            action="approval.granted",
            target_id=approval_id,
            result="APPROVED",
            reason="COMPOSITION_SATISFIED",
            metadata={
                "approval_id": str(approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "path_id": matched.path_id,
                "payload_hash": request.payload_hash,
            },
            now=now,
        )
        return updated

    # -- grants and consumption ------------------------------------------

    def current_grant(
        self, *, actor: ActorContext, approval_id: UUID, payload_hash: str
    ) -> ApprovalGrant:
        """The grant, or an exact error explaining why there is none."""
        now = self.clock()
        request = self.repository.load(actor=actor, approval_id=approval_id)
        if request is None:
            raise ApprovalNotFound

        request = self._close_if_expired(actor, request, now)
        self._refuse_if_not_current(request)

        if not hashes_match(request.payload_hash, payload_hash):
            self._invalidate(actor, request, reason="PAYLOAD_CHANGED")
            raise ApprovalStale
        if request.status is not ApprovalStatus.APPROVED:
            from app.approvals.errors import ApprovalRequired

            raise ApprovalRequired(str(approval_id))
        if self.repository.consumption_for(actor=actor, approval_id=approval_id) is not None:
            raise ApprovalReplayed

        decisions = self.repository.decisions_for(actor=actor, approval_id=approval_id)
        return ApprovalGrant(
            approval_id=request.approval_id,
            tenant_id=request.tenant_id,
            requester_id=request.requester_id,
            approver_ids=tuple(
                item.actor_id for item in decisions if item.decision is DecisionType.APPROVED
            ),
            payload_hash=request.payload_hash,
            satisfied_path_id=request.satisfied_path_id or 0,
            granted_at=request.updated_at,
            expires_at=applicable_deadline(request),
            required_assurance=request.required_assurance,
            single_use_key=f"{request.approval_id}:{request.payload_hash}",
        )

    def mark_consumed(self, *, actor: ActorContext, approval_id: UUID) -> ApprovalRequest:
        now = self.clock()
        return self.repository.set_status(
            actor=actor, approval_id=approval_id, status=ApprovalStatus.CONSUMED, now=now
        )

    # -- lifecycle transitions -------------------------------------------

    def cancel(self, *, actor: ActorContext, approval_id: UUID) -> ApprovalRequest:
        return self._terminate(actor, approval_id, ApprovalStatus.CANCELLED, "CANCELLED")

    def revoke(self, *, actor: ActorContext, approval_id: UUID) -> ApprovalRequest:
        return self._terminate(actor, approval_id, ApprovalStatus.REVOKED, "REVOKED")

    def _terminate(
        self, actor: ActorContext, approval_id: UUID, status: ApprovalStatus, reason: str
    ) -> ApprovalRequest:
        now = self.clock()
        request = self.repository.load(actor=actor, approval_id=approval_id)
        if request is None:
            raise ApprovalNotFound
        if request.status in TERMINAL_STATUSES:
            return request
        updated = self.repository.set_status(
            actor=actor, approval_id=approval_id, status=status, now=now
        )
        self.audit.record(
            actor=actor,
            action="approval.terminated",
            target_id=approval_id,
            result=status.value,
            reason=reason,
            metadata={
                "approval_id": str(approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "result_code": reason,
            },
            now=now,
        )
        return updated

    def _invalidate(self, actor: ActorContext, request: ApprovalRequest, *, reason: str) -> None:
        if request.status in TERMINAL_STATUSES:
            return
        now = self.clock()
        self.repository.set_status(
            actor=actor,
            approval_id=request.approval_id,
            status=ApprovalStatus.INVALIDATED,
            now=now,
        )
        self.audit.record(
            actor=actor,
            action="approval.invalidated",
            target_id=request.approval_id,
            result="INVALIDATED",
            reason=reason,
            metadata={
                "approval_id": str(request.approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "result_code": "APPROVAL_STALE",
            },
            now=now,
        )

    def _close_if_expired(
        self, actor: ActorContext, request: ApprovalRequest, now: datetime
    ) -> ApprovalRequest:
        """Server clock only. A client-supplied time never extends an approval."""
        if request.status in TERMINAL_STATUSES or now < applicable_deadline(request):
            return request
        closed = self.repository.set_status(
            actor=actor,
            approval_id=request.approval_id,
            status=ApprovalStatus.EXPIRED,
            now=now,
        )
        self.audit.record(
            actor=actor,
            action="approval.expired",
            target_id=request.approval_id,
            result="EXPIRED",
            reason="TTL_ELAPSED",
            metadata={
                "approval_id": str(request.approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "result_code": "APPROVAL_EXPIRED",
            },
            now=now,
        )
        return closed

    def _refuse_if_not_current(self, request: ApprovalRequest) -> None:
        if request.status is ApprovalStatus.EXPIRED:
            raise ApprovalExpired
        if request.status in (ApprovalStatus.REVOKED, ApprovalStatus.CANCELLED):
            raise ApprovalRevoked
        if request.status is ApprovalStatus.INVALIDATED:
            raise ApprovalStale
        if request.status is ApprovalStatus.CONSUMED:
            raise ApprovalReplayed
        if request.status in TERMINAL_STATUSES:
            raise ApprovalRevoked

    def _audit_refusal(
        self, actor: ActorContext, request: ApprovalRequest, code: str, now: datetime
    ) -> None:
        self.audit.record(
            actor=actor,
            action="approval.refused",
            target_id=request.approval_id,
            result="DENIED",
            reason=code,
            metadata={
                "approval_id": str(request.approval_id),
                "action_key": request.action_key,
                "risk": request.risk.value,
                "result_code": code,
            },
            now=now,
        )


def _payload_json(descriptor: ActionDescriptor) -> str:
    """The stored payload is the canonical form, so what is read back is what was hashed."""
    import json

    from app.policy.canonical import normalize

    return json.dumps(
        normalize(descriptor.normalized_arguments),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
