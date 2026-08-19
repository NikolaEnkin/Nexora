"""Approval persistence.

Every statement is a literal string with bound parameters; nothing composes SQL
from a variable. Every read and write runs inside a signed tenant context, so
row-level security is the boundary even when a caller forgets a filter.

Two uniqueness constraints do the real work and are deliberately relied on
instead of service-side checks:

* `uq_approval_decisions_one_per_actor` makes "every decision comes from a
  different actor" true under concurrency.
* `uq_approval_consumptions_single_use` makes an approval single-use. Ten workers
  racing to consume the same grant produce one row; the losers see an
  `IntegrityError` and convert it into a durable no-op rather than a second
  effect.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.approvals.contracts import (
    ApprovalDecisionRecord,
    ApprovalRequest,
    ApprovalStatus,
    DecisionType,
)
from app.approvals.identity import derive_consumption_id, derive_decision_id
from app.contracts import ActorContext
from app.db import set_request_context
from app.policy.contracts import Assurance, RiskLevel

# The returned column list is written out in full in every statement rather than
# interpolated from a constant. Interpolation would be safe here — the constant is
# not caller-controlled — but "no SQL is ever composed from a variable" is a rule
# worth being able to verify by reading, not by tracing where a name came from.
_INSERT_REQUEST = text(
    """INSERT INTO approval_requests (
        id, tenant_id, requester_id, operation_id, action_key, target_type, target_id,
        payload, payload_hash, risk, normalization_version, policy_version,
        catalogue_version, open_path_ids, required_assurance, status, satisfied_path_id,
        idempotency_key, correlation_id, expires_at, created_at, updated_at, terminal_at
    ) VALUES (
        :id, :tenant_id, :requester_id, :operation_id, :action_key, :target_type, :target_id,
        CAST(:payload AS jsonb), :payload_hash, :risk, :normalization_version, :policy_version,
        :catalogue_version, :open_path_ids, :required_assurance, 'PENDING', NULL,
        :idempotency_key, :correlation_id, :expires_at, :now, :now, NULL
    ) ON CONFLICT DO NOTHING
    RETURNING id, tenant_id, requester_id, operation_id, action_key, target_type,
              target_id, payload, payload_hash, risk, normalization_version, policy_version,
              catalogue_version, open_path_ids, required_assurance, status, satisfied_path_id,
              expires_at, created_at, updated_at, terminal_at"""
)
_SELECT_REQUEST = text(
    """SELECT id, tenant_id, requester_id, operation_id, action_key, target_type,
              target_id, payload, payload_hash, risk, normalization_version, policy_version,
              catalogue_version, open_path_ids, required_assurance, status, satisfied_path_id,
              expires_at, created_at, updated_at, terminal_at
    FROM approval_requests WHERE id = :id"""
)
_SELECT_REQUEST_FOR_UPDATE = text(
    """SELECT id, tenant_id, requester_id, operation_id, action_key, target_type,
              target_id, payload, payload_hash, risk, normalization_version, policy_version,
              catalogue_version, open_path_ids, required_assurance, status, satisfied_path_id,
              expires_at, created_at, updated_at, terminal_at
    FROM approval_requests WHERE id = :id FOR UPDATE"""
)
_UPDATE_STATUS = text(
    """UPDATE approval_requests
    SET status = :status,
        satisfied_path_id = COALESCE(:satisfied_path_id, satisfied_path_id),
        terminal_at = CASE WHEN :is_terminal THEN :now ELSE terminal_at END,
        updated_at = :now
    WHERE id = :id
    RETURNING id, tenant_id, requester_id, operation_id, action_key, target_type,
              target_id, payload, payload_hash, risk, normalization_version, policy_version,
              catalogue_version, open_path_ids, required_assurance, status, satisfied_path_id,
              expires_at, created_at, updated_at, terminal_at"""
)
_INSERT_DECISION = text(
    """INSERT INTO approval_decisions (
        id, tenant_id, approval_id, actor_id, decision, payload_hash, assurance, roles,
        idempotency_key, correlation_id, created_at
    ) VALUES (
        :id, :tenant_id, :approval_id, :actor_id, :decision, :payload_hash, :assurance,
        :roles, :idempotency_key, :correlation_id, :now
    ) ON CONFLICT DO NOTHING
    RETURNING id, approval_id, tenant_id, actor_id, decision, payload_hash, assurance,
              roles, created_at"""
)
_SELECT_DECISIONS = text(
    """SELECT id, approval_id, tenant_id, actor_id, decision, payload_hash, assurance,
              roles, created_at
    FROM approval_decisions WHERE approval_id = :approval_id ORDER BY created_at, id"""
)
_INSERT_CONSUMPTION = text(
    """INSERT INTO approval_consumptions (
        id, tenant_id, approval_id, operation_id, action_key, payload_hash, result_ref,
        consumed_at
    ) VALUES (
        :id, :tenant_id, :approval_id, :operation_id, :action_key, :payload_hash,
        :result_ref, :now
    ) ON CONFLICT DO NOTHING
    RETURNING id, result_ref, consumed_at"""
)
_SELECT_CONSUMPTION = text(
    """SELECT id, result_ref, consumed_at FROM approval_consumptions
    WHERE approval_id = :approval_id"""
)
_INCREMENT_EFFECT = text(
    """INSERT INTO protected_effect_counters (tenant_id, action_key, target_id,
                                              effect_count, updated_at)
    VALUES (:tenant_id, :action_key, :target_id, 1, :now)
    ON CONFLICT (tenant_id, action_key, target_id)
    DO UPDATE SET effect_count = protected_effect_counters.effect_count + 1,
                  updated_at = :now
    RETURNING effect_count"""
)
_SELECT_EFFECT = text(
    """SELECT COALESCE(sum(effect_count), 0) FROM protected_effect_counters
    WHERE action_key = :action_key AND target_id = :target_id"""
)
_SELECT_TOTAL_EFFECT = text("SELECT COALESCE(sum(effect_count), 0) FROM protected_effect_counters")


@dataclass(frozen=True, slots=True)
class ConsumptionRecord:
    consumption_id: UUID
    result_ref: str
    consumed_at: datetime
    created: bool


def _to_request(row: RowMapping) -> ApprovalRequest:
    payload = row["payload"]
    return ApprovalRequest(
        approval_id=row["id"],
        tenant_id=row["tenant_id"],
        requester_id=row["requester_id"],
        operation_id=row["operation_id"],
        action_key=row["action_key"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        payload=payload if isinstance(payload, dict) else json.loads(payload),
        payload_hash=row["payload_hash"],
        risk=RiskLevel(row["risk"]),
        normalization_version=row["normalization_version"],
        policy_version=row["policy_version"],
        catalogue_version=row["catalogue_version"],
        open_path_ids=tuple(row["open_path_ids"]),
        required_assurance=Assurance(row["required_assurance"]),
        status=ApprovalStatus(row["status"]),
        satisfied_path_id=row["satisfied_path_id"],
        expires_at=row["expires_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        terminal_at=row["terminal_at"],
    )


def _to_decision(row: RowMapping) -> ApprovalDecisionRecord:
    return ApprovalDecisionRecord(
        decision_id=row["id"],
        approval_id=row["approval_id"],
        tenant_id=row["tenant_id"],
        actor_id=row["actor_id"],
        decision=DecisionType(row["decision"]),
        payload_hash=row["payload_hash"],
        assurance=Assurance(row["assurance"]),
        roles=tuple(row["roles"]),
        created_at=row["created_at"],
    )


@dataclass(slots=True)
class ApprovalRepository:
    sessions: sessionmaker[Session]

    # -- requests --------------------------------------------------------

    def create_or_get(
        self,
        *,
        actor: ActorContext,
        approval_id: UUID,
        request: dict[str, Any],
        now: datetime,
    ) -> tuple[ApprovalRequest, bool]:
        """Resolve one approval request for this submission identity.

        A retry returns the existing row untouched: it never resets lifecycle
        state and never creates a second pending request for the same action.
        """
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            inserted = (
                session.execute(_INSERT_REQUEST, {"id": approval_id, "now": now, **request})
                .mappings()
                .one_or_none()
            )
            if inserted is not None:
                return _to_request(inserted), True
            existing = (
                session.execute(_SELECT_REQUEST, {"id": approval_id}).mappings().one_or_none()
            )
            if existing is None:
                # A row blocked the insert but this tenant cannot see it.
                from app.approvals.errors import ApprovalNotFound

                raise ApprovalNotFound
            return _to_request(existing), False

    def load(self, *, actor: ActorContext, approval_id: UUID) -> ApprovalRequest | None:
        """Absent and foreign are indistinguishable: both return `None`."""
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            row = session.execute(_SELECT_REQUEST, {"id": approval_id}).mappings().one_or_none()
        return None if row is None else _to_request(row)

    def set_status(
        self,
        *,
        actor: ActorContext,
        approval_id: UUID,
        status: ApprovalStatus,
        now: datetime,
        satisfied_path_id: int | None = None,
    ) -> ApprovalRequest:
        from app.approvals.contracts import TERMINAL_STATUSES

        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            row = (
                session.execute(
                    _UPDATE_STATUS,
                    {
                        "id": approval_id,
                        "status": status.value,
                        "satisfied_path_id": satisfied_path_id,
                        "is_terminal": status in TERMINAL_STATUSES,
                        "now": now,
                    },
                )
                .mappings()
                .one()
            )
            return _to_request(row)

    # -- decisions -------------------------------------------------------

    def record_decision(
        self,
        *,
        actor: ActorContext,
        approval_id: UUID,
        decision: DecisionType,
        payload_hash: str,
        idempotency_key: str,
        now: datetime,
    ) -> tuple[ApprovalDecisionRecord, bool]:
        """Append one decision. A replay converges on the stored one."""
        decision_id = derive_decision_id(approval_id, actor.actor_id)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            inserted = (
                session.execute(
                    _INSERT_DECISION,
                    {
                        "id": decision_id,
                        "tenant_id": actor.tenant_id,
                        "approval_id": approval_id,
                        "actor_id": actor.actor_id,
                        "decision": decision.value,
                        "payload_hash": payload_hash,
                        "assurance": actor.assurance,
                        "roles": list(actor.roles),
                        "idempotency_key": idempotency_key,
                        "correlation_id": actor.correlation_id,
                        "now": now,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if inserted is not None:
                return _to_decision(inserted), True
            existing = [
                row
                for row in session.execute(_SELECT_DECISIONS, {"approval_id": approval_id})
                .mappings()
                .all()
                if row["actor_id"] == actor.actor_id
            ]
            if not existing:
                from app.approvals.errors import ApprovalNotAuthorized

                raise ApprovalNotAuthorized
            return _to_decision(existing[0]), False

    def decisions_for(
        self, *, actor: ActorContext, approval_id: UUID
    ) -> list[ApprovalDecisionRecord]:
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            rows = session.execute(_SELECT_DECISIONS, {"approval_id": approval_id}).mappings().all()
        return [_to_decision(row) for row in rows]

    # -- consumption and the fake protected effect -----------------------

    def consume_and_apply(
        self,
        *,
        actor: ActorContext,
        approval_id: UUID,
        operation_id: UUID | None,
        action_key: str,
        target_id: UUID,
        payload_hash: str,
        result_ref: str,
        now: datetime,
    ) -> ConsumptionRecord:
        """Write the consumption and the protected effect in one transaction.

        `ARCH-004`: the effect and the record that it happened commit together, so
        a crash between them is impossible and an unknown outcome is always
        resolvable by reading the consumption row.
        """
        consumption_id = derive_consumption_id(approval_id)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            try:
                inserted = (
                    session.execute(
                        _INSERT_CONSUMPTION,
                        {
                            "id": consumption_id,
                            "tenant_id": actor.tenant_id,
                            "approval_id": approval_id,
                            "operation_id": operation_id,
                            "action_key": action_key,
                            "payload_hash": payload_hash,
                            "result_ref": result_ref,
                            "now": now,
                        },
                    )
                    .mappings()
                    .one_or_none()
                )
            except IntegrityError:
                inserted = None
            if inserted is None:
                existing = (
                    session.execute(_SELECT_CONSUMPTION, {"approval_id": approval_id})
                    .mappings()
                    .one_or_none()
                )
                if existing is None:
                    from app.approvals.errors import ApprovalReplayed

                    raise ApprovalReplayed
                return ConsumptionRecord(
                    consumption_id=existing["id"],
                    result_ref=existing["result_ref"],
                    consumed_at=existing["consumed_at"],
                    created=False,
                )
            session.execute(
                _INCREMENT_EFFECT,
                {
                    "tenant_id": actor.tenant_id,
                    "action_key": action_key,
                    "target_id": target_id,
                    "now": now,
                },
            )
            return ConsumptionRecord(
                consumption_id=inserted["id"],
                result_ref=inserted["result_ref"],
                consumed_at=inserted["consumed_at"],
                created=True,
            )

    def consumption_for(
        self, *, actor: ActorContext, approval_id: UUID
    ) -> ConsumptionRecord | None:
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            row = (
                session.execute(_SELECT_CONSUMPTION, {"approval_id": approval_id})
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        return ConsumptionRecord(
            consumption_id=row["id"],
            result_ref=row["result_ref"],
            consumed_at=row["consumed_at"],
            created=False,
        )

    def effect_count(self, *, actor: ActorContext, action_key: str, target_id: UUID) -> int:
        """Row-level security scopes this to the caller's tenant."""
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            return int(
                session.execute(
                    _SELECT_EFFECT, {"action_key": action_key, "target_id": target_id}
                ).scalar_one()
            )

    def total_effect_count(self, *, actor: ActorContext) -> int:
        """Every protected effect visible to this tenant. Security negatives assert zero."""
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            return int(session.execute(_SELECT_TOTAL_EFFECT).scalar_one())
