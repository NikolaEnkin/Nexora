"""Approval audit evidence.

Every policy denial, decision, invalidation, expiry and consumption leaves a row.
The metadata passes through the Phase-01 allowlist, so a payload, a rendered
approval text or an amount cannot reach `audit_events` even if a caller puts one
in the mapping: unlisted keys are dropped rather than redacted, which fails closed
for keys nobody thought to name.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.approvals.identity import APPROVAL_NAMESPACE
from app.audit.redaction import safe_audit_metadata
from app.contracts import ActorContext
from app.db import set_request_context
from app.events.service import canonical_json

_INSERT_AUDIT = text(
    """INSERT INTO audit_events (
        id, tenant_id, actor_id, action, target_type, target_id, result, reason,
        correlation_id, metadata, contract_version, occurred_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :action, :target_type, :target_id, :result, :reason,
        :correlation_id, CAST(:metadata AS jsonb), 1, :now
    ) ON CONFLICT DO NOTHING"""
)


@dataclass(slots=True)
class ApprovalAuditLog:
    sessions: sessionmaker[Session]

    def record(
        self,
        *,
        actor: ActorContext,
        action: str,
        target_id: UUID,
        result: str,
        reason: str,
        metadata: dict[str, Any],
        now: datetime,
        session: Session | None = None,
    ) -> None:
        parameters = {
            "id": uuid5(
                APPROVAL_NAMESPACE, f"audit:{actor.tenant_id}:{target_id}:{action}:{result}:{now}"
            ),
            "tenant_id": actor.tenant_id,
            "actor_id": actor.actor_id,
            "action": action,
            "target_type": "approval",
            "target_id": target_id,
            "result": result,
            "reason": reason,
            "correlation_id": actor.correlation_id,
            "metadata": canonical_json(safe_audit_metadata(metadata)),
            "now": now,
        }
        if session is not None:
            session.execute(_INSERT_AUDIT, parameters)
            return
        with self.sessions() as owned, owned.begin():
            set_request_context(owned, actor.tenant_id, actor.actor_id)
            owned.execute(_INSERT_AUDIT, parameters)
