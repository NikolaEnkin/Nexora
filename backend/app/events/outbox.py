import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid5

import structlog
from sqlalchemy import text
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.authz import authorize
from app.contracts import ActorContext, AuthorizationEffect
from app.errors import AuthorizationDenied

OUTBOX_RECOVERY_NAMESPACE = UUID("71000000-0000-0000-0000-000000000001")


@dataclass(frozen=True, slots=True)
class ClaimedOutboxEvent:
    id: UUID
    domain_event_id: UUID
    attempt_count: int


@dataclass(frozen=True, slots=True)
class OutboxBacklogSnapshot:
    pending_count: int
    oldest_age_seconds: float


def log_backlog_snapshot(session: Session, *, now: datetime) -> OutboxBacklogSnapshot:
    row = (
        session.execute(
            text(
                """SELECT count(*) AS pending_count, min(available_at) AS oldest_available_at,
            current_setting('app.tenant_id', true) AS tenant_id
            FROM outbox_events WHERE state = 'PENDING'"""
            )
        )
        .mappings()
        .one()
    )
    oldest = row["oldest_available_at"]
    age = 0.0 if oldest is None else max(0.0, (now - oldest).total_seconds())
    snapshot = OutboxBacklogSnapshot(pending_count=row["pending_count"], oldest_age_seconds=age)
    structlog.get_logger("outbox").info(
        "outbox_backlog",
        tenant_id=row["tenant_id"],
        pending_count=snapshot.pending_count,
        oldest_age_seconds=snapshot.oldest_age_seconds,
    )
    return snapshot


def claim_next(session: Session, *, now: datetime, lease: timedelta) -> ClaimedOutboxEvent | None:
    log_backlog_snapshot(session, now=now)
    row = (
        session.execute(
            text(
                """WITH candidate AS (
                SELECT id FROM outbox_events
                WHERE (state = 'PENDING' AND available_at <= :now)
                   OR (state = 'CLAIMED' AND lease_expires_at <= :now)
                ORDER BY available_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE outbox_events AS outbox
            SET state = 'CLAIMED', claimed_at = :now, lease_expires_at = :lease_expires,
                attempt_count = attempt_count + 1
            FROM candidate
            WHERE outbox.id = candidate.id
            RETURNING outbox.id, outbox.domain_event_id, outbox.attempt_count"""
            ),
            {"now": now, "lease_expires": now + lease},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    structlog.get_logger("outbox").info(
        "outbox_claimed",
        outbox_event_id=str(row["id"]),
        domain_event_id=str(row["domain_event_id"]),
        attempt_count=row["attempt_count"],
        outcome="CLAIMED",
    )
    return ClaimedOutboxEvent(
        id=row["id"], domain_event_id=row["domain_event_id"], attempt_count=row["attempt_count"]
    )


def mark_published(session: Session, *, event_id: UUID, now: datetime) -> bool:
    updated = cast(
        CursorResult[Any],
        session.execute(
            text(
                """UPDATE outbox_events SET state = 'PUBLISHED', published_at = :now,
                lease_expires_at = NULL, last_error_code = NULL
                WHERE id = :id AND state = 'CLAIMED'"""
            ),
            {"id": event_id, "now": now},
        ),
    )
    return updated.rowcount == 1


def mark_failed(session: Session, *, event_id: UUID, error_code: str) -> bool:
    updated = cast(
        CursorResult[Any],
        session.execute(
            text(
                """UPDATE outbox_events SET state = 'FAILED', lease_expires_at = NULL,
                last_error_code = :error_code WHERE id = :id AND state = 'CLAIMED'"""
            ),
            {"id": event_id, "error_code": error_code},
        ),
    )
    return updated.rowcount == 1


def recover_failed(session: Session, *, event_id: UUID, actor: ActorContext, now: datetime) -> bool:
    decision = authorize(
        actor,
        "tenant.manage",
        object_tenant_id=actor.tenant_id,
        object_scope="outbox_recovery",
    )
    if decision.effect is not AuthorizationEffect.ALLOW:
        raise AuthorizationDenied
    failed_row = (
        session.execute(
            text(
                """SELECT domain_event_id, attempt_count FROM outbox_events
                WHERE id = :id AND state = 'FAILED' FOR UPDATE"""
            ),
            {"id": event_id},
        )
        .mappings()
        .one_or_none()
    )
    if failed_row is None:
        return False
    audit_id = uuid5(OUTBOX_RECOVERY_NAMESPACE, f"{actor.tenant_id}:{event_id}:{now.isoformat()}")
    session.execute(
        text(
            """INSERT INTO audit_events (
            id, tenant_id, actor_id, action, target_type, target_id, result, reason,
            correlation_id, metadata, contract_version, occurred_at)
            VALUES (:id, :tenant, :actor, 'outbox.recover', 'outbox_event', :target,
            'SUCCEEDED', 'OPERATOR_RECOVERY', :correlation, CAST(:metadata AS jsonb), 1, :now)"""
        ),
        {
            "id": audit_id,
            "tenant": actor.tenant_id,
            "actor": actor.actor_id,
            "target": event_id,
            "correlation": actor.correlation_id,
            "metadata": json.dumps(
                {
                    "attempt_count": failed_row["attempt_count"],
                    "domain_event_id": str(failed_row["domain_event_id"]),
                }
            ),
            "now": now,
        },
    )
    session.execute(
        text(
            """UPDATE outbox_events SET state = 'PENDING', available_at = :now,
            claimed_at = NULL, lease_expires_at = NULL, last_error_code = NULL
            WHERE id = :id AND state = 'FAILED'"""
        ),
        {"id": event_id, "now": now},
    )
    structlog.get_logger("outbox").info(
        "outbox_recovered",
        tenant_id=str(actor.tenant_id),
        actor_id=str(actor.actor_id),
        outbox_event_id=str(event_id),
        audit_event_id=str(audit_id),
        correlation_id=str(actor.correlation_id),
        outcome="PENDING",
    )
    return True
