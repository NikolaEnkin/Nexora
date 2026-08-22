"""Idempotency arbitration, shared by every consequential write.

This is the subtle half of `ARCH-004` and the half where defects hide, so it has
exactly one implementation. The mechanical half — which domain rows, which event
type, which audit target — differs per domain and lives with the domain.

Three behaviours are load-bearing and were learned the hard way in Phase 01
(finding F-01) and Phase 02:

* **`ON CONFLICT DO NOTHING` carries no column target.** The record id is a
  deterministic `uuid5`, so concurrent duplicates collide on the primary key *and*
  on the scoped unique index. Naming only one as arbiter leaves the other
  unhandled, and the loser of the race raises `UniqueViolation` instead of
  converging on the first durable result.
* **A different payload under the same key is a conflict, never an overwrite.**
* **An expired lease is reclaimable; a live one is not.** Without the lease a
  crashed writer would block its own key forever.

The caller runs inside an open transaction and is responsible for the domain
rows. This function only decides whether the caller may proceed, must replay, or
must be refused.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.contracts import ActorContext
from app.errors import (
    IdempotencyConflict,
    IdempotencyFinalFailure,
    IdempotencyInProgress,
)

LEASE = timedelta(minutes=5)
RETENTION = timedelta(days=7)

_INSERT = text(
    """INSERT INTO idempotency_records (
        id, tenant_id, actor_id, operation, idempotency_key, request_hash,
        contract_version, state, stored_result, stored_error, lease_expires_at,
        expires_at, created_at, updated_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :operation, :key, :request_hash,
        1, 'IN_PROGRESS', NULL, NULL, :lease_expires_at,
        :expires_at, :now, :now
    ) ON CONFLICT DO NOTHING RETURNING id"""
)
_SELECT_FOR_UPDATE = text(
    """SELECT request_hash, state, stored_result, stored_error, lease_expires_at
    FROM idempotency_records
    WHERE tenant_id = :tenant_id AND actor_id = :actor_id
      AND operation = :operation AND idempotency_key = :key
    FOR UPDATE"""
)
_RENEW_LEASE = text(
    """UPDATE idempotency_records
    SET lease_expires_at = :lease_expires_at, updated_at = :now
    WHERE id = :id AND state = 'IN_PROGRESS'"""
)
_COMPLETE = text(
    """UPDATE idempotency_records
    SET state = 'SUCCEEDED', stored_result = CAST(:result AS jsonb),
        lease_expires_at = NULL, updated_at = :now
    WHERE id = :id"""
)


@dataclass(frozen=True, slots=True)
class Claim:
    """The verdict. Exactly one of `proceed` / `replayed_result` is meaningful."""

    proceed: bool
    replayed_result: dict[str, Any] | None = None


def claim(
    session: Session,
    *,
    actor: ActorContext,
    operation: str,
    idempotency_key: str,
    request_hash: str,
    record_id: UUID,
    now: datetime,
) -> Claim:
    """Decide whether this caller owns the write, must replay, or is refused.

    Raises `IdempotencyConflict` for the same key with a different payload,
    `IdempotencyFinalFailure` for a key that already failed permanently, and
    `IdempotencyInProgress` while another writer holds a live lease.
    """
    inserted = session.execute(
        _INSERT,
        {
            "id": record_id,
            "tenant_id": actor.tenant_id,
            "actor_id": actor.actor_id,
            "operation": operation,
            "key": idempotency_key,
            "request_hash": request_hash,
            "lease_expires_at": now + LEASE,
            "expires_at": now + RETENTION,
            "now": now,
        },
    ).scalar_one_or_none()
    if inserted is not None:
        return Claim(proceed=True)

    existing = (
        session.execute(
            _SELECT_FOR_UPDATE,
            {
                "tenant_id": actor.tenant_id,
                "actor_id": actor.actor_id,
                "operation": operation,
                "key": idempotency_key,
            },
        )
        .mappings()
        .one()
    )
    if existing["request_hash"] != request_hash:
        raise IdempotencyConflict
    if existing["state"] == "SUCCEEDED" and existing["stored_result"] is not None:
        return Claim(proceed=False, replayed_result=dict(existing["stored_result"]))
    if existing["state"] == "FAILED_FINAL":
        raise IdempotencyFinalFailure

    lease_expires_at = existing["lease_expires_at"]
    if lease_expires_at is None or lease_expires_at > now:
        raise IdempotencyInProgress
    session.execute(_RENEW_LEASE, {"id": record_id, "lease_expires_at": now + LEASE, "now": now})
    return Claim(proceed=True)


def complete(session: Session, *, record_id: UUID, stored_result: str, now: datetime) -> None:
    """Mark the claim satisfied. Must run inside the same transaction as the write."""
    session.execute(_COMPLETE, {"id": record_id, "result": stored_result, "now": now})
