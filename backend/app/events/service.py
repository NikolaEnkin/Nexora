import hashlib
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid5

import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.audit import safe_audit_metadata
from app.authz import authorize
from app.contracts import ActorContext, AuthorizationEffect
from app.db import set_request_context
from app.errors import (
    AuthorizationDenied,
    IdempotencyConflict,
    IdempotencyFinalFailure,
    IdempotencyInProgress,
)

FOUNDATION_NAMESPACE = UUID("70000000-0000-0000-0000-000000000001")


MAX_SAFE_INTEGER = 2**53 - 1


def _normalize_json(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer is outside the cross-runtime safe range")
        return value
    if isinstance(value, float):
        raise ValueError("floating-point arguments require a domain string representation")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError("JSON object keys must be ASCII strings")
            normalized[key] = _normalize_json(item)
        return normalized
    raise ValueError(f"unsupported JSON argument type: {type(value).__name__}")


def canonical_json(payload: dict[str, Any]) -> str:
    normalized = _normalize_json(payload)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_hash(contract_version: str, arguments: dict[str, Any]) -> str:
    canonical = canonical_json({"arguments": arguments, "version": contract_version})
    return hashlib.sha256(canonical.encode()).hexdigest()


def stable_id(kind: str, actor: ActorContext, operation: str, key: str) -> UUID:
    value = f"{kind}:{actor.tenant_id}:{actor.actor_id}:{operation}:{key}"
    return uuid5(FOUNDATION_NAMESPACE, value)


@dataclass(frozen=True, slots=True)
class MutationResult:
    operation_id: UUID
    event_id: UUID
    result: dict[str, Any]
    replayed: bool


class InjectedFailure(RuntimeError):
    pass


@dataclass(slots=True)
class FoundationMutationService:
    sessions: sessionmaker[Session]

    def execute(
        self,
        *,
        actor: ActorContext,
        operation: str,
        idempotency_key: str,
        arguments: dict[str, Any],
        now: datetime,
        fail_before_commit: bool = False,
        secret_values: tuple[str, ...] = (),
    ) -> MutationResult:
        logger = structlog.get_logger("foundation-mutation")
        decision = authorize(
            actor,
            "tenant.manage",
            object_tenant_id=actor.tenant_id,
            object_scope="foundation_mutation",
        )
        if decision.effect is not AuthorizationEffect.ALLOW:
            raise AuthorizationDenied

        normalized_hash = request_hash("1", arguments)
        record_id = stable_id("idempotency", actor, operation, idempotency_key)
        operation_id = stable_id("mutation", actor, operation, idempotency_key)
        event_id = stable_id("event", actor, operation, idempotency_key)
        outbox_id = stable_id("outbox", actor, operation, idempotency_key)
        audit_id = stable_id("audit", actor, operation, idempotency_key)

        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            # ON CONFLICT carries no column target on purpose. `record_id` is a
            # deterministic uuid5, so concurrent duplicates collide on the primary
            # key as well as on the scoped-key unique index. Naming only the scoped
            # key as arbiter leaves the primary-key collision unhandled, and the
            # loser of the race raises UniqueViolation instead of converging on the
            # first durable result (BR-01-003).
            inserted = session.execute(
                text(
                    """INSERT INTO idempotency_records (
                        id, tenant_id, actor_id, operation, idempotency_key, request_hash,
                        contract_version, state, stored_result, stored_error, lease_expires_at,
                        expires_at, created_at, updated_at
                    ) VALUES (
                        :id, :tenant_id, :actor_id, :operation, :key, :request_hash,
                        1, 'IN_PROGRESS', NULL, NULL, :lease_expires_at,
                        :expires_at, :now, :now
                    ) ON CONFLICT DO NOTHING RETURNING id"""
                ),
                {
                    "id": record_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "operation": operation,
                    "key": idempotency_key,
                    "request_hash": normalized_hash,
                    "lease_expires_at": now + timedelta(minutes=5),
                    "expires_at": now + timedelta(days=7),
                    "now": now,
                },
            ).scalar_one_or_none()

            if inserted is None:
                existing = (
                    session.execute(
                        text(
                            """SELECT request_hash, state, stored_result, stored_error,
                                   lease_expires_at
                        FROM idempotency_records
                        WHERE tenant_id = :tenant_id AND actor_id = :actor_id
                          AND operation = :operation AND idempotency_key = :key
                        FOR UPDATE"""
                        ),
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
                if existing["request_hash"] != normalized_hash:
                    logger.info(
                        "idempotency_conflict",
                        tenant_id=str(actor.tenant_id),
                        actor_id=str(actor.actor_id),
                        operation=operation,
                        correlation_id=str(actor.correlation_id),
                        outcome="CONFLICT",
                    )
                    raise IdempotencyConflict
                if existing["state"] == "SUCCEEDED" and existing["stored_result"] is not None:
                    stored = dict(existing["stored_result"])
                    replay = MutationResult(
                        operation_id=UUID(stored["operation_id"]),
                        event_id=UUID(stored["event_id"]),
                        result=dict(stored["result"]),
                        replayed=True,
                    )
                    logger.info(
                        "foundation_mutation",
                        tenant_id=str(actor.tenant_id),
                        actor_id=str(actor.actor_id),
                        operation=operation,
                        correlation_id=str(actor.correlation_id),
                        audit_event_id=str(audit_id),
                        outcome="REPLAYED",
                    )
                    return replay
                if existing["state"] == "FAILED_FINAL":
                    raise IdempotencyFinalFailure
                lease_expires_at = existing["lease_expires_at"]
                if lease_expires_at is None or lease_expires_at > now:
                    raise IdempotencyInProgress
                session.execute(
                    text(
                        """UPDATE idempotency_records
                        SET lease_expires_at = :lease_expires_at, updated_at = :now
                        WHERE id = :id AND state = 'IN_PROGRESS'"""
                    ),
                    {"id": record_id, "lease_expires_at": now + timedelta(minutes=5), "now": now},
                )

            stored_result: dict[str, Any] = {
                "operation_id": str(operation_id),
                "event_id": str(event_id),
                "result": {"accepted": True, "payload_hash": normalized_hash},
            }
            session.execute(
                text(
                    """INSERT INTO foundation_mutations
                    (id, tenant_id, actor_id, operation, payload_hash, result, created_at)
                    VALUES (:id, :tenant_id, :actor_id, :operation, :payload_hash,
                            CAST(:result AS jsonb), :now)"""
                ),
                {
                    "id": operation_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "operation": operation,
                    "payload_hash": normalized_hash,
                    "result": canonical_json(stored_result["result"]),
                    "now": now,
                },
            )
            session.execute(
                text(
                    """INSERT INTO domain_events (
                        id, tenant_id, actor_id, aggregate_type, aggregate_id, aggregate_version,
                        event_type, event_version, occurred_at, correlation_id, causation_id,
                        payload_ref, payload_hash
                    ) VALUES (
                        :id, :tenant_id, :actor_id, 'foundation_mutation', :aggregate_id, 1,
                        'foundation.mutation.recorded', 1, :now, :correlation_id, NULL,
                        :payload_ref, :payload_hash
                    )"""
                ),
                {
                    "id": event_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "aggregate_id": operation_id,
                    "now": now,
                    "correlation_id": actor.correlation_id,
                    "payload_ref": f"foundation_mutations/{operation_id}",
                    "payload_hash": normalized_hash,
                },
            )
            session.execute(
                text(
                    """INSERT INTO outbox_events (
                        id, tenant_id, domain_event_id, state, attempt_count, available_at,
                        claimed_at, lease_expires_at, published_at, last_error_code, created_at
                    ) VALUES (
                        :id, :tenant_id, :event_id, 'PENDING', 0, :now,
                        NULL, NULL, NULL, NULL, :now
                    )"""
                ),
                {"id": outbox_id, "tenant_id": actor.tenant_id, "event_id": event_id, "now": now},
            )
            audit_metadata = safe_audit_metadata(
                {
                    "operation": operation,
                    "request_hash": normalized_hash,
                    "event_id": str(event_id),
                    "idempotency_record_id": str(record_id),
                    "outcome": "SUCCEEDED",
                    "raw_request": arguments,
                },
                secret_values=secret_values,
            )
            session.execute(
                text(
                    """INSERT INTO audit_events (
                        id, tenant_id, actor_id, action, target_type, target_id, result, reason,
                        correlation_id, metadata, contract_version, occurred_at
                    ) VALUES (
                        :id, :tenant_id, :actor_id, :action, 'foundation_mutation', :target_id,
                        'SUCCEEDED', 'AUTHORIZED', :correlation_id,
                        CAST(:metadata AS jsonb), 1, :now
                    )"""
                ),
                {
                    "id": audit_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "action": operation,
                    "target_id": operation_id,
                    "correlation_id": actor.correlation_id,
                    "metadata": canonical_json(audit_metadata),
                    "now": now,
                },
            )
            session.execute(
                text(
                    """UPDATE idempotency_records
                    SET state = 'SUCCEEDED', stored_result = CAST(:result AS jsonb),
                        lease_expires_at = NULL, updated_at = :now
                    WHERE id = :id"""
                ),
                {"id": record_id, "result": canonical_json(stored_result), "now": now},
            )
            if fail_before_commit:
                raise InjectedFailure("injected failure before transaction commit")

        result = MutationResult(
            operation_id=operation_id,
            event_id=event_id,
            result=dict(stored_result["result"]),
            replayed=False,
        )
        logger.info(
            "foundation_mutation",
            tenant_id=str(actor.tenant_id),
            actor_id=str(actor.actor_id),
            operation=operation,
            correlation_id=str(actor.correlation_id),
            audit_event_id=str(audit_id),
            outcome="SUCCEEDED",
        )
        return result
