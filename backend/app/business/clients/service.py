"""Canonical client records.

`ARCH-004`: the client row, its domain event, the outbox entry, the idempotency
result and the audit record commit in **one** transaction. A crash between any two
of them is impossible, so an unknown outcome is always resolvable by reading the
idempotency record rather than by guessing.

`BR-04-001`: an ambiguous or missing canonical entity produces a clarification and
zero mutation. Resolution is by exact id or by exact normalized key — never by
fuzzy match, because a near-match on a client name is how an invoice ends up
addressed to the wrong company.

`BR-04-003`: the backend owns identity. The caller supplies names; the service
derives the normalized key, assigns the id and the version. A model-supplied id or
version is ignored, and there is no field for one in the tool schema.
"""

import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field
from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session, sessionmaker

from app.audit import safe_audit_metadata
from app.authz import authorize
from app.business.idempotency import claim, complete
from app.contracts import ActorContext, AuthorizationEffect
from app.contracts.foundation import FrozenContract
from app.db import set_request_context
from app.errors import ApplicationError, AuthorizationDenied
from app.events.service import canonical_json, request_hash, stable_id

CONTRACT_VERSION = 1


class ClientNotFound(ApplicationError):
    """Absent and foreign are indistinguishable, as everywhere else in this system."""

    def __init__(self) -> None:
        super().__init__(
            code="CLIENT_NOT_FOUND", message="The client was not found.", status_code=404
        )


class AmbiguousEntity(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="AMBIGUOUS_ENTITY",
            message="The reference matches more than one client.",
            status_code=409,
        )


class VersionConflict(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="VERSION_CONFLICT",
            message="The client changed since it was read.",
            status_code=409,
        )


class BusinessRuleViolation(ApplicationError):
    def __init__(self, rule: str) -> None:
        super().__init__(
            code="BUSINESS_RULE_VIOLATION",
            message="The request violates a business rule.",
            status_code=422,
            details={"rule": rule},
        )


class ClientRecord(FrozenContract):
    """`Client v1` — what a tool returns. No finance fields exist yet."""

    version: Literal["1"] = "1"
    client_id: UUID
    tenant_id: UUID
    legal_name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    normalized_key: str
    status: Literal["ACTIVE", "ARCHIVED"]
    row_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


def normalize_key(legal_name: str) -> str:
    """The canonical identity of a client name.

    Case, accents and internal whitespace are folded so that "Example  GmbH",
    "example gmbh" and "Éxample GmbH" cannot become three different clients that
    later receive three different invoices. Nothing beyond that is folded: two
    genuinely different companies keep two different keys.
    """
    folded = unicodedata.normalize("NFKD", legal_name)
    stripped = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return " ".join(stripped.casefold().split())


_SELECT_BY_ID = text(
    """SELECT id, tenant_id, legal_name, display_name, normalized_key, status,
              row_version, created_at, updated_at
    FROM clients WHERE id = :id"""
)
_SELECT_BY_KEY = text(
    """SELECT id, tenant_id, legal_name, display_name, normalized_key, status,
              row_version, created_at, updated_at
    FROM clients WHERE normalized_key = :key AND status = 'ACTIVE'"""
)
_SELECT_FOR_UPDATE = text(
    """SELECT id, tenant_id, legal_name, display_name, normalized_key, status,
              row_version, created_at, updated_at
    FROM clients WHERE id = :id FOR UPDATE"""
)
_INSERT = text(
    """INSERT INTO clients (
        id, tenant_id, legal_name, display_name, normalized_key, status, contact_ref,
        row_version, created_at, updated_at
    ) VALUES (
        :id, :tenant_id, :legal_name, :display_name, :normalized_key, 'ACTIVE',
        CAST(:contact_ref AS jsonb), 1, :now, :now
    ) ON CONFLICT DO NOTHING
    RETURNING id, tenant_id, legal_name, display_name, normalized_key, status,
              row_version, created_at, updated_at"""
)
_UPDATE = text(
    """UPDATE clients
    SET legal_name = :legal_name, display_name = :display_name,
        normalized_key = :normalized_key, status = :status,
        row_version = row_version + 1, updated_at = :now
    WHERE id = :id AND row_version = :expected_version
    RETURNING id, tenant_id, legal_name, display_name, normalized_key, status,
              row_version, created_at, updated_at"""
)
_INSERT_EVENT = text(
    """INSERT INTO domain_events (
        id, tenant_id, actor_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, event_version, occurred_at, correlation_id, causation_id,
        payload_ref, payload_hash
    ) VALUES (
        :id, :tenant_id, :actor_id, 'client', :aggregate_id, :aggregate_version,
        :event_type, 1, :now, :correlation_id, NULL, :payload_ref, :payload_hash
    ) ON CONFLICT DO NOTHING"""
)
_INSERT_OUTBOX = text(
    """INSERT INTO outbox_events (
        id, tenant_id, domain_event_id, state, attempt_count, available_at,
        claimed_at, lease_expires_at, published_at, last_error_code, created_at
    ) VALUES (:id, :tenant_id, :event_id, 'PENDING', 0, :now, NULL, NULL, NULL, NULL, :now)
    ON CONFLICT DO NOTHING"""
)
_INSERT_AUDIT = text(
    """INSERT INTO audit_events (
        id, tenant_id, actor_id, action, target_type, target_id, result, reason,
        correlation_id, metadata, contract_version, occurred_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :action, 'client', :target_id, 'SUCCEEDED',
        'AUTHORIZED', :correlation_id, CAST(:metadata AS jsonb), 1, :now
    ) ON CONFLICT DO NOTHING"""
)


def _to_record(row: RowMapping) -> ClientRecord:
    return ClientRecord(
        client_id=row["id"],
        tenant_id=row["tenant_id"],
        legal_name=row["legal_name"],
        display_name=row["display_name"],
        normalized_key=row["normalized_key"],
        status=row["status"],
        row_version=row["row_version"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@dataclass(slots=True)
class ClientService:
    sessions: sessionmaker[Session]

    # -- reads -----------------------------------------------------------

    def get(
        self, *, actor: ActorContext, client_id: UUID | None = None, legal_name: str | None = None
    ) -> ClientRecord:
        """Resolve by exact id or exact normalized key. Never both, never neither."""
        self._require(actor, "client.read")
        if (client_id is None) == (legal_name is None):
            raise BusinessRuleViolation("exactly one of client_id or legal_name is required")

        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            if client_id is not None:
                row = session.execute(_SELECT_BY_ID, {"id": client_id}).mappings().one_or_none()
            else:
                rows = (
                    session.execute(_SELECT_BY_KEY, {"key": normalize_key(legal_name or "")})
                    .mappings()
                    .all()
                )
                if len(rows) > 1:
                    # The partial unique index makes this unreachable today. It is
                    # checked anyway, because BR-04-001 must hold even if a future
                    # revision relaxes that index.
                    raise AmbiguousEntity
                row = rows[0] if rows else None
        if row is None:
            raise ClientNotFound
        return _to_record(row)

    # -- writes ----------------------------------------------------------

    def create(
        self,
        *,
        actor: ActorContext,
        legal_name: str,
        display_name: str,
        idempotency_key: str,
        now: datetime,
        contact_ref: dict[str, Any] | None = None,
    ) -> tuple[ClientRecord, bool]:
        """Create a client, or return the one this submission already created."""
        self._require(actor, "client.write")
        key = normalize_key(legal_name)
        if not key:
            raise BusinessRuleViolation("legal_name must contain a usable identity")

        arguments = {
            "legal_name": legal_name,
            "display_name": display_name,
            "normalized_key": key,
        }
        return self._mutate(
            actor=actor,
            operation="client_create",
            idempotency_key=idempotency_key,
            arguments=arguments,
            event_type="client.created",
            now=now,
            write=lambda session, client_id: (
                session.execute(
                    _INSERT,
                    {
                        "id": client_id,
                        "tenant_id": actor.tenant_id,
                        "legal_name": legal_name,
                        "display_name": display_name,
                        "normalized_key": key,
                        "contact_ref": canonical_json(contact_ref or {}),
                        "now": now,
                    },
                )
                .mappings()
                .one_or_none()
            ),
            aggregate_version=1,
        )

    def update(
        self,
        *,
        actor: ActorContext,
        client_id: UUID,
        expected_version: int,
        idempotency_key: str,
        now: datetime,
        legal_name: str | None = None,
        display_name: str | None = None,
        status: str | None = None,
    ) -> tuple[ClientRecord, bool]:
        """Patch a client under an optimistic version check (`BR-04-004`)."""
        self._require(actor, "client.write")
        current = self.get(actor=actor, client_id=client_id)
        if current.row_version != expected_version:
            raise VersionConflict

        next_legal = legal_name if legal_name is not None else current.legal_name
        next_display = display_name if display_name is not None else current.display_name
        next_status = status if status is not None else current.status
        if next_status not in ("ACTIVE", "ARCHIVED"):
            raise BusinessRuleViolation("status must be ACTIVE or ARCHIVED")
        next_key = normalize_key(next_legal)
        if not next_key:
            raise BusinessRuleViolation("legal_name must contain a usable identity")

        arguments = {
            "client_id": str(client_id),
            "expected_version": expected_version,
            "legal_name": next_legal,
            "display_name": next_display,
            "status": next_status,
        }

        def write(session: Session, _derived_id: UUID) -> RowMapping | None:
            locked = session.execute(_SELECT_FOR_UPDATE, {"id": client_id}).mappings().one_or_none()
            if locked is None:
                raise ClientNotFound
            if locked["row_version"] != expected_version:
                raise VersionConflict
            return (
                session.execute(
                    _UPDATE,
                    {
                        "id": client_id,
                        "legal_name": next_legal,
                        "display_name": next_display,
                        "normalized_key": next_key,
                        "status": next_status,
                        "expected_version": expected_version,
                        "now": now,
                    },
                )
                .mappings()
                .one_or_none()
            )

        return self._mutate(
            actor=actor,
            operation="client_update",
            idempotency_key=idempotency_key,
            arguments=arguments,
            event_type="client.updated",
            now=now,
            write=write,
            aggregate_version=expected_version + 1,
            target_id=client_id,
        )

    # -- internals -------------------------------------------------------

    def _require(self, actor: ActorContext, permission: str) -> None:
        decision = authorize(
            actor, permission, object_tenant_id=actor.tenant_id, object_scope="client"
        )
        if decision.effect is not AuthorizationEffect.ALLOW:
            raise AuthorizationDenied

    def _mutate(
        self,
        *,
        actor: ActorContext,
        operation: str,
        idempotency_key: str,
        arguments: dict[str, Any],
        event_type: str,
        now: datetime,
        write: Any,
        aggregate_version: int,
        target_id: UUID | None = None,
    ) -> tuple[ClientRecord, bool]:
        """One transaction: domain row, event, outbox, idempotency and audit."""
        normalized_hash = request_hash(str(CONTRACT_VERSION), arguments)
        record_id = stable_id("idempotency", actor, operation, idempotency_key)
        # Derived from the *submission*, not from the name. Deriving it from the
        # normalized key would tie an id to a name forever, so a client archived
        # today could never be recreated under the same name tomorrow: the derived
        # id would collide with the archived row's primary key.
        client_id = target_id or stable_id("client", actor, operation, idempotency_key)
        event_id = stable_id("event", actor, operation, idempotency_key)
        outbox_id = stable_id("outbox", actor, operation, idempotency_key)
        audit_id = stable_id("audit", actor, operation, idempotency_key)

        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            verdict = claim(
                session,
                actor=actor,
                operation=operation,
                idempotency_key=idempotency_key,
                request_hash=normalized_hash,
                record_id=record_id,
                now=now,
            )
            if not verdict.proceed:
                stored = verdict.replayed_result or {}
                replayed_id = UUID(str(stored["client_id"]))
                row = session.execute(_SELECT_BY_ID, {"id": replayed_id}).mappings().one()
                return _to_record(row), True

            row = write(session, client_id)
            if row is None:
                # The insert lost a uniqueness race, or the update matched no row.
                raise BusinessRuleViolation("a client with this identity already exists")
            record = _to_record(row)

            session.execute(
                _INSERT_EVENT,
                {
                    "id": event_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "aggregate_id": record.client_id,
                    "aggregate_version": aggregate_version,
                    "event_type": event_type,
                    "now": now,
                    "correlation_id": actor.correlation_id,
                    "payload_ref": f"clients/{record.client_id}",
                    "payload_hash": normalized_hash,
                },
            )
            session.execute(
                _INSERT_OUTBOX,
                {
                    "id": outbox_id,
                    "tenant_id": actor.tenant_id,
                    "event_id": event_id,
                    "now": now,
                },
            )
            session.execute(
                _INSERT_AUDIT,
                {
                    "id": audit_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "action": operation,
                    "target_id": record.client_id,
                    "correlation_id": actor.correlation_id,
                    "metadata": canonical_json(
                        safe_audit_metadata(
                            {
                                "operation": operation,
                                "request_hash": normalized_hash,
                                "event_id": str(event_id),
                                "idempotency_record_id": str(record_id),
                                "outcome": "SUCCEEDED",
                            }
                        )
                    ),
                    "now": now,
                },
            )
            complete(
                session,
                record_id=record_id,
                stored_result=canonical_json(
                    {"client_id": str(record.client_id), "row_version": record.row_version}
                ),
                now=now,
            )
        return record, False
