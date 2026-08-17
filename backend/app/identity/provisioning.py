import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid5

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.db import set_request_context
from app.errors import IdempotencyConflict
from app.events.service import request_hash

PROVISIONING_NAMESPACE = UUID("80000000-0000-0000-0000-000000000001")
ROLE_PERMISSIONS = {
    "OWNER": ("tenant.read", "tenant.manage", "membership.read", "membership.manage", "audit.read"),
    "OPERATOR": ("tenant.read", "membership.read"),
    "VIEWER": ("tenant.read", "membership.read"),
}


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    tenant_id: UUID
    owner_id: UUID
    operation_id: UUID
    event_id: UUID
    replayed: bool


@dataclass(slots=True)
class TenantProvisioner:
    migration_sessions: sessionmaker[Session]
    context_secret: str
    enabled: bool = False

    def provision(
        self,
        *,
        tenant_id: UUID,
        slug: str,
        owner_id: UUID,
        owner_subject: str,
        owner_label: str,
        correlation_id: UUID,
        idempotency_key: str,
        now: datetime,
    ) -> ProvisioningResult:
        if not self.enabled:
            raise RuntimeError("controlled tenant provisioning is disabled")
        role_ids = {
            name: uuid5(PROVISIONING_NAMESPACE, f"{tenant_id}:{name}") for name in ROLE_PERMISSIONS
        }
        request_arguments = {
            "owner_id": str(owner_id),
            "owner_label": owner_label,
            "owner_subject": owner_subject,
            "slug": slug,
            "tenant_id": str(tenant_id),
        }
        payload_hash = request_hash("1", request_arguments)
        record_id = uuid5(PROVISIONING_NAMESPACE, f"idempotency:{tenant_id}:{idempotency_key}")
        operation_id = uuid5(PROVISIONING_NAMESPACE, f"operation:{tenant_id}:{idempotency_key}")
        event_id = uuid5(PROVISIONING_NAMESPACE, f"event:{tenant_id}:{idempotency_key}")
        outbox_id = uuid5(PROVISIONING_NAMESPACE, f"outbox:{tenant_id}:{idempotency_key}")
        audit_id = uuid5(PROVISIONING_NAMESPACE, f"audit:{tenant_id}:{idempotency_key}")
        with self.migration_sessions() as session, session.begin():
            set_request_context(session, tenant_id, owner_id, context_secret=self.context_secret)
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"tenant.provision:{tenant_id}:{idempotency_key}"},
            )
            existing = (
                session.execute(
                    text(
                        """SELECT request_hash, state FROM idempotency_records
                        WHERE id = :id FOR UPDATE"""
                    ),
                    {"id": record_id},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                if existing["request_hash"] != payload_hash:
                    raise IdempotencyConflict
                if existing["state"] != "SUCCEEDED":
                    raise RuntimeError("tenant provisioning is already in progress")
                return ProvisioningResult(
                    tenant_id=tenant_id,
                    owner_id=owner_id,
                    operation_id=operation_id,
                    event_id=event_id,
                    replayed=True,
                )
            session.execute(
                text(
                    """INSERT INTO tenants (id, slug, status, created_at, updated_at)
                    VALUES (:id, :slug, 'ACTIVE', :now, :now)"""
                ),
                {"id": tenant_id, "slug": slug, "now": now},
            )
            session.execute(
                text(
                    """INSERT INTO users
                    (id, tenant_id, external_subject, display_label, status, created_at, updated_at)
                    VALUES (:id, :tenant_id, :subject, :label, 'ACTIVE', :now, :now)"""
                ),
                {
                    "id": owner_id,
                    "tenant_id": tenant_id,
                    "subject": owner_subject,
                    "label": owner_label,
                    "now": now,
                },
            )
            for name, permissions in ROLE_PERMISSIONS.items():
                session.execute(
                    text(
                        """INSERT INTO roles
                        (id, tenant_id, name, description, created_at, updated_at)
                        VALUES (:id, :tenant_id, :name, :description, :now, :now)"""
                    ),
                    {
                        "id": role_ids[name],
                        "tenant_id": tenant_id,
                        "name": name,
                        "description": f"Foundation {name} role",
                        "now": now,
                    },
                )
                for permission in permissions:
                    session.execute(
                        text(
                            """INSERT INTO role_permissions
                            (tenant_id, role_id, permission_id, granted_by, granted_at)
                            SELECT :tenant_id, :role_id, id, :owner_id, :now
                            FROM permissions WHERE permission_key = :permission"""
                        ),
                        {
                            "tenant_id": tenant_id,
                            "role_id": role_ids[name],
                            "owner_id": owner_id,
                            "now": now,
                            "permission": permission,
                        },
                    )
            session.execute(
                text(
                    """INSERT INTO user_roles
                    (tenant_id, user_id, role_id, granted_by, granted_at)
                    VALUES (:tenant_id, :owner_id, :role_id, :owner_id, :now)"""
                ),
                {
                    "tenant_id": tenant_id,
                    "owner_id": owner_id,
                    "role_id": role_ids["OWNER"],
                    "now": now,
                },
            )
            session.execute(
                text(
                    """INSERT INTO idempotency_records (
                    id, tenant_id, actor_id, operation, idempotency_key, request_hash,
                    contract_version, state, stored_result, stored_error, lease_expires_at,
                    expires_at, created_at, updated_at)
                    VALUES (:id, :tenant, :actor, 'tenant.provision', :key, :hash, 1,
                    'IN_PROGRESS', NULL, NULL, :lease, :expires, :now, :now)"""
                ),
                {
                    "id": record_id,
                    "tenant": tenant_id,
                    "actor": owner_id,
                    "key": idempotency_key,
                    "hash": payload_hash,
                    "lease": now + timedelta(minutes=5),
                    "expires": now + timedelta(days=7),
                    "now": now,
                },
            )
            stored_result = {
                "event_id": str(event_id),
                "operation_id": str(operation_id),
                "result": {"owner_id": str(owner_id), "tenant_id": str(tenant_id)},
            }
            session.execute(
                text(
                    """INSERT INTO foundation_mutations
                    (id, tenant_id, actor_id, operation, payload_hash, result, created_at)
                    VALUES (:id, :tenant, :actor, 'tenant.provision', :hash,
                            CAST(:result AS jsonb), :now)"""
                ),
                {
                    "id": operation_id,
                    "tenant": tenant_id,
                    "actor": owner_id,
                    "hash": payload_hash,
                    "result": json.dumps(stored_result["result"], sort_keys=True),
                    "now": now,
                },
            )
            session.execute(
                text(
                    """INSERT INTO domain_events (
                    id, tenant_id, actor_id, aggregate_type, aggregate_id, aggregate_version,
                    event_type, event_version, occurred_at, correlation_id, causation_id,
                    payload_ref, payload_hash)
                    VALUES (:id, :tenant, :actor, 'tenant', :tenant, 1,
                    'tenant.provisioned', 1, :now, :correlation, NULL, :payload_ref, :hash)"""
                ),
                {
                    "id": event_id,
                    "tenant": tenant_id,
                    "actor": owner_id,
                    "now": now,
                    "correlation": correlation_id,
                    "payload_ref": f"tenants/{tenant_id}",
                    "hash": payload_hash,
                },
            )
            session.execute(
                text(
                    """INSERT INTO outbox_events (
                    id, tenant_id, domain_event_id, state, attempt_count, available_at,
                    claimed_at, lease_expires_at, published_at, last_error_code, created_at)
                    VALUES (:id, :tenant, :event, 'PENDING', 0, :now,
                    NULL, NULL, NULL, NULL, :now)"""
                ),
                {"id": outbox_id, "tenant": tenant_id, "event": event_id, "now": now},
            )
            session.execute(
                text(
                    """INSERT INTO audit_events (
                    id, tenant_id, actor_id, action, target_type, target_id, result, reason,
                    correlation_id, metadata, contract_version, occurred_at)
                    VALUES (:id, :tenant, :actor, 'tenant.provision', 'tenant', :tenant,
                    'SUCCEEDED', 'CONTROLLED_BOOTSTRAP', :correlation,
                    CAST(:metadata AS jsonb), 1, :now)"""
                ),
                {
                    "id": audit_id,
                    "tenant": tenant_id,
                    "actor": owner_id,
                    "correlation": correlation_id,
                    "metadata": json.dumps(
                        {
                            "idempotency_record_id": str(record_id),
                            "payload_hash": payload_hash,
                        },
                        sort_keys=True,
                    ),
                    "now": now,
                },
            )
            session.execute(
                text(
                    """UPDATE idempotency_records SET state = 'SUCCEEDED',
                    stored_result = CAST(:result AS jsonb), lease_expires_at = NULL,
                    updated_at = :now WHERE id = :id"""
                ),
                {"id": record_id, "result": json.dumps(stored_result), "now": now},
            )
        return ProvisioningResult(
            tenant_id=tenant_id,
            owner_id=owner_id,
            operation_id=operation_id,
            event_id=event_id,
            replayed=False,
        )
