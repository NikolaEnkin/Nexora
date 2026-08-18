"""Create Phase-01 authoritative foundation.

Revision ID: 0001_foundation
Revises: None
Create Date: 2026-08-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.config import get_migration_settings

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def _timestamps() -> list[sa.Column[object]]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def _enable_rls(
    table: str, tenant_column: str = "tenant_id", extra_predicate: str = "true"
) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'''CREATE POLICY "tenant_isolation_{table}" ON "{table}"
        USING (nexora_context_allows({tenant_column}) AND ({extra_predicate}))
        WITH CHECK (nexora_context_allows({tenant_column}) AND ({extra_predicate}))'''
    )


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.create_table(
        "tenants",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("status IN ('ACTIVE', 'SUSPENDED')", name="ck_tenants_status"),
    )
    op.create_index("ix_tenants_tenant_id", "tenants", ["id"])

    op.create_table(
        "users",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("external_subject", sa.String(255), nullable=False),
        sa.Column("display_label", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_users_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "external_subject", name="uq_users_tenant_subject"),
        sa.CheckConstraint("status IN ('ACTIVE', 'INVITED', 'REVOKED')", name="ck_users_status"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    op.create_table(
        "permissions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("permission_key", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("contract_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("contract_version = 1", name="ck_permissions_contract_version"),
    )

    op.create_table(
        "roles",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(30), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_roles_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
        sa.CheckConstraint("name IN ('OWNER', 'OPERATOR', 'VIEWER')", name="ck_roles_name"),
    )
    op.create_index("ix_roles_tenant_id", "roles", ["tenant_id"])

    op.create_table(
        "user_roles",
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("role_id", UUID, nullable=False),
        sa.Column("granted_by", UUID, nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"], ["users.tenant_id", "users.id"], name="fk_user_roles_user"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"], ["roles.tenant_id", "roles.id"], name="fk_user_roles_role"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "granted_by"],
            ["users.tenant_id", "users.id"],
            name="fk_user_roles_grantor",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "user_id", "role_id"),
    )
    op.create_index("ix_user_roles_tenant_id", "user_roles", ["tenant_id"])

    op.create_table(
        "role_permissions",
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("role_id", UUID, nullable=False),
        sa.Column("permission_id", UUID, sa.ForeignKey("permissions.id"), nullable=False),
        sa.Column("granted_by", UUID, nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"],
            ["roles.tenant_id", "roles.id"],
            name="fk_role_permissions_role",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "granted_by"],
            ["users.tenant_id", "users.id"],
            name="fk_role_permissions_grantor",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "role_id", "permission_id"),
    )
    op.create_index("ix_role_permissions_tenant_id", "role_permissions", ["tenant_id"])

    op.create_table(
        "auth_sessions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"], ["users.tenant_id", "users.id"], name="fk_auth_sessions_user"
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'REVOKED', 'EXPIRED')", name="ck_auth_sessions_status"
        ),
        sa.CheckConstraint(
            "idle_expires_at <= absolute_expires_at", name="ck_auth_sessions_expiry"
        ),
    )
    op.create_index("ix_auth_sessions_tenant_id", "auth_sessions", ["tenant_id"])
    op.create_index(
        "ix_auth_sessions_user_status", "auth_sessions", ["tenant_id", "user_id", "status"]
    )

    op.create_table(
        "foundation_mutations",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, nullable=False),
        sa.Column("operation", sa.String(100), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("result", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["users.tenant_id", "users.id"],
            name="fk_foundation_mutations_actor",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_foundation_mutations_tenant_id_id"),
    )
    op.create_index("ix_foundation_mutations_tenant_id", "foundation_mutations", ["tenant_id"])

    op.create_table(
        "domain_events",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, nullable=False),
        sa.Column("aggregate_type", sa.String(100), nullable=False),
        sa.Column("aggregate_id", UUID, nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("event_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", UUID, nullable=False),
        sa.Column("causation_id", UUID, nullable=True),
        sa.Column("payload_ref", sa.String(255), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["users.tenant_id", "users.id"],
            name="fk_domain_events_actor",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_domain_events_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "aggregate_version",
            name="uq_domain_events_aggregate_version",
        ),
        sa.CheckConstraint("aggregate_version >= 1", name="ck_domain_events_aggregate_version"),
        sa.CheckConstraint("event_version = 1", name="ck_domain_events_event_version"),
    )
    op.create_index("ix_domain_events_tenant_id", "domain_events", ["tenant_id"])
    op.create_index(
        "ix_domain_events_correlation", "domain_events", ["tenant_id", "correlation_id"]
    )

    op.create_table(
        "outbox_events",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("domain_event_id", UUID, nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "domain_event_id"],
            ["domain_events.tenant_id", "domain_events.id"],
            name="fk_outbox_events_domain_event",
        ),
        sa.UniqueConstraint("domain_event_id", name="uq_outbox_events_domain_event"),
        sa.CheckConstraint(
            "state IN ('PENDING', 'CLAIMED', 'PUBLISHED', 'FAILED')", name="ck_outbox_events_state"
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_outbox_events_attempt_count"),
        sa.CheckConstraint(
            "(state = 'PENDING' AND claimed_at IS NULL AND lease_expires_at IS NULL "
            "AND published_at IS NULL) OR "
            "(state = 'CLAIMED' AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND published_at IS NULL AND attempt_count >= 1) OR "
            "(state = 'PUBLISHED' AND published_at IS NOT NULL AND lease_expires_at IS NULL "
            "AND attempt_count >= 1) OR "
            "(state = 'FAILED' AND last_error_code IS NOT NULL AND lease_expires_at IS NULL "
            "AND attempt_count >= 1)",
            name="ck_outbox_events_state_fields",
        ),
    )
    op.create_index("ix_outbox_events_tenant_id", "outbox_events", ["tenant_id"])
    op.create_index("ix_outbox_events_pending", "outbox_events", ["state", "available_at", "id"])

    op.create_table(
        "idempotency_records",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, nullable=False),
        sa.Column("operation", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("contract_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("stored_result", JSONB, nullable=True),
        sa.Column("stored_error", JSONB, nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["users.tenant_id", "users.id"],
            name="fk_idempotency_records_actor",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "actor_id",
            "operation",
            "idempotency_key",
            name="uq_idempotency_records_scope_key",
        ),
        sa.CheckConstraint("contract_version = 1", name="ck_idempotency_records_contract_version"),
        sa.CheckConstraint(
            "state IN ('IN_PROGRESS', 'SUCCEEDED', 'FAILED_FINAL')",
            name="ck_idempotency_records_state",
        ),
        sa.CheckConstraint(
            "(state = 'IN_PROGRESS' AND stored_result IS NULL AND stored_error IS NULL "
            "AND lease_expires_at IS NOT NULL) OR "
            "(state = 'SUCCEEDED' AND stored_result IS NOT NULL AND stored_error IS NULL "
            "AND lease_expires_at IS NULL) OR "
            "(state = 'FAILED_FINAL' AND stored_result IS NULL AND stored_error IS NOT NULL "
            "AND lease_expires_at IS NULL)",
            name="ck_idempotency_records_state_fields",
        ),
    )
    op.create_index("ix_idempotency_records_tenant_id", "idempotency_records", ["tenant_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(100), nullable=False),
        sa.Column("target_id", UUID, nullable=False),
        sa.Column("result", sa.String(50), nullable=False),
        sa.Column("reason", sa.String(100), nullable=False),
        sa.Column("correlation_id", UUID, nullable=False),
        sa.Column("metadata", JSONB, nullable=False),
        sa.Column("contract_version", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_id"], ["users.tenant_id", "users.id"], name="fk_audit_events_actor"
        ),
        sa.CheckConstraint("contract_version = 1", name="ck_audit_events_contract_version"),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_correlation", "audit_events", ["tenant_id", "correlation_id"])

    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("id", UUID),
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
            sa.column("contract_version", sa.Integer()),
            sa.column("created_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": "10000000-0000-0000-0000-000000000001",
                "permission_key": "tenant.read",
                "description": "Read tenant metadata",
                "contract_version": 1,
                "created_at": "2026-01-15T10:00:00+00:00",
            },
            {
                "id": "10000000-0000-0000-0000-000000000002",
                "permission_key": "tenant.manage",
                "description": "Manage tenant foundation settings",
                "contract_version": 1,
                "created_at": "2026-01-15T10:00:00+00:00",
            },
            {
                "id": "10000000-0000-0000-0000-000000000003",
                "permission_key": "membership.read",
                "description": "Read tenant membership",
                "contract_version": 1,
                "created_at": "2026-01-15T10:00:00+00:00",
            },
            {
                "id": "10000000-0000-0000-0000-000000000004",
                "permission_key": "membership.manage",
                "description": "Manage tenant membership",
                "contract_version": 1,
                "created_at": "2026-01-15T10:00:00+00:00",
            },
            {
                "id": "10000000-0000-0000-0000-000000000005",
                "permission_key": "audit.read",
                "description": "Read tenant audit evidence",
                "contract_version": 1,
                "created_at": "2026-01-15T10:00:00+00:00",
            },
        ],
    )

    context_secret = get_migration_settings().rls_context_secret.get_secret_value()
    op.execute("CREATE SCHEMA nexora_private AUTHORIZATION nexora_migrator")
    op.execute("REVOKE ALL ON SCHEMA nexora_private FROM PUBLIC")
    op.create_table(
        "rls_context_secrets",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("secret_value", sa.Text(), nullable=False),
        schema="nexora_private",
    )
    op.get_bind().execute(
        sa.text(
            "INSERT INTO nexora_private.rls_context_secrets (singleton, secret_value) "
            "VALUES (true, :secret)"
        ),
        {"secret": context_secret},
    )
    op.execute("REVOKE ALL ON nexora_private.rls_context_secrets FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA nexora_private TO nexora_rls_guard")
    op.execute("GRANT SELECT ON nexora_private.rls_context_secrets TO nexora_rls_guard")
    op.execute("GRANT CREATE ON SCHEMA public TO nexora_rls_guard")
    op.execute(
        """CREATE FUNCTION nexora_context_allows(row_tenant uuid) RETURNS boolean
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public, nexora_private
        AS $$
        DECLARE
          tenant_text text := current_setting('app.tenant_id', true);
          actor_text text := current_setting('app.actor_id', true);
          supplied_signature text := current_setting('app.context_signature', true);
          expected_signature text;
        BEGIN
          IF NOT pg_input_is_valid(tenant_text, 'uuid')
             OR NOT pg_input_is_valid(actor_text, 'uuid') THEN
            RETURN false;
          END IF;
          IF tenant_text::uuid <> row_tenant THEN
            RETURN false;
          END IF;
          SELECT encode(hmac(tenant_text || ':' || actor_text, secret_value, 'sha256'), 'hex')
            INTO expected_signature
            FROM nexora_private.rls_context_secrets WHERE singleton = true;
          IF supplied_signature IS NULL
             OR expected_signature IS NULL
             OR supplied_signature <> expected_signature THEN
            RETURN false;
          END IF;
          IF session_user = 'nexora_migrator' THEN
            RETURN true;
          END IF;
          RETURN EXISTS (
            SELECT 1 FROM tenants
            JOIN users ON users.tenant_id = tenants.id
            WHERE tenants.id = row_tenant AND tenants.status = 'ACTIVE'
              AND users.id = actor_text::uuid AND users.status = 'ACTIVE'
          );
        END
        $$"""
    )
    op.execute("ALTER FUNCTION nexora_context_allows(uuid) OWNER TO nexora_rls_guard")
    op.execute("REVOKE ALL ON FUNCTION nexora_context_allows(uuid) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION nexora_context_allows(uuid) TO nexora_runtime")
    op.execute("GRANT SELECT ON tenants, users TO nexora_rls_guard")
    op.execute("GRANT SELECT, UPDATE ON auth_sessions TO nexora_rls_guard")
    op.execute(
        """CREATE FUNCTION nexora_resolve_session(session_hash text, checked_at timestamptz)
        RETURNS TABLE (tenant_id uuid, user_id uuid, external_subject varchar,
                       csrf_hash varchar, absolute_expires_at timestamptz)
        LANGUAGE sql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
          SELECT auth.tenant_id, auth.user_id, users.external_subject,
                 auth.csrf_hash, auth.absolute_expires_at
          FROM auth_sessions AS auth
          JOIN users ON users.tenant_id = auth.tenant_id AND users.id = auth.user_id
          JOIN tenants ON tenants.id = auth.tenant_id
          WHERE auth.token_hash = session_hash AND auth.status = 'ACTIVE'
            AND users.status = 'ACTIVE' AND tenants.status = 'ACTIVE'
            AND auth.idle_expires_at > checked_at AND auth.absolute_expires_at > checked_at
          FOR UPDATE OF auth
        $$"""
    )
    op.execute("ALTER FUNCTION nexora_resolve_session(text, timestamptz) OWNER TO nexora_rls_guard")
    op.execute("REVOKE ALL ON FUNCTION nexora_resolve_session(text, timestamptz) FROM PUBLIC")
    op.execute(
        "GRANT EXECUTE ON FUNCTION nexora_resolve_session(text, timestamptz) TO nexora_runtime"
    )
    op.execute("REVOKE CREATE ON SCHEMA public FROM nexora_rls_guard")

    _enable_rls("tenants", "id")
    tenant_tables = (
        "users",
        "roles",
        "user_roles",
        "role_permissions",
        "foundation_mutations",
        "domain_events",
        "outbox_events",
        "audit_events",
    )
    for table in tenant_tables:
        _enable_rls(table)
    actor_predicate = (
        "session_user = 'nexora_migrator' OR user_id::text = current_setting('app.actor_id', true)"
    )
    _enable_rls("auth_sessions", extra_predicate=actor_predicate)
    idempotency_actor_predicate = "actor_id::text = current_setting('app.actor_id', true)"
    _enable_rls("idempotency_records", extra_predicate=idempotency_actor_predicate)

    op.execute(
        """CREATE FUNCTION reject_append_only_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'append-only relation cannot be changed' USING ERRCODE = '42501';
        END
        $$"""
    )
    for table in ("domain_events", "audit_events"):
        op.execute(
            f'''CREATE TRIGGER "trg_{table}_append_only"
            BEFORE UPDATE OR DELETE ON "{table}"
            FOR EACH ROW EXECUTE FUNCTION reject_append_only_change()'''
        )

    op.execute(
        """CREATE FUNCTION reject_immutable_foundation_field() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'immutable foundation field cannot be changed' USING ERRCODE = '23514';
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_tenants_slug_immutable
        BEFORE UPDATE OF slug ON tenants FOR EACH ROW
        WHEN (OLD.slug IS DISTINCT FROM NEW.slug)
        EXECUTE FUNCTION reject_immutable_foundation_field()"""
    )
    op.execute(
        """CREATE TRIGGER trg_roles_name_immutable
        BEFORE UPDATE OF name ON roles FOR EACH ROW
        WHEN (OLD.name IS DISTINCT FROM NEW.name)
        EXECUTE FUNCTION reject_immutable_foundation_field()"""
    )
    op.execute(
        """CREATE FUNCTION preserve_last_active_owner() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          owner_role uuid;
        BEGIN
          PERFORM 1 FROM tenants WHERE id = OLD.tenant_id FOR UPDATE;
          SELECT id INTO owner_role FROM roles
          WHERE tenant_id = OLD.tenant_id AND name = 'OWNER';
          IF OLD.role_id = owner_role
             AND (TG_OP = 'DELETE' OR NEW.role_id IS DISTINCT FROM OLD.role_id
                  OR NEW.user_id IS DISTINCT FROM OLD.user_id)
             AND NOT EXISTS (
               SELECT 1 FROM user_roles ur
               JOIN users u ON u.tenant_id = ur.tenant_id AND u.id = ur.user_id
               WHERE ur.tenant_id = OLD.tenant_id AND ur.role_id = owner_role
                 AND ur.user_id <> OLD.user_id AND u.status = 'ACTIVE'
             ) THEN
            RAISE EXCEPTION 'tenant must retain an active OWNER' USING ERRCODE = '23514';
          END IF;
          RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_user_roles_preserve_owner
        BEFORE UPDATE OR DELETE ON user_roles FOR EACH ROW
        EXECUTE FUNCTION preserve_last_active_owner()"""
    )
    op.execute(
        """CREATE FUNCTION preserve_last_owner_user() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          PERFORM 1 FROM tenants WHERE id = OLD.tenant_id FOR UPDATE;
          IF OLD.status = 'ACTIVE' AND NEW.status <> 'ACTIVE'
             AND EXISTS (
               SELECT 1 FROM user_roles ur JOIN roles r
                 ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
               WHERE ur.tenant_id = OLD.tenant_id AND ur.user_id = OLD.id
                 AND r.name = 'OWNER'
             )
             AND NOT EXISTS (
               SELECT 1 FROM user_roles ur
               JOIN roles r ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
               JOIN users u ON u.tenant_id = ur.tenant_id AND u.id = ur.user_id
               WHERE ur.tenant_id = OLD.tenant_id AND ur.user_id <> OLD.id
                 AND r.name = 'OWNER' AND u.status = 'ACTIVE'
             ) THEN
            RAISE EXCEPTION 'tenant must retain an active OWNER' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_users_preserve_owner
        BEFORE UPDATE OF status ON users FOR EACH ROW
        EXECUTE FUNCTION preserve_last_owner_user()"""
    )
    op.execute(
        """CREATE FUNCTION revoke_membership_sessions() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          affected_tenant uuid := COALESCE(NEW.tenant_id, OLD.tenant_id);
          affected_user uuid := COALESCE(NEW.user_id, OLD.user_id);
        BEGIN
          UPDATE auth_sessions SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
          WHERE tenant_id = affected_tenant AND user_id = affected_user AND status = 'ACTIVE';
          RETURN COALESCE(NEW, OLD);
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_user_roles_revoke_sessions
        AFTER INSERT OR UPDATE OR DELETE ON user_roles FOR EACH ROW
        EXECUTE FUNCTION revoke_membership_sessions()"""
    )
    op.execute(
        """CREATE FUNCTION revoke_status_sessions() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          IF NEW.status IS DISTINCT FROM OLD.status THEN
            UPDATE auth_sessions SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
            WHERE tenant_id = NEW.tenant_id AND user_id = NEW.id AND status = 'ACTIVE';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_users_revoke_sessions
        AFTER UPDATE OF status ON users FOR EACH ROW EXECUTE FUNCTION revoke_status_sessions()"""
    )
    op.execute(
        """CREATE FUNCTION revoke_tenant_sessions() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
          IF OLD.status = 'ACTIVE' AND NEW.status = 'SUSPENDED' THEN
            UPDATE auth_sessions SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
            WHERE tenant_id = NEW.id AND status = 'ACTIVE';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_tenants_revoke_sessions
        AFTER UPDATE OF status ON tenants FOR EACH ROW EXECUTE FUNCTION revoke_tenant_sessions()"""
    )
    op.execute(
        """CREATE FUNCTION revoke_role_permission_sessions() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          affected_tenant uuid := COALESCE(NEW.tenant_id, OLD.tenant_id);
          affected_role uuid := COALESCE(NEW.role_id, OLD.role_id);
        BEGIN
          UPDATE auth_sessions auth SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
          FROM user_roles ur
          WHERE ur.tenant_id = affected_tenant AND ur.role_id = affected_role
            AND auth.tenant_id = ur.tenant_id AND auth.user_id = ur.user_id
            AND auth.status = 'ACTIVE';
          RETURN COALESCE(NEW, OLD);
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_role_permissions_revoke_sessions
        AFTER INSERT OR UPDATE OR DELETE ON role_permissions FOR EACH ROW
        EXECUTE FUNCTION revoke_role_permission_sessions()"""
    )
    op.execute(
        """CREATE FUNCTION protect_auth_session_state() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF session_user <> 'nexora_runtime' THEN RETURN NEW; END IF;
          IF TG_OP = 'INSERT' THEN
            IF NEW.user_id::text <> current_setting('app.actor_id', true)
               OR NEW.status <> 'ACTIVE' OR NEW.revoked_at IS NOT NULL
               OR NEW.idle_expires_at > NEW.created_at + interval '30 minutes'
               OR NEW.absolute_expires_at > NEW.created_at + interval '12 hours' THEN
              RAISE EXCEPTION 'invalid runtime session creation' USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
          END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
             OR NEW.user_id IS DISTINCT FROM OLD.user_id
             OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
             OR NEW.csrf_hash IS DISTINCT FROM OLD.csrf_hash
             OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at
             OR NEW.created_at IS DISTINCT FROM OLD.created_at
             OR NOT (NEW.status = OLD.status OR (OLD.status = 'ACTIVE' AND NEW.status = 'REVOKED'))
             OR NEW.idle_expires_at > LEAST(
                   NEW.absolute_expires_at, NEW.last_seen_at + interval '30 minutes')
             OR NEW.last_seen_at < OLD.last_seen_at
             OR NEW.last_seen_at > CURRENT_TIMESTAMP + interval '1 minute'
             OR NEW.updated_at < OLD.updated_at
             OR NEW.updated_at > CURRENT_TIMESTAMP + interval '1 minute' THEN
            RAISE EXCEPTION 'invalid runtime session transition' USING ERRCODE = '42501';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_auth_sessions_protect_state
        BEFORE INSERT OR UPDATE ON auth_sessions FOR EACH ROW
        EXECUTE FUNCTION protect_auth_session_state()"""
    )
    op.execute(
        """CREATE FUNCTION protect_idempotency_state() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF session_user <> 'nexora_runtime' THEN RETURN NEW; END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
             OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
             OR NEW.operation IS DISTINCT FROM OLD.operation
             OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
             OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
             OR NEW.contract_version IS DISTINCT FROM OLD.contract_version
             OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
             OR NEW.created_at IS DISTINCT FROM OLD.created_at
             OR OLD.state IN ('SUCCEEDED', 'FAILED_FINAL')
             OR NOT (OLD.state = 'IN_PROGRESS' AND NEW.state IN
                     ('IN_PROGRESS', 'SUCCEEDED', 'FAILED_FINAL')) THEN
            RAISE EXCEPTION 'invalid idempotency transition' USING ERRCODE = '42501';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_idempotency_protect_state
        BEFORE UPDATE ON idempotency_records FOR EACH ROW
        EXECUTE FUNCTION protect_idempotency_state()"""
    )
    op.execute(
        """CREATE FUNCTION protect_outbox_state() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
          context_actor uuid;
        BEGIN
          IF session_user <> 'nexora_runtime' THEN RETURN NEW; END IF;
          IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
             OR NEW.domain_event_id IS DISTINCT FROM OLD.domain_event_id
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'immutable outbox fields changed' USING ERRCODE = '42501';
          END IF;
          IF OLD.state = 'PENDING' AND NEW.state = 'CLAIMED'
             AND NEW.attempt_count = OLD.attempt_count + 1 THEN RETURN NEW; END IF;
          IF OLD.state = 'CLAIMED' AND NEW.state = 'CLAIMED'
             AND NEW.attempt_count = OLD.attempt_count + 1 THEN RETURN NEW; END IF;
          IF OLD.state = 'CLAIMED' AND NEW.state IN ('PUBLISHED', 'FAILED')
             AND NEW.attempt_count = OLD.attempt_count THEN
            RETURN NEW;
          END IF;
          IF OLD.state = 'FAILED' AND NEW.state = 'PENDING' THEN
            IF NEW.attempt_count <> OLD.attempt_count THEN
              RAISE EXCEPTION 'invalid outbox attempt transition' USING ERRCODE = '42501';
            END IF;
            context_actor := current_setting('app.actor_id', true)::uuid;
            IF NOT EXISTS (
              SELECT 1 FROM user_roles ur
              JOIN roles r ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
              JOIN role_permissions rp ON rp.tenant_id = r.tenant_id AND rp.role_id = r.id
              JOIN permissions p ON p.id = rp.permission_id
              WHERE ur.tenant_id = OLD.tenant_id AND ur.user_id = context_actor
                AND p.permission_key = 'tenant.manage'
            ) OR NOT EXISTS (
              SELECT 1 FROM audit_events ae WHERE ae.tenant_id = OLD.tenant_id
                AND ae.actor_id = context_actor AND ae.action = 'outbox.recover'
                AND ae.target_id = OLD.id
                AND ae.metadata ->> 'attempt_count' = OLD.attempt_count::text
            ) THEN
              RAISE EXCEPTION 'outbox recovery requires authorized audit' USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'invalid outbox transition' USING ERRCODE = '42501';
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_outbox_protect_state
        BEFORE UPDATE ON outbox_events FOR EACH ROW EXECUTE FUNCTION protect_outbox_state()"""
    )
    op.execute("REVOKE ALL ON FUNCTION preserve_last_active_owner() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION preserve_last_owner_user() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION revoke_membership_sessions() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION revoke_status_sessions() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION revoke_tenant_sessions() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION revoke_role_permission_sessions() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION protect_outbox_state() FROM PUBLIC")

    op.execute("GRANT USAGE ON SCHEMA public TO nexora_runtime")
    op.execute("GRANT SELECT ON permissions TO nexora_runtime")
    op.execute(
        "GRANT SELECT ON tenants, users, roles, user_roles, role_permissions TO nexora_runtime"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON auth_sessions TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT ON foundation_mutations TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON idempotency_records TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT ON domain_events, audit_events TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON outbox_events TO nexora_runtime")


def downgrade() -> None:
    op.execute("DROP FUNCTION protect_outbox_state() CASCADE")
    op.execute("DROP FUNCTION protect_idempotency_state() CASCADE")
    op.execute("DROP FUNCTION protect_auth_session_state() CASCADE")
    op.execute("DROP FUNCTION revoke_role_permission_sessions() CASCADE")
    op.execute("DROP FUNCTION revoke_tenant_sessions() CASCADE")
    op.execute("DROP FUNCTION revoke_status_sessions() CASCADE")
    op.execute("DROP FUNCTION revoke_membership_sessions() CASCADE")
    op.execute("DROP FUNCTION preserve_last_owner_user() CASCADE")
    op.execute("DROP FUNCTION preserve_last_active_owner() CASCADE")
    op.execute("DROP FUNCTION reject_immutable_foundation_field() CASCADE")
    for table in (
        "audit_events",
        "idempotency_records",
        "outbox_events",
        "domain_events",
        "foundation_mutations",
        "auth_sessions",
        "role_permissions",
        "user_roles",
        "roles",
        "permissions",
        "users",
        "tenants",
    ):
        op.drop_table(table)
    op.execute("SET LOCAL ROLE nexora_rls_guard")
    op.execute("DROP FUNCTION nexora_resolve_session(text, timestamptz)")
    op.execute("DROP FUNCTION nexora_context_allows(uuid)")
    op.execute("RESET ROLE")
    op.execute("DROP FUNCTION reject_append_only_change()")
    op.drop_table("rls_context_secrets", schema="nexora_private")
    op.execute("DROP SCHEMA nexora_private")
