"""Create the Phase-04 business domain — clients only.

Revision ID: 0004_business_domain
Revises: 0003_policy_approval
Create Date: 2026-08-21

**This revision is deliberately incomplete.** Packet §9 also specifies `offers`,
`offer_items`, `invoices`, `invoice_items` and `payments`. None of them are here,
because their statuses, numbering, currency handling, tax columns and totals are
`HD-004`'s to decide and packet §8 states that an unresolved business cell blocks
the tool rather than permitting a guessed default. Adding a placeholder status
enum now would be exactly that guess, and would have to be migrated over issued
financial documents later.

`clients` is not blocked: client identity is not a financial rule. Its lifecycle
(`ACTIVE` / `ARCHIVED`) is a technical choice recorded here, not an `HD-004`
question — `HD-004` scopes offer, invoice and payment lifecycles.

The remaining tables arrive in a later revision once `ADR-005` is accepted. That
is why this file creates a table rather than a schema: `0005` must be able to add
siblings without rewriting anything here.

Row-level security is tenant-scoped, matching `0003`. A client is visible to
everyone in the tenant who holds the permission; `ADR-002` makes object access
tenant-wide, and the narrow `client.read` / `client.write` permissions are the
control.
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_business_domain"
down_revision: str | None = "0003_policy_approval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB

CLIENT_STATUSES = ("ACTIVE", "ARCHIVED")

# Business permissions named by ADR-004 §1 for the client actions. ADR-004 states
# that the phase owning the action creates them; these are Phase 04's.
NEW_PERMISSIONS = (
    ("client.read", "Read client records"),
    ("client.write", "Create and update client records"),
)
PERMISSION_ROLE_MAP = {
    "client.read": ("OWNER", "OPERATOR", "VIEWER", "DEPUTY"),
    "client.write": ("OWNER", "OPERATOR"),
}


def _tenant_rls(table: str) -> None:
    quoted = f'"{table}"'
    op.execute(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY")
    predicate = "public.nexora_context_allows(tenant_id)"
    op.execute(
        f'CREATE POLICY "tenant_isolation_{table}" ON {quoted} '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def _tenant_ids(bind: sa.Connection) -> list[str]:
    """Enumerate tenants under the guard role.

    `tenants` uses FORCE row-level security and `nexora_migrator` holds no
    `BYPASSRLS`, so a plain `SELECT` returns zero rows and every downstream
    statement silently becomes a no-op. That was Phase-03 finding F-03; the fix
    is carried forward rather than rediscovered.
    """
    bind.execute(sa.text("SET LOCAL ROLE nexora_rls_guard"))
    try:
        return [str(row[0]) for row in bind.execute(sa.text("SELECT id FROM tenants")).all()]
    finally:
        bind.execute(sa.text("RESET ROLE"))


def _set_tenant_context(bind: sa.Connection, tenant_id: str) -> None:
    import hashlib
    import hmac as hmac_module

    from app.config import get_migration_settings

    secret = get_migration_settings().rls_context_secret.get_secret_value()
    signature = hmac_module.new(
        secret.encode(), f"{tenant_id}:{tenant_id}".encode(), hashlib.sha256
    ).hexdigest()
    bind.execute(
        sa.text(
            "SELECT set_config('app.tenant_id', :tenant_id, true), "
            "set_config('app.actor_id', :actor_id, true), "
            "set_config('app.context_signature', :signature, true)"
        ),
        {"tenant_id": tenant_id, "actor_id": tenant_id, "signature": signature},
    )


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("legal_name", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        # The canonical key. `BR-04-001` requires an ambiguous alias to produce a
        # clarification rather than a guess, so resolution is by exact id or by
        # this exact normalized key — never by fuzzy match.
        sa.Column("normalized_key", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        # Contact details live behind a reference rather than in columns: Phase 05
        # owns the canonical contact registry, and duplicating addresses here would
        # create a second source of truth for who receives a document.
        sa.Column("contact_ref", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        # Optimistic concurrency. `BR-04-004` needs a version to increment, and
        # `client_update` requires the caller to state the version it saw.
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN " + str(CLIENT_STATUSES), name="ck_clients_status"),
        sa.CheckConstraint("row_version >= 1", name="ck_clients_row_version"),
        sa.CheckConstraint("length(legal_name) > 0", name="ck_clients_legal_name"),
        sa.CheckConstraint("length(normalized_key) > 0", name="ck_clients_normalized_key"),
    )
    # "Unique active normalized identity per tenant" (packet §9). Partial, so an
    # archived client does not block reusing the same name for a new one.
    op.create_index(
        "uq_clients_active_identity",
        "clients",
        ["tenant_id", "normalized_key"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )
    op.create_index("ix_clients_tenant_status", "clients", ["tenant_id", "status"])

    op.execute(
        """CREATE FUNCTION protect_client_identity() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.tenant_id <> OLD.tenant_id OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'client tenant and creation time are immutable'
              USING ERRCODE = '23514';
          END IF;
          IF NEW.row_version <= OLD.row_version THEN
            RAISE EXCEPTION 'client row_version must increase'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_clients_protect_identity
        BEFORE UPDATE ON clients
        FOR EACH ROW EXECUTE FUNCTION protect_client_identity()"""
    )
    op.execute("REVOKE ALL ON FUNCTION protect_client_identity() FROM PUBLIC")

    for permission_key, description in NEW_PERMISSIONS:
        op.execute(
            sa.text(
                """INSERT INTO permissions (id, permission_key, description, contract_version,
                                            created_at)
                VALUES (gen_random_uuid(), :key, :description, 1, now())
                ON CONFLICT (permission_key) DO NOTHING"""
            ).bindparams(key=permission_key, description=description)
        )

    _backfill_existing_tenants()

    # No DELETE: a client is archived, never removed, because invoices will
    # reference it and history must stay resolvable.
    op.execute("GRANT SELECT, INSERT, UPDATE ON clients TO nexora_runtime")
    op.execute("GRANT SELECT ON clients TO nexora_rls_guard")
    _tenant_rls("clients")


def _backfill_existing_tenants() -> None:
    """Map the two client permissions onto existing tenants' roles."""
    bind = op.get_bind()
    for tenant_id in _tenant_ids(bind):
        _set_tenant_context(bind, tenant_id)
        for permission_key, role_names in PERMISSION_ROLE_MAP.items():
            bind.execute(
                sa.text(
                    """INSERT INTO role_permissions (tenant_id, role_id, permission_id,
                                                     granted_by, granted_at)
                    SELECT r.tenant_id, r.id, p.id, grantor.id, now()
                    FROM roles r
                    JOIN permissions p ON p.permission_key = :key
                    JOIN LATERAL (
                        SELECT u.id FROM users u
                        JOIN user_roles ur ON ur.user_id = u.id
                        JOIN roles owner_role ON owner_role.id = ur.role_id
                        WHERE ur.tenant_id = r.tenant_id
                          AND owner_role.name = 'OWNER' AND u.status = 'ACTIVE'
                        ORDER BY u.id LIMIT 1
                    ) AS grantor ON true
                    WHERE r.tenant_id = :tenant_id AND r.name = ANY(:roles)
                      AND NOT EXISTS (
                          SELECT 1 FROM role_permissions rp
                          WHERE rp.role_id = r.id AND rp.permission_id = p.id
                      )"""
                ),
                {"tenant_id": tenant_id, "key": permission_key, "roles": list(role_names)},
            )


def assert_downgrade_allowed(bind: sa.Connection) -> None:
    """Packet §9: downgrade is test-only. It also refuses while clients exist,
    because a client that an invoice will later reference is not disposable."""
    if os.environ.get("NEXORA_ENVIRONMENT") not in {"test", "development"}:
        raise RuntimeError("business domain downgrade requires a disposable database")
    if os.environ.get("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK") != "true":
        raise RuntimeError("business domain downgrade requires explicit destructive opt-in")
    bind.execute(sa.text("SET LOCAL ROLE nexora_rls_guard"))
    try:
        existing = int(bind.execute(sa.text("SELECT count(*) FROM clients")).scalar_one())
    finally:
        bind.execute(sa.text("RESET ROLE"))
    if existing:
        raise RuntimeError(f"refusing to drop client storage: {existing} clients exist")


def downgrade() -> None:
    bind = op.get_bind()
    assert_downgrade_allowed(bind)

    keys = [key for key, _ in NEW_PERMISSIONS]
    for tenant_id in _tenant_ids(bind):
        _set_tenant_context(bind, tenant_id)
        bind.execute(
            sa.text(
                """DELETE FROM role_permissions rp USING permissions p
                WHERE rp.permission_id = p.id AND p.permission_key = ANY(:keys)
                  AND rp.tenant_id = :tenant_id"""
            ),
            {"keys": keys, "tenant_id": tenant_id},
        )
    op.execute("DROP TRIGGER trg_clients_protect_identity ON clients")
    op.execute("DROP FUNCTION protect_client_identity() CASCADE")
    op.drop_table("clients")
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = ANY(:keys)").bindparams(keys=keys)
    )
