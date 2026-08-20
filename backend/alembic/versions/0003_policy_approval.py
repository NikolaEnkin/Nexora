"""Create the Phase-03 policy and approval boundary.

Revision ID: 0003_policy_approval
Revises: 0002_langgraph_checkpoint
Create Date: 2026-08-19

Unlike ``0002``, these tables live in ``public``. Approvals are authoritative
business truth in the same sense as ``audit_events`` and ``idempotency_records``:
they record what a human decided and are never rebuildable from a projection.
Phase 02 kept ``public`` byte-identical to preserve the Phase-01 catalog contract;
this revision renegotiates it deliberately, under Nikola's ruling A-2, because
accepted ``ADR-004`` requires a ``DEPUTY`` role that ``ck_roles_name`` forbids.

Row-level security here is **tenant-scoped only**, not tenant-and-actor as in
``0002``. That difference is the point of an approval: an approver is by
definition someone other than the requester, so an actor-scoped policy would hide
every request from the people who must decide it. ``ADR-002``'s "tenant-wide
access through explicit permission" is the governing rule, and the narrow
``approval.decide`` permissions are what restrict who may act.

No table here grants ``DELETE`` to the runtime role. Approval history is never
hard-deleted (``ADR-004`` §Rollback).
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_policy_approval"
down_revision: str | None = "0002_langgraph_checkpoint"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB

RISK_LEVELS = ("R1", "R2", "R3")
ASSURANCES = ("standard", "step_up")
DECISIONS = ("APPROVED", "REJECTED")

APPROVAL_STATUSES = (
    "DRAFT",
    "PENDING",
    "APPROVED",
    "CONSUMING",
    "CONSUMED",
    "REJECTED",
    "CANCELLED",
    "EXPIRED",
    "INVALIDATED",
    "REVOKED",
    "FAILED_FINAL",
)
NONTERMINAL_STATUSES = ("DRAFT", "PENDING", "APPROVED", "CONSUMING")
TERMINAL_STATUSES = (
    "CONSUMED",
    "REJECTED",
    "CANCELLED",
    "EXPIRED",
    "INVALIDATED",
    "REVOKED",
    "FAILED_FINAL",
)

TENANT_TABLES = (
    "approval_requests",
    "approval_decisions",
    "approval_consumptions",
    "protected_effect_counters",
)

# ADR-004 §2. Business permissions (client.*, offer.*, invoice.*, payment.*,
# email.*, contact.*) are created by Phases 04 and 05, which own those actions.
NEW_PERMISSIONS = (
    ("approval.decide", "Record an approval decision on a protected action"),
    ("approval.decide.high", "Record an approval decision on an R3 protected action"),
)
# approval.decide.high implies approval.decide: whoever may approve the more
# dangerous action may approve the less dangerous one.
PERMISSION_ROLE_MAP = {
    "approval.decide": ("OWNER", "OPERATOR", "DEPUTY"),
    "approval.decide.high": ("OWNER", "DEPUTY"),
}


def _tenant_rls(table: str) -> None:
    """Tenant-scoped forced RLS delegating to the Phase-01 signed-context authority."""
    quoted = f'"{table}"'
    op.execute(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY")
    predicate = "public.nexora_context_allows(tenant_id)"
    op.execute(
        f'CREATE POLICY "tenant_isolation_{table}" ON {quoted} '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


# ADR-004 §1, embedded literally rather than imported from `app.policy.catalogue`.
# A migration must keep meaning the same forever, so it cannot depend on code that
# a later revision may change; reclassification is a new catalogue version and a
# new revision. `P03-CATALOGUE-DRIFT` asserts the two agree at the current version.
CATALOGUE_V1 = (
    ("client_get", "R1", "client.read", "standard", None, None),
    ("offer_get", "R1", "offer.read", "standard", None, None),
    ("offer_items", "R1", "offer.read", "standard", None, None),
    ("invoice_get", "R1", "invoice.read", "standard", None, None),
    ("invoice_items", "R1", "invoice.read", "standard", None, None),
    ("invoice_list_unpaid", "R1", "invoice.read", "standard", None, None),
    ("offer_validate", "R1", "offer.write", "standard", None, None),
    ("invoice_validate", "R1", "invoice.write", "standard", None, None),
    ("email_account_list", "R1", "email.read", "standard", None, None),
    ("email_draft_get", "R1", "email.read", "standard", None, None),
    ("email_thread_recent", "R1", "email.read", "standard", None, None),
    ("client_create", "R2", "client.write", "standard", None, None),
    ("client_update", "R2", "client.write", "standard", None, None),
    ("offer_draft_create", "R2", "offer.write", "standard", None, None),
    ("invoice_draft_create", "R2", "invoice.write", "standard", None, None),
    ("email_draft_create", "R2", "email.draft", "standard", None, None),
    ("email_draft_update", "R2", "email.draft", "standard", None, None),
    ("contact_resolve", "R2", "contact.read", "standard", None, None),
    ("email_send", "R2", "email.send", "standard", None, None),
    ("invoice_issue", "R3", "invoice.issue", "step_up", "amount", "currency"),
    ("payment_record", "R3", "payment.record", "step_up", "amount", "currency"),
)
CATALOGUE_VERSION_V1 = 1


def _seed_catalogue() -> None:
    for action_key, risk, permission, assurance, amount_field, currency_field in CATALOGUE_V1:
        op.execute(
            sa.text(
                """INSERT INTO policy_action_catalogue (
                    id, catalogue_version, action_key, risk, required_permission,
                    required_assurance, amount_field, currency_field, created_at
                ) VALUES (
                    gen_random_uuid(), :version, :action_key, :risk, :permission,
                    :assurance, :amount_field, :currency_field, now()
                ) ON CONFLICT (catalogue_version, action_key) DO NOTHING"""
            ).bindparams(
                version=CATALOGUE_VERSION_V1,
                action_key=action_key,
                risk=risk,
                permission=permission,
                assurance=assurance,
                amount_field=amount_field,
                currency_field=currency_field,
            )
        )


def upgrade() -> None:
    _create_catalogue()
    _seed_catalogue()
    _create_approval_tables()
    _create_effect_counter()
    _extend_roles_and_permissions()
    _create_guards()
    _grant_runtime()


def _create_catalogue() -> None:
    """Versioned classification data. Global rather than tenant-scoped: the
    catalogue is a property of the deployed policy version, not of a customer."""
    op.create_table(
        "policy_action_catalogue",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("catalogue_version", sa.Integer(), nullable=False),
        sa.Column("action_key", sa.String(100), nullable=False),
        sa.Column("risk", sa.String(2), nullable=False),
        sa.Column("required_permission", sa.String(100), nullable=False),
        sa.Column("required_assurance", sa.String(20), nullable=False),
        sa.Column("amount_field", sa.String(100), nullable=True),
        sa.Column("currency_field", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("risk IN " + str(RISK_LEVELS), name="ck_policy_catalogue_risk"),
        sa.CheckConstraint(
            "required_assurance IN ('standard', 'step_up')",
            name="ck_policy_catalogue_assurance",
        ),
        sa.CheckConstraint("catalogue_version >= 1", name="ck_policy_catalogue_version"),
        sa.UniqueConstraint(
            "catalogue_version", "action_key", name="uq_policy_catalogue_version_action"
        ),
    )


def _create_approval_tables() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("requester_id", UUID, nullable=False),
        sa.Column("operation_id", UUID, nullable=True),
        sa.Column("action_key", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(100), nullable=False),
        sa.Column("target_id", UUID, nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("risk", sa.String(2), nullable=False),
        sa.Column("normalization_version", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("catalogue_version", sa.Integer(), nullable=False),
        sa.Column("open_path_ids", postgresql.ARRAY(sa.Integer()), nullable=False),
        sa.Column("required_assurance", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("satisfied_path_id", sa.Integer(), nullable=True),
        # ADR-004 §3 as amended: the collection window ends here and the execution
        # window begins. Two windows need two timestamps; `updated_at` cannot serve,
        # because it moves on every write.
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("correlation_id", UUID, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN " + str(APPROVAL_STATUSES), name="ck_approval_requests_status"
        ),
        sa.CheckConstraint("risk IN " + str(RISK_LEVELS), name="ck_approval_requests_risk"),
        sa.CheckConstraint(
            "required_assurance IN ('standard', 'step_up')",
            name="ck_approval_requests_assurance",
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[a-f0-9]{64}$'", name="ck_approval_requests_payload_hash"
        ),
        sa.CheckConstraint("normalization_version >= 1", name="ck_approval_requests_norm_version"),
        sa.CheckConstraint("policy_version >= 1", name="ck_approval_requests_policy_version"),
        sa.CheckConstraint("catalogue_version >= 1", name="ck_approval_requests_catalogue_version"),
        # A request that reached a terminal status must record when.
        sa.CheckConstraint(
            "(status IN " + str(NONTERMINAL_STATUSES) + " AND terminal_at IS NULL) "
            "OR (status IN " + str(TERMINAL_STATUSES) + " AND terminal_at IS NOT NULL)",
            name="ck_approval_requests_terminal_at",
        ),
        # One approval request per idempotent submission.
        sa.UniqueConstraint(
            "tenant_id",
            "requester_id",
            "action_key",
            "idempotency_key",
            name="uq_approval_requests_identity",
        ),
    )
    op.create_index(
        "ix_approval_requests_tenant_status", "approval_requests", ["tenant_id", "status"]
    )
    op.create_index(
        "ix_approval_requests_tenant_expiry", "approval_requests", ["tenant_id", "expires_at"]
    )
    op.create_index(
        "ix_approval_requests_tenant_target",
        "approval_requests",
        ["tenant_id", "action_key", "target_id"],
    )

    op.create_table(
        "approval_decisions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("approval_id", UUID, sa.ForeignKey("approval_requests.id"), nullable=False),
        sa.Column("actor_id", UUID, nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("assurance", sa.String(20), nullable=False),
        sa.Column("roles", postgresql.ARRAY(sa.String(30)), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("correlation_id", UUID, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("decision IN " + str(DECISIONS), name="ck_approval_decisions_decision"),
        sa.CheckConstraint(
            "assurance IN ('standard', 'step_up')", name="ck_approval_decisions_assurance"
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[a-f0-9]{64}$'", name="ck_approval_decisions_payload_hash"
        ),
        # "Every decision in a path must come from a different actor" (ADR-004 §2)
        # is a database property, not a service-side check.
        sa.UniqueConstraint("approval_id", "actor_id", name="uq_approval_decisions_one_per_actor"),
        sa.UniqueConstraint(
            "tenant_id",
            "approval_id",
            "actor_id",
            "idempotency_key",
            name="uq_approval_decisions_replay",
        ),
    )
    op.create_index(
        "ix_approval_decisions_approval", "approval_decisions", ["approval_id", "created_at"]
    )

    op.create_table(
        "approval_consumptions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("approval_id", UUID, sa.ForeignKey("approval_requests.id"), nullable=False),
        sa.Column("operation_id", UUID, nullable=True),
        sa.Column("action_key", sa.String(100), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("result_ref", sa.String(255), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "payload_hash ~ '^[a-f0-9]{64}$'", name="ck_approval_consumptions_payload_hash"
        ),
        # At most one consumption per approval: single-use is arbitrated here,
        # not by a service-side read-then-write that a concurrent worker races.
        sa.UniqueConstraint("approval_id", name="uq_approval_consumptions_single_use"),
    )


def _create_effect_counter() -> None:
    """The fake protected effect (packet §4).

    This exists so a security negative can assert "the protected side effect count
    is zero" against durable state rather than against a mock's call list. Phase 03
    performs no real business mutation, so this counter *is* the side effect.
    """
    op.create_table(
        "protected_effect_counters",
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("action_key", sa.String(100), nullable=False),
        sa.Column("target_id", UUID, nullable=False),
        sa.Column("effect_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "action_key", "target_id"),
        sa.CheckConstraint("effect_count >= 0", name="ck_protected_effect_count"),
    )


def _extend_roles_and_permissions() -> None:
    """ADR-004 §2 — the DEPUTY role and the two approval permissions.

    Ruling A-2 authorizes altering the Phase-01 constraint forward. The
    ``0001_foundation`` file itself is not edited.
    """
    op.drop_constraint("ck_roles_name", "roles", type_="check")
    op.create_check_constraint(
        "ck_roles_name", "roles", "name IN ('OWNER', 'OPERATOR', 'VIEWER', 'DEPUTY')"
    )

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


def _tenant_ids(bind: sa.Connection) -> list[str]:
    """Enumerate tenants.

    `tenants` uses FORCE row-level security and `nexora_migrator` holds no
    `BYPASSRLS`, so a plain `SELECT` here returns zero rows and every downstream
    statement silently becomes a no-op. The guard role is the mechanism `0002`
    already established for exactly this: read under `nexora_rls_guard`, then do
    the work per tenant under a signed context.
    """
    bind.execute(sa.text("SET LOCAL ROLE nexora_rls_guard"))
    try:
        return [str(row[0]) for row in bind.execute(sa.text("SELECT id FROM tenants")).all()]
    finally:
        bind.execute(sa.text("RESET ROLE"))


def _set_tenant_context(bind: sa.Connection, tenant_id: str) -> None:
    """Set the signed context `public.nexora_context_allows` requires.

    The signature is checked before the `session_user = 'nexora_migrator'` branch,
    so the migrator needs a valid triple even though it is then trusted. The actor
    identifier does not have to exist for that branch, so the tenant's own id is
    used rather than inventing a synthetic user.
    """
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


def _backfill_existing_tenants() -> None:
    """Give tenants that already exist the DEPUTY role and the approval permissions.

    Tenants provisioned *after* this revision are **not** covered:
    `app/identity/provisioning.py` seeds only OWNER/OPERATOR/VIEWER and is Phase-01
    code outside this packet's allowlist. That gap is recorded as finding F-01.
    """
    bind = op.get_bind()
    for tenant_id in _tenant_ids(bind):
        _set_tenant_context(bind, tenant_id)
        bind.execute(
            sa.text(
                """INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
                SELECT gen_random_uuid(), :tenant_id, 'DEPUTY',
                       'Approval deputy: R3 approval authority only', now(), now()
                WHERE NOT EXISTS (
                    SELECT 1 FROM roles r
                    WHERE r.tenant_id = :tenant_id AND r.name = 'DEPUTY'
                )"""
            ),
            {"tenant_id": tenant_id},
        )
        for permission_key, role_names in PERMISSION_ROLE_MAP.items():
            bind.execute(
                sa.text(
                    """INSERT INTO role_permissions (tenant_id, role_id, permission_id,
                                                     granted_by, granted_at)
                    SELECT r.tenant_id, r.id, p.id, grantor.id, now()
                    FROM roles r
                    JOIN permissions p ON p.permission_key = :key
                    JOIN LATERAL (
                        SELECT u.id
                        FROM users u
                        JOIN user_roles ur ON ur.user_id = u.id
                        JOIN roles owner_role ON owner_role.id = ur.role_id
                        WHERE ur.tenant_id = r.tenant_id
                          AND owner_role.name = 'OWNER'
                          AND u.status = 'ACTIVE'
                        ORDER BY u.id
                        LIMIT 1
                    ) AS grantor ON true
                    WHERE r.tenant_id = :tenant_id
                      AND r.name = ANY(:roles)
                      AND NOT EXISTS (
                          SELECT 1 FROM role_permissions rp
                          WHERE rp.role_id = r.id AND rp.permission_id = p.id
                      )"""
                ),
                {"tenant_id": tenant_id, "key": permission_key, "roles": list(role_names)},
            )


def _create_guards() -> None:
    # Append-only history. ADR-004 §Rollback: a rollback of the rules never
    # erases what was decided under them.
    op.execute(
        """CREATE FUNCTION reject_approval_history_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'approval history is append-only' USING ERRCODE = '23514';
        END
        $$"""
    )
    for table in ("approval_decisions", "approval_consumptions"):
        op.execute(
            f"""CREATE TRIGGER trg_{table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_approval_history_change()"""
        )

    # The immutable half of an approval request. Payload, hash, versions, target
    # and requester cannot drift after creation, so a stored request always means
    # exactly what the approver saw.
    op.execute(
        """CREATE FUNCTION protect_approval_request_state() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.payload_hash <> OLD.payload_hash
             OR NEW.payload::text <> OLD.payload::text
             OR NEW.tenant_id <> OLD.tenant_id
             OR NEW.requester_id <> OLD.requester_id
             OR NEW.action_key <> OLD.action_key
             OR NEW.target_type <> OLD.target_type
             OR NEW.target_id <> OLD.target_id
             OR NEW.normalization_version <> OLD.normalization_version
             OR NEW.policy_version <> OLD.policy_version
             OR NEW.catalogue_version <> OLD.catalogue_version
             OR NEW.risk <> OLD.risk
             OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'approval request identity is immutable'
              USING ERRCODE = '23514';
          END IF;
          IF OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
            RAISE EXCEPTION 'approval grant time is immutable once set'
              USING ERRCODE = '23514';
          END IF;
          IF OLD.status = ANY (ARRAY['CONSUMED','REJECTED','CANCELLED','EXPIRED',
                                     'INVALIDATED','REVOKED','FAILED_FINAL'])
             AND NEW.status <> OLD.status THEN
            RAISE EXCEPTION 'terminal approval status is immutable'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER trg_approval_requests_protect_state
        BEFORE UPDATE ON approval_requests
        FOR EACH ROW EXECUTE FUNCTION protect_approval_request_state()"""
    )

    # ADR-004 §2: at most one active DEPUTY per tenant, enforced the same way
    # ADR-002 enforces "at least one active OWNER" — by trigger, so "only one
    # person" is a property of the schema rather than of discipline.
    op.execute(
        """CREATE FUNCTION enforce_single_active_deputy() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
          deputy_count integer;
        BEGIN
          SELECT count(*) INTO deputy_count
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            JOIN users u ON u.id = ur.user_id
           WHERE ur.tenant_id = NEW.tenant_id
             AND r.name = 'DEPUTY'
             AND u.status = 'ACTIVE';
          IF deputy_count > 1 THEN
            RAISE EXCEPTION 'a tenant may have at most one active DEPUTY'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE CONSTRAINT TRIGGER trg_user_roles_single_deputy
        AFTER INSERT OR UPDATE ON user_roles
        DEFERRABLE INITIALLY IMMEDIATE
        FOR EACH ROW EXECUTE FUNCTION enforce_single_active_deputy()"""
    )

    for function in (
        "reject_approval_history_change()",
        "protect_approval_request_state()",
        "enforce_single_active_deputy()",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")


def _grant_runtime() -> None:
    op.execute("GRANT SELECT ON policy_action_catalogue TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON approval_requests TO nexora_runtime")
    # Append-only: no UPDATE, and no DELETE anywhere in this revision.
    op.execute("GRANT SELECT, INSERT ON approval_decisions TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT ON approval_consumptions TO nexora_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE ON protected_effect_counters TO nexora_runtime")

    # FORCE RLS hides rows from the owner too; the guard role performs the
    # downgrade-time read, exactly as in 0002.
    for table in TENANT_TABLES:
        op.execute(f"GRANT SELECT ON {table} TO nexora_rls_guard")

    for table in TENANT_TABLES:
        _tenant_rls(table)


def nonterminal_approval_count(bind: sa.Connection) -> int:
    """Approvals that have not reached a terminal status."""
    bind.execute(sa.text("SET LOCAL ROLE nexora_rls_guard"))
    try:
        return int(
            bind.execute(
                sa.text("SELECT count(*) FROM approval_requests WHERE status = ANY(:statuses)"),
                {"statuses": list(NONTERMINAL_STATUSES)},
            ).scalar_one()
        )
    finally:
        bind.execute(sa.text("RESET ROLE"))


def assert_downgrade_allowed(bind: sa.Connection) -> None:
    """Packet §9: downgrade is test-only and refuses while approvals are live."""
    if os.environ.get("NEXORA_ENVIRONMENT") not in {"test", "development"}:
        raise RuntimeError("approval downgrade requires a disposable test/development database")
    if os.environ.get("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK") != "true":
        raise RuntimeError("approval downgrade requires explicit destructive opt-in")
    pending = nonterminal_approval_count(bind)
    if pending:
        raise RuntimeError(
            f"refusing to drop approval storage: {pending} approvals are non-terminal"
        )


def downgrade() -> None:
    """Disposable environments only, and only when no approval is still live."""
    bind = op.get_bind()
    assert_downgrade_allowed(bind)

    op.execute("DROP TRIGGER trg_user_roles_single_deputy ON user_roles")
    op.execute("DROP FUNCTION enforce_single_active_deputy() CASCADE")
    op.execute("DROP FUNCTION protect_approval_request_state() CASCADE")
    op.execute("DROP FUNCTION reject_approval_history_change() CASCADE")

    # The same RLS constraint applies on the way down: without a signed context per
    # tenant these deletes match zero rows, and the `DELETE FROM permissions` below
    # then fails on a foreign key that "should" already have been cleared.
    keys = [key for key, _ in NEW_PERMISSIONS]
    for tenant_id in _tenant_ids(bind):
        _set_tenant_context(bind, tenant_id)
        bind.execute(
            sa.text(
                """DELETE FROM role_permissions rp
                USING permissions p
                WHERE rp.permission_id = p.id AND p.permission_key = ANY(:keys)
                  AND rp.tenant_id = :tenant_id"""
            ),
            {"keys": keys, "tenant_id": tenant_id},
        )
        bind.execute(
            sa.text(
                """DELETE FROM user_roles ur
                USING roles r
                WHERE r.id = ur.role_id AND r.name = 'DEPUTY' AND ur.tenant_id = :tenant_id"""
            ),
            {"tenant_id": tenant_id},
        )
        # Since amendment A-6, provisioning also gives DEPUTY `tenant.read` and
        # `membership.read`. Every mapping for the role has to go before the role
        # itself, not only the two approval permissions.
        bind.execute(
            sa.text(
                """DELETE FROM role_permissions rp
                USING roles r
                WHERE r.id = rp.role_id AND r.name = 'DEPUTY' AND rp.tenant_id = :tenant_id"""
            ),
            {"tenant_id": tenant_id},
        )
        bind.execute(
            sa.text("DELETE FROM roles WHERE name = 'DEPUTY' AND tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        )
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = ANY(:keys)").bindparams(
            keys=[key for key, _ in NEW_PERMISSIONS]
        )
    )
    op.drop_constraint("ck_roles_name", "roles", type_="check")
    op.create_check_constraint("ck_roles_name", "roles", "name IN ('OWNER', 'OPERATOR', 'VIEWER')")

    op.drop_table("protected_effect_counters")
    op.drop_table("approval_consumptions")
    op.drop_table("approval_decisions")
    op.drop_table("approval_requests")
    op.drop_table("policy_action_catalogue")
