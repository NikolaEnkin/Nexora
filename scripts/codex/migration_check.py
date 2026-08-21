from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.config import get_migration_settings

REQUIRED_TABLES = {
    "alembic_version",
    "audit_events",
    "auth_sessions",
    "domain_events",
    "foundation_mutations",
    "idempotency_records",
    "outbox_events",
    "permissions",
    "role_permissions",
    "roles",
    "tenants",
    "user_roles",
    "users",
}
TENANT_TABLES = REQUIRED_TABLES - {"alembic_version", "permissions"}
REQUIRED_FUNCTIONS = {
    "nexora_context_allows",
    "nexora_resolve_session",
    "preserve_last_active_owner",
    "preserve_last_owner_user",
    "protect_auth_session_state",
    "protect_idempotency_state",
    "protect_outbox_state",
    "reject_append_only_change",
    "reject_immutable_foundation_field",
    "revoke_membership_sessions",
    "revoke_role_permission_sessions",
    "revoke_status_sessions",
    "revoke_tenant_sessions",
}
EXPECTED_CATALOG_SHA256 = "a3981e630def8e0fc3e9134fff66c1d95aef98e3dc8051027bff8dc008a33160"

PHASE_01_HEAD = "0001_foundation"
PHASE_02_HEAD = "0002_langgraph_checkpoint"
PHASE_03_HEAD = "0003_policy_approval"
# Newest first, matching `walk_revisions`. Extended additively in Phase 03 under
# amendment A-1: every Phase-01 and Phase-02 assertion below is unchanged, and the
# chain simply grew by one revision.
PHASE_04_HEAD = "0004_business_domain"
# Step-up gets its own revision: a session column has no business in a migration
# named `business_domain`.
STEP_UP_HEAD = "0005_session_step_up"
MIGRATION_CHAIN = [STEP_UP_HEAD, PHASE_04_HEAD, PHASE_03_HEAD, PHASE_02_HEAD, PHASE_01_HEAD]
CURRENT_HEAD = STEP_UP_HEAD

# Phase 03 changes the public catalog on purpose (amendment A-2). This pins the new
# shape so an *unintended* further change is still caught.
EXPECTED_PHASE_03_CATALOG_SHA256 = (
    "d0e6de8f5d09cab54127fcf1f71be710187298a80008e245e082aa1b9d3deeeb"
)

APPROVAL_TABLES = (
    "approval_requests",
    "approval_decisions",
    "approval_consumptions",
    "protected_effect_counters",
)
APPROVAL_HISTORY_TABLES = ("approval_decisions", "approval_consumptions")
PHASE_03_TABLES = REQUIRED_TABLES | set(APPROVAL_TABLES) | {"policy_action_catalogue"}
PHASE_03_TENANT_TABLES = TENANT_TABLES | set(APPROVAL_TABLES)
PHASE_03_TRIGGERS = frozenset(
    {
        "trg_approval_decisions_append_only",
        "trg_approval_consumptions_append_only",
        "trg_approval_requests_protect_state",
        "trg_user_roles_single_deputy",
    }
)
PHASE_03_FUNCTIONS = frozenset(
    {
        "enforce_single_active_deputy",
        "protect_approval_request_state",
        "reject_approval_history_change",
    }
)

# Phase 04 adds `clients` only. The offer, invoice and payment tables from packet
# §9 are absent on purpose: HD-004 is unresolved, and a placeholder would be the
# guessed default packet §8 forbids. When ADR-005 is accepted they arrive in their
# own revision and this set grows again.
PHASE_04_TABLES = PHASE_03_TABLES | {"clients"}
PHASE_04_TENANT_TABLES = PHASE_03_TENANT_TABLES | {"clients"}
PHASE_04_TRIGGERS = PHASE_03_TRIGGERS | {"trg_clients_protect_identity"}
PHASE_04_FUNCTIONS = PHASE_03_FUNCTIONS | {"protect_client_identity", "protect_session_step_up"}
PHASE_04_TRIGGERS = PHASE_04_TRIGGERS | {"trg_auth_sessions_protect_step_up"}
EXPECTED_PHASE_04_CATALOG_SHA256 = (
    "e99cb83d697c3069a8b70b6520b47b25735943fe41f929a4670d069fe4871bb5"
)

AGENT_SCHEMA = "nexora_agent"
AGENT_TABLES = {
    "agent_checkpoint_writes",
    "agent_checkpoints",
    "agent_operation_events",
    "agent_operations",
}
AGENT_FUNCTIONS = {
    "protect_agent_operation_state",
    "reject_agent_checkpoint_change",
    "reject_agent_event_change",
}
AGENT_TRIGGERS = {
    "trg_agent_checkpoints_immutable",
    "trg_agent_events_append_only",
    "trg_agent_operations_protect_state",
}
# Least privilege for the runtime role. DELETE is deliberately absent everywhere:
# operations are cancelled and retained, checkpoints are preserved for repair.
EXPECTED_AGENT_GRANTS = {
    ("agent_checkpoint_writes", "INSERT"),
    ("agent_checkpoint_writes", "SELECT"),
    ("agent_checkpoint_writes", "UPDATE"),
    ("agent_checkpoints", "INSERT"),
    ("agent_checkpoints", "SELECT"),
    ("agent_operation_events", "INSERT"),
    ("agent_operation_events", "SELECT"),
    ("agent_operations", "INSERT"),
    ("agent_operations", "SELECT"),
    ("agent_operations", "UPDATE"),
}
FORBIDDEN_AGENT_PRIVILEGES = {"DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
EXPECTED_AGENT_CATALOG_SHA256 = "8f5e428d2fcd1d8ba52758e0773342287b8c47c9d23c1e8fbad9d888c2834572"


def _catalog_hash(snapshot: dict[str, Any]) -> str:
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _without_head(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if key != "head"}


def _guard_local_database(url: str) -> None:
    parsed = make_url(url)
    exact_fixture = (
        parsed.host in {"127.0.0.1", "localhost"}
        and parsed.port == 54329
        and parsed.database == "nexora"
        and parsed.username == "nexora_migrator"
    )
    if not exact_fixture:
        raise RuntimeError("migration check refuses a non-fixture database identity")
    if os.environ.get("NEXORA_ENVIRONMENT") != "test":
        raise RuntimeError("destructive migration check requires the test environment")
    if os.environ.get("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK") != "true":
        raise RuntimeError("destructive migration check requires explicit opt-in")
    script = ScriptDirectory.from_config(Config("backend/alembic.ini"))
    heads = script.get_heads()
    revisions = list(script.walk_revisions())
    if heads != [CURRENT_HEAD] or [item.revision for item in revisions] != MIGRATION_CHAIN:
        raise RuntimeError(
            f"downgrade check requires the exact ordered revision chain {MIGRATION_CHAIN}"
        )


def _alembic(*arguments: str) -> None:
    command = [".venv/bin/alembic", "-c", "backend/alembic.ini", *arguments]
    print("$", " ".join(command), flush=True)
    # The executable and all possible arguments are constants owned by this script.
    subprocess.run(  # noqa: S603
        command, check=True, env={**os.environ, "NEXORA_ENVIRONMENT": "test"}
    )


def _snapshot(
    url: str,
    expected_head: str,
    *,
    expected_tables: frozenset[str] | None = None,
    tenant_tables: frozenset[str] | None = None,
    extra_triggers: frozenset[str] = frozenset(),
    extra_functions: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Snapshot the `public` catalog.

    The expected table and tenant-table sets are parameters rather than module
    constants because the set legitimately grows per revision. Defaulting to the
    Phase-01 sets keeps every existing call site asserting exactly what it did
    before (amendment A-1: additive only).
    """
    required = REQUIRED_TABLES if expected_tables is None else expected_tables
    tenant_scoped = TENANT_TABLES if tenant_tables is None else tenant_tables
    engine = create_engine(url)
    with engine.connect() as connection:
        tables = set(
            connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
        )
        if tables != required:
            raise AssertionError(
                f"unexpected tables: expected={sorted(required)} actual={sorted(tables)}"
            )
        head = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        if head != expected_head:
            raise AssertionError(f"unexpected migration head: {head}")
        rls_rows = connection.execute(
            text(
                """SELECT relname, relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relname = ANY(:tables)
                ORDER BY relname"""
            ),
            {"tables": sorted(tenant_scoped)},
        ).all()
        if {row[0] for row in rls_rows} != tenant_scoped:
            raise AssertionError("one or more tenant-sensitive tables are missing")
        if any(not row[1] or not row[2] for row in rls_rows):
            raise AssertionError("one or more tenant-sensitive tables lack ENABLE/FORCE RLS")
        private_table = connection.execute(
            text(
                """SELECT c.relname, owner.rolname, COALESCE(c.relacl::text, ''),
                          namespace_owner.rolname, COALESCE(n.nspacl::text, '')
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_roles owner ON owner.oid = c.relowner
                JOIN pg_roles namespace_owner ON namespace_owner.oid = n.nspowner
                WHERE n.nspname = 'nexora_private' AND c.relname = 'rls_context_secrets'"""
            )
        ).one_or_none()
        if private_table is None:
            raise AssertionError("private RLS context authority is missing")
        private_columns = connection.execute(
            text(
                """SELECT table_name, column_name, data_type, is_nullable
                FROM information_schema.columns WHERE table_schema = 'nexora_private'
                ORDER BY table_name, ordinal_position"""
            )
        ).all()
        private_access = connection.execute(
            text(
                """SELECT has_schema_privilege('nexora_runtime', 'nexora_private', 'USAGE'),
                          has_table_privilege(
                            'nexora_runtime', 'nexora_private.rls_context_secrets', 'SELECT'
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_class private_class,
                            LATERAL aclexplode(
                              COALESCE(
                                private_class.relacl,
                                acldefault('r', private_class.relowner)
                              )
                            ) acl
                            WHERE private_class.oid =
                              'nexora_private.rls_context_secrets'::regclass
                              AND acl.grantee = 0 AND acl.privilege_type = 'SELECT'
                          )"""
            )
        ).one()
        if any(private_access):
            raise AssertionError("runtime/PUBLIC can access the private RLS secret authority")
        function_rows = connection.execute(
            text(
                """SELECT p.proname, owner.rolname, COALESCE(p.proacl::text, ''),
                          pg_get_functiondef(p.oid)
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                JOIN pg_roles owner ON owner.oid = p.proowner
                WHERE n.nspname = 'public' AND p.proname = ANY(:names)
                ORDER BY p.proname"""
            ),
            {"names": sorted(REQUIRED_FUNCTIONS | extra_functions)},
        ).all()
        if {row.proname for row in function_rows} != REQUIRED_FUNCTIONS | extra_functions:
            raise AssertionError("required security/state function is missing")
        trigger_rows = connection.execute(
            text(
                """SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid)
                FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace
                ORDER BY c.relname, t.tgname"""
            )
        ).all()
        required_trigger_names = {
            "trg_audit_events_append_only",
            "trg_auth_sessions_protect_state",
            "trg_domain_events_append_only",
            "trg_idempotency_protect_state",
            "trg_outbox_protect_state",
            "trg_role_permissions_revoke_sessions",
            "trg_roles_name_immutable",
            "trg_tenants_revoke_sessions",
            "trg_tenants_slug_immutable",
            "trg_user_roles_preserve_owner",
            "trg_user_roles_revoke_sessions",
            "trg_users_preserve_owner",
            "trg_users_revoke_sessions",
        } | extra_triggers
        if {row.tgname for row in trigger_rows} != required_trigger_names:
            raise AssertionError("required security/state trigger is missing or unexpected")
        runtime = connection.execute(
            text(
                """SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
                FROM pg_roles WHERE rolname = 'nexora_runtime'"""
            )
        ).one()
        if any(runtime):
            raise AssertionError("nexora_runtime has an elevated role attribute")
        runtime_owned = connection.execute(
            text(
                """SELECT count(*) FROM pg_class c
                JOIN pg_roles r ON r.oid = c.relowner
                WHERE r.rolname = 'nexora_runtime' AND c.relkind IN ('r', 'p')"""
            )
        ).scalar_one()
        if runtime_owned:
            raise AssertionError("nexora_runtime owns a table")
        role_rows = connection.execute(
            text(
                """SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb,
                          rolinherit, rolbypassrls
                FROM pg_roles WHERE rolname IN
                  ('nexora_runtime', 'nexora_migrator', 'nexora_rls_guard')
                ORDER BY rolname"""
            )
        ).all()
        memberships = connection.execute(
            text(
                """SELECT member_role.rolname, granted_role.rolname
                FROM pg_auth_members membership
                JOIN pg_roles member_role ON member_role.oid = membership.member
                JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
                WHERE member_role.rolname LIKE 'nexora_%'
                   OR granted_role.rolname LIKE 'nexora_%'
                ORDER BY member_role.rolname, granted_role.rolname"""
            )
        ).all()
        objects = connection.execute(
            text(
                """SELECT c.relname, c.relkind, COALESCE(i.indisunique, false),
                          CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) ELSE '' END
                FROM pg_class c
                LEFT JOIN pg_index i ON i.indexrelid = c.oid
                WHERE c.relnamespace = 'public'::regnamespace
                  AND c.relkind IN ('r', 'i')
                ORDER BY c.relkind, c.relname"""
            )
        ).all()
        constraints = connection.execute(
            text(
                """SELECT conname, contype, pg_get_constraintdef(oid) FROM pg_constraint
                WHERE connamespace = 'public'::regnamespace ORDER BY conname"""
            )
        ).all()
        columns = connection.execute(
            text(
                """SELECT table_name, column_name, data_type, udt_name, is_nullable,
                          COALESCE(column_default, '')
                FROM information_schema.columns WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position"""
            )
        ).all()
        policies = connection.execute(
            text(
                """SELECT tablename, policyname, qual, with_check
                FROM pg_policies WHERE schemaname = 'public'
                ORDER BY tablename, policyname"""
            )
        ).all()
        if {row.tablename for row in policies} != tenant_scoped:
            raise AssertionError("tenant RLS policy set is incomplete")
        grants = connection.execute(
            text(
                """SELECT table_name, privilege_type FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND table_schema = 'public'
                ORDER BY table_name, privilege_type"""
            )
        ).all()
        return {
            "head": head,
            "objects": [tuple(row) for row in objects],
            "constraints": [tuple(row) for row in constraints],
            "columns": [tuple(row) for row in columns],
            "functions": [tuple(row) for row in function_rows],
            "private_table": tuple(private_table),
            "private_columns": [tuple(row) for row in private_columns],
            "private_access": tuple(private_access),
            "roles": [tuple(row) for row in role_rows],
            "memberships": [tuple(row) for row in memberships],
            "triggers": [tuple(row) for row in trigger_rows],
            "policies": [tuple(row) for row in policies],
            "grants": [tuple(row) for row in grants],
            "rls": [tuple(row) for row in rls_rows],
        }


def _agent_snapshot(url: str) -> dict[str, Any]:
    """Phase-02 runtime schema. Asserted semantically, then hashed as a drift detector."""
    engine = create_engine(url)
    with engine.connect() as connection:
        tables = set(
            connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = :schema"),
                {"schema": AGENT_SCHEMA},
            ).scalars()
        )
        if tables != AGENT_TABLES:
            raise AssertionError(
                f"unexpected agent tables: expected={sorted(AGENT_TABLES)} actual={sorted(tables)}"
            )
        schema_owner = connection.execute(
            text("SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = :schema"),
            {"schema": AGENT_SCHEMA},
        ).scalar_one()
        if schema_owner != "nexora_migrator":
            raise AssertionError(f"agent schema is owned by {schema_owner}")
        schema_access = connection.execute(
            text(
                """SELECT has_schema_privilege('nexora_runtime', :schema, 'USAGE'),
                          has_schema_privilege('nexora_runtime', :schema, 'CREATE'),
                          pg_catalog.has_schema_privilege('public', :schema, 'USAGE')"""
            ),
            {"schema": AGENT_SCHEMA},
        ).one()
        if not schema_access[0]:
            raise AssertionError("runtime cannot use the agent schema")
        if schema_access[1]:
            raise AssertionError("runtime can create objects in the agent schema")
        if schema_access[2]:
            raise AssertionError("PUBLIC can use the agent schema")

        rls_rows = connection.execute(
            text(
                """SELECT relname, relrowsecurity, relforcerowsecurity, relowner::regrole::text
                FROM pg_class
                WHERE relnamespace = CAST(:schema AS regnamespace) AND relname = ANY(:tables)
                ORDER BY relname"""
            ),
            {"schema": AGENT_SCHEMA, "tables": sorted(AGENT_TABLES)},
        ).all()
        if {row[0] for row in rls_rows} != AGENT_TABLES:
            raise AssertionError("an agent table is missing from the RLS inspection")
        if any(not row[1] or not row[2] for row in rls_rows):
            raise AssertionError("an agent table lacks ENABLE/FORCE RLS")
        if any(row[3] != "nexora_migrator" for row in rls_rows):
            raise AssertionError("an agent table is not owned by nexora_migrator")

        policies = connection.execute(
            text(
                """SELECT tablename, policyname, qual, with_check FROM pg_policies
                WHERE schemaname = :schema ORDER BY tablename, policyname"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        if {row.tablename for row in policies} != AGENT_TABLES:
            raise AssertionError("agent tenant/actor policy set is incomplete")
        for row in policies:
            if "nexora_context_allows" not in (row.qual or ""):
                raise AssertionError(f"{row.tablename} policy does not use the tenant authority")
            if "app.actor_id" not in (row.qual or ""):
                raise AssertionError(f"{row.tablename} policy does not bind the actor")

        grants = connection.execute(
            text(
                """SELECT table_name, privilege_type FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND table_schema = :schema
                ORDER BY table_name, privilege_type"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        actual_grants = {(row.table_name, row.privilege_type) for row in grants}
        if actual_grants != EXPECTED_AGENT_GRANTS:
            raise AssertionError(
                "agent runtime grants differ from the least-privilege contract: "
                f"unexpected={sorted(actual_grants - EXPECTED_AGENT_GRANTS)} "
                f"missing={sorted(EXPECTED_AGENT_GRANTS - actual_grants)}"
            )
        forbidden = {item for item in actual_grants if item[1] in FORBIDDEN_AGENT_PRIVILEGES}
        if forbidden:
            raise AssertionError(f"runtime holds a forbidden agent privilege: {sorted(forbidden)}")

        other_grantees = connection.execute(
            text(
                """SELECT DISTINCT grantee FROM information_schema.role_table_grants
                WHERE table_schema = :schema
                  AND grantee NOT IN ('nexora_runtime', 'nexora_migrator', 'nexora_rls_guard')"""
            ),
            {"schema": AGENT_SCHEMA},
        ).scalars()
        unexpected_grantees = sorted(other_grantees)
        if unexpected_grantees:
            raise AssertionError(f"unexpected agent schema grantee: {unexpected_grantees}")

        # The runtime must not be able to reach business tables through this schema.
        cross_schema = connection.execute(
            text(
                """SELECT count(*) FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND table_schema = 'public'
                  AND privilege_type IN ('DELETE', 'TRUNCATE')"""
            )
        ).scalar_one()
        if cross_schema:
            raise AssertionError("runtime gained DELETE/TRUNCATE on a public table")

        function_rows = connection.execute(
            text(
                """SELECT p.proname, p.proowner::regrole::text, COALESCE(p.proacl::text, ''),
                          pg_get_functiondef(p.oid)
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema ORDER BY p.proname"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        if {row.proname for row in function_rows} != AGENT_FUNCTIONS:
            raise AssertionError("required agent state/append-only function is missing")

        trigger_rows = connection.execute(
            text(
                """SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid)
                FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                WHERE NOT t.tgisinternal AND c.relnamespace = CAST(:schema AS regnamespace)
                ORDER BY c.relname, t.tgname"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        if {row.tgname for row in trigger_rows} != AGENT_TRIGGERS:
            raise AssertionError("required agent trigger is missing or unexpected")

        objects = connection.execute(
            text(
                """SELECT c.relname, c.relkind, COALESCE(i.indisunique, false),
                          CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) ELSE '' END
                FROM pg_class c
                LEFT JOIN pg_index i ON i.indexrelid = c.oid
                WHERE c.relnamespace = CAST(:schema AS regnamespace) AND c.relkind IN ('r', 'i')
                ORDER BY c.relkind, c.relname"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        index_definitions = [row[3] for row in objects if row[1] == "i"]
        terminal_index = [
            definition
            for definition in index_definitions
            if "uq_agent_events_terminal_once" in definition
        ]
        # Postgres renders the predicate as ((type)::text = 'stream.completed'::text),
        # so assert the properties rather than one exact rendering.
        if len(terminal_index) != 1:
            raise AssertionError("terminal-event uniqueness index is missing")
        definition = terminal_index[0]
        if not definition.startswith("CREATE UNIQUE INDEX"):
            raise AssertionError("terminal-event index is not unique")
        if " WHERE " not in definition or "'stream.completed'" not in definition:
            raise AssertionError("terminal-event index is not restricted to the terminal type")

        constraints = connection.execute(
            text(
                """SELECT conname, contype, pg_get_constraintdef(oid) FROM pg_constraint
                WHERE connamespace = CAST(:schema AS regnamespace) ORDER BY conname"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        columns = connection.execute(
            text(
                """SELECT table_name, column_name, data_type, udt_name, is_nullable,
                          COALESCE(column_default, '')
                FROM information_schema.columns WHERE table_schema = :schema
                ORDER BY table_name, ordinal_position"""
            ),
            {"schema": AGENT_SCHEMA},
        ).all()
        # No business column may appear in a coordination table.
        forbidden_columns = {
            "amount",
            "approval_id",
            "client_id",
            "currency",
            "invoice_id",
            "offer_id",
            "payment_id",
            "risk_level",
        }
        present = {row.column_name for row in columns}
        if present & forbidden_columns:
            raise AssertionError(
                f"business column in agent schema: {sorted(present & forbidden_columns)}"
            )

        return {
            "objects": [tuple(row) for row in objects],
            "constraints": [tuple(row) for row in constraints],
            "columns": [tuple(row) for row in columns],
            "functions": [tuple(row) for row in function_rows],
            "triggers": [tuple(row) for row in trigger_rows],
            "policies": [tuple(row) for row in policies],
            "grants": sorted(actual_grants),
            "rls": [tuple(row) for row in rls_rows],
            "schema_owner": schema_owner,
        }


def _clear_fixture_rows(url: str) -> None:
    """Empty the disposable fixture database's runtime rows, if the schema exists.

    Only ever reached after `_guard_local_database` has proved this is the exact
    local fixture identity and the destructive opt-in is present.
    """
    engine = create_engine(url)
    with engine.begin() as connection:
        exists = connection.execute(
            text("SELECT to_regclass('nexora_agent.agent_operations') IS NOT NULL")
        ).scalar_one()
        if exists:
            connection.execute(
                text(
                    """TRUNCATE TABLE nexora_agent.agent_checkpoint_writes,
                    nexora_agent.agent_checkpoints, nexora_agent.agent_operation_events,
                    nexora_agent.agent_operations CASCADE"""
                )
            )


def _assert_phase03_boundary(url: str) -> None:
    """Assert the Phase-03 approval boundary directly against PostgreSQL.

    Additive: nothing here relaxes a Phase-01 or Phase-02 assertion. These are the
    properties `ADR-004` states as *database* properties, so they are checked
    against the database rather than through the service that relies on them.
    """
    engine = create_engine(url)
    with engine.connect() as connection:
        present = {
            row[0]
            for row in connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
        missing = (set(APPROVAL_TABLES) | {"policy_action_catalogue"}) - present
        if missing:
            raise AssertionError(f"Phase-03 tables are missing: {sorted(missing)}")

        rls = (
            connection.execute(
                text(
                    """SELECT relname FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relname = ANY(:tables)
                  AND relrowsecurity AND relforcerowsecurity"""
                ),
                {"tables": list(APPROVAL_TABLES)},
            )
            .scalars()
            .all()
        )
        if set(rls) != set(APPROVAL_TABLES):
            raise AssertionError("an approval table lacks ENABLE/FORCE row-level security")

        deletes = (
            connection.execute(
                text(
                    """SELECT table_name FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND privilege_type = 'DELETE'
                  AND table_name = ANY(:tables)"""
                ),
                {"tables": [*APPROVAL_TABLES, "policy_action_catalogue"]},
            )
            .scalars()
            .all()
        )
        if deletes:
            raise AssertionError(f"nexora_runtime holds DELETE on {sorted(deletes)}")

        updates = (
            connection.execute(
                text(
                    """SELECT table_name FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND privilege_type = 'UPDATE'
                  AND table_name = ANY(:tables)"""
                ),
                {"tables": list(APPROVAL_HISTORY_TABLES)},
            )
            .scalars()
            .all()
        )
        if updates:
            raise AssertionError(f"approval history is not append-only: {sorted(updates)}")

        roles_check = connection.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_roles_name'"
            )
        ).scalar_one()
        if "DEPUTY" not in roles_check:
            raise AssertionError("ck_roles_name does not admit the ADR-004 DEPUTY role")

        seeded = connection.execute(
            text("SELECT count(*) FROM policy_action_catalogue WHERE catalogue_version = 1")
        ).scalar_one()
        if seeded != 21:
            raise AssertionError(f"catalogue v1 seeded {seeded} actions, expected 21")

        for permission_key in ("approval.decide", "approval.decide.high"):
            exists = connection.execute(
                text("SELECT count(*) FROM permissions WHERE permission_key = :key"),
                {"key": permission_key},
            ).scalar_one()
            if not exists:
                raise AssertionError(f"permission {permission_key} is missing")


def _assert_phase04_boundary(url: str) -> None:
    """Assert the Phase-04 client boundary directly against PostgreSQL."""
    engine = create_engine(url)
    with engine.connect() as connection:
        forced = connection.execute(
            text(
                """SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relname = 'clients'"""
            )
        ).scalar_one()
        if not forced:
            raise AssertionError("clients lacks ENABLE/FORCE row-level security")

        deletes = (
            connection.execute(
                text(
                    """SELECT privilege_type FROM information_schema.role_table_grants
                    WHERE grantee = 'nexora_runtime' AND table_name = 'clients'
                      AND privilege_type = 'DELETE'"""
                )
            )
            .scalars()
            .all()
        )
        if deletes:
            raise AssertionError("nexora_runtime holds DELETE on clients")

        unique = connection.execute(
            text(
                """SELECT indexdef FROM pg_indexes
                WHERE tablename = 'clients' AND indexname = 'uq_clients_active_identity'"""
            )
        ).scalar_one_or_none()
        if unique is None or "ACTIVE" not in unique:
            raise AssertionError("the active client identity index is missing or not partial")

        # The financial tables must NOT exist yet: HD-004 is unresolved.
        premature = (
            connection.execute(
                text(
                    """SELECT tablename FROM pg_tables WHERE schemaname = 'public'
                    AND tablename = ANY(:tables)"""
                ),
                {"tables": ["offers", "offer_items", "invoices", "invoice_items", "payments"]},
            )
            .scalars()
            .all()
        )
        if premature:
            raise AssertionError(
                f"financial tables exist while HD-004 is unresolved: {sorted(premature)}"
            )

        for permission_key in ("client.read", "client.write"):
            exists = connection.execute(
                text("SELECT count(*) FROM permissions WHERE permission_key = :key"),
                {"key": permission_key},
            ).scalar_one()
            if not exists:
                raise AssertionError(f"permission {permission_key} is missing")


def main() -> None:
    url = get_migration_settings().migration_database_url
    _guard_local_database(url)

    # Start from base so the run is hermetic regardless of what the previous run
    # or a preceding test suite left behind. Without this the check silently
    # depends on an already-empty fixture database.
    #
    # The Phase-02 downgrade guard deliberately refuses while any operation is
    # still active, so the disposable fixture rows are cleared first. The guard
    # itself is proved separately by
    # backend/tests/security/agent/test_migration_boundary.py.
    _clear_fixture_rows(url)
    _alembic("downgrade", "base")

    # Stop at the Phase-01 head first. Reproducing the accepted Phase-01 catalog
    # hash byte-for-byte proves Phase 02 did not renegotiate that contract.
    _alembic("upgrade", PHASE_01_HEAD)
    phase01 = _snapshot(url, PHASE_01_HEAD)
    phase01_hash = _catalog_hash(phase01)
    if phase01_hash != EXPECTED_CATALOG_SHA256:
        raise AssertionError(
            f"catalog differs from the exact Phase-01 schema contract: actual={phase01_hash}"
        )

    # Stop at the Phase-02 head next. The Phase-01 public catalog must still be
    # byte-identical here: Phase 02's isolation claim is unaffected by Phase 03.
    _alembic("upgrade", PHASE_02_HEAD)
    phase02 = _snapshot(url, PHASE_02_HEAD)
    phase02_agent = _agent_snapshot(url)
    if _without_head(phase02) != _without_head(phase01):
        raise AssertionError("Phase 02 mutated the Phase-01 public catalog")
    phase02_agent_hash = _catalog_hash(phase02_agent)
    if phase02_agent_hash != EXPECTED_AGENT_CATALOG_SHA256:
        raise AssertionError(
            f"agent catalog differs from the Phase-02 schema contract: actual={phase02_agent_hash}"
        )

    # Phase 03 deliberately renegotiates the public catalog (amendment A-2:
    # ADR-004 requires a DEPUTY role that ck_roles_name forbids). The new shape is
    # pinned by its own hash, so an *unintended* further change still fails.
    _alembic("upgrade", PHASE_03_HEAD)
    phase03 = _snapshot(
        url,
        PHASE_03_HEAD,
        expected_tables=frozenset(PHASE_03_TABLES),
        tenant_tables=frozenset(PHASE_03_TENANT_TABLES),
        extra_triggers=PHASE_03_TRIGGERS,
        extra_functions=PHASE_03_FUNCTIONS,
    )
    phase03_hash = _catalog_hash(phase03)
    if phase03_hash != EXPECTED_PHASE_03_CATALOG_SHA256:
        raise AssertionError(
            f"catalog differs from the Phase-03 schema contract: actual={phase03_hash}"
        )

    _alembic("upgrade", "head")
    first = _snapshot(
        url,
        CURRENT_HEAD,
        expected_tables=frozenset(PHASE_04_TABLES),
        tenant_tables=frozenset(PHASE_04_TENANT_TABLES),
        extra_triggers=PHASE_04_TRIGGERS,
        extra_functions=PHASE_04_FUNCTIONS,
    )
    first_agent = _agent_snapshot(url)
    first_hash = _catalog_hash(first)
    if first_hash != EXPECTED_PHASE_04_CATALOG_SHA256:
        raise AssertionError(
            f"catalog differs from the Phase-04 schema contract: actual={first_hash}"
        )
    if first_agent != phase02_agent:
        raise AssertionError("a later phase mutated the Phase-02 agent schema")
    _assert_phase03_boundary(url)
    _assert_phase04_boundary(url)

    _alembic("upgrade", "head")
    if (
        _snapshot(
            url,
            CURRENT_HEAD,
            expected_tables=frozenset(PHASE_04_TABLES),
            tenant_tables=frozenset(PHASE_04_TENANT_TABLES),
            extra_triggers=PHASE_04_TRIGGERS,
            extra_functions=PHASE_04_FUNCTIONS,
        ),
        _agent_snapshot(url),
    ) != (first, first_agent):
        raise AssertionError("second upgrade produced catalog drift")

    _alembic("downgrade", "base")
    _alembic("upgrade", "head")
    if (
        _snapshot(
            url,
            CURRENT_HEAD,
            expected_tables=frozenset(PHASE_04_TABLES),
            tenant_tables=frozenset(PHASE_04_TENANT_TABLES),
            extra_triggers=PHASE_04_TRIGGERS,
            extra_functions=PHASE_04_FUNCTIONS,
        ),
        _agent_snapshot(url),
    ) != (first, first_agent):
        raise AssertionError("downgrade/upgrade recovery produced catalog drift")

    print(
        f"migration-check: {PHASE_01_HEAD} -> {PHASE_02_HEAD} -> {PHASE_03_HEAD} -> "
        f"{CURRENT_HEAD}, no drift, "
        "Phase-01 catalog reproduced, Phase-02 agent schema unchanged, "
        "Phase-03 approval and Phase-04 client RLS/grants verified"
    )


if __name__ == "__main__":
    main()
