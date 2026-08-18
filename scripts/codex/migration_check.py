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


def _catalog_hash(snapshot: dict[str, Any]) -> str:
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
    if heads != ["0001_foundation"] or [item.revision for item in revisions] != ["0001_foundation"]:
        raise RuntimeError("downgrade check requires 0001_foundation to be the sole revision/head")


def _alembic(*arguments: str) -> None:
    command = [".venv/bin/alembic", "-c", "backend/alembic.ini", *arguments]
    print("$", " ".join(command), flush=True)
    # The executable and all possible arguments are constants owned by this script.
    subprocess.run(  # noqa: S603
        command, check=True, env={**os.environ, "NEXORA_ENVIRONMENT": "test"}
    )


def _snapshot(url: str) -> dict[str, Any]:
    engine = create_engine(url)
    with engine.connect() as connection:
        tables = set(
            connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).scalars()
        )
        if tables != REQUIRED_TABLES:
            raise AssertionError(
                f"unexpected tables: expected={sorted(REQUIRED_TABLES)} actual={sorted(tables)}"
            )
        head = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        if head != "0001_foundation":
            raise AssertionError(f"unexpected migration head: {head}")
        rls_rows = connection.execute(
            text(
                """SELECT relname, relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relname = ANY(:tables)
                ORDER BY relname"""
            ),
            {"tables": sorted(TENANT_TABLES)},
        ).all()
        if {row[0] for row in rls_rows} != TENANT_TABLES:
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
            {"names": sorted(REQUIRED_FUNCTIONS)},
        ).all()
        if {row.proname for row in function_rows} != REQUIRED_FUNCTIONS:
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
        }
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
        if {row.tablename for row in policies} != TENANT_TABLES:
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


def main() -> None:
    url = get_migration_settings().migration_database_url
    _guard_local_database(url)
    _alembic("upgrade", "head")
    first = _snapshot(url)
    if _catalog_hash(first) != EXPECTED_CATALOG_SHA256:
        raise AssertionError("catalog differs from the exact Phase-01 schema contract")
    _alembic("upgrade", "head")
    second = _snapshot(url)
    if first != second:
        raise AssertionError("second upgrade produced catalog drift")
    _alembic("downgrade", "base")
    _alembic("upgrade", "head")
    recovered = _snapshot(url)
    if first != recovered:
        raise AssertionError("downgrade/upgrade recovery produced catalog drift")
    print("migration-check: 0001_foundation, no drift, RLS/grants verified")


if __name__ == "__main__":
    main()
