"""Create the Phase-02 agent runtime coordination storage.

Revision ID: 0002_langgraph_checkpoint
Revises: 0001_foundation
Create Date: 2026-08-19

Everything lives in a dedicated ``nexora_agent`` schema rather than ``public``.
That gives the checkpoint role a boundary it cannot reach past (packet 12), and
it leaves every ``public`` object created by ``0001_foundation`` byte-identical,
so the accepted Phase-01 catalog contract is preserved rather than renegotiated.

These tables coordinate execution. They are never business truth: no client,
offer, invoice, payment, approval or risk column exists here, and none may be
added by a later phase without its own revision.
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_langgraph_checkpoint"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())

SCHEMA = "nexora_agent"

OPERATION_STATES = ("RECEIVED", "RUNNING", "WAITING", "COMPLETED", "FAILED", "CANCELLED")
ACTIVE_OPERATION_STATES = ("RECEIVED", "RUNNING", "WAITING")
TERMINAL_OPERATION_STATES = ("COMPLETED", "FAILED", "CANCELLED")
RUNTIME_ERROR_CODES = (
    "INVALID_STATE",
    "CHECKPOINT_CONFLICT",
    "OPERATION_NOT_FOUND",
    "DEPENDENCY_TIMEOUT",
    "DEPENDENCY_UNAVAILABLE",
    "INTERNAL",
    "STATE_VERSION_UNSUPPORTED",
)
STREAM_EVENT_TYPES = (
    "operation.started",
    "operation.state_changed",
    "message.delta",
    "message.completed",
    "operation.failed",
    "stream.completed",
)
TERMINAL_EVENT_TYPE = "stream.completed"

AGENT_TABLES = (
    "agent_operations",
    "agent_operation_events",
    "agent_checkpoints",
    "agent_checkpoint_writes",
)


def _quoted(values: Sequence[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _timestamps() -> list[sa.Column[object]]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def _enable_rls(table: str) -> None:
    """Tenant *and* actor ownership, enforced by the database as well as the service.

    ``BR-02-002`` requires that loading a conversation or operation prove both.
    The tenant half delegates to the Phase-01 signed-context authority; the actor
    half is checked directly, mirroring how ``idempotency_records`` is protected.
    """
    qualified = f'"{SCHEMA}"."{table}"'
    op.execute(f"ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY")
    predicate = (
        "public.nexora_context_allows(tenant_id) "
        "AND actor_id::text = current_setting('app.actor_id', true)"
    )
    op.execute(
        f'CREATE POLICY "tenant_actor_isolation_{table}" ON {qualified} '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA {SCHEMA} AUTHORIZATION nexora_migrator")
    op.execute(f"REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC")

    op.create_table(
        "agent_operations",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("public.tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, sa.ForeignKey("public.users.id"), nullable=False),
        sa.Column("conversation_id", UUID, nullable=False),
        sa.Column("client_request_id", sa.String(200), nullable=False),
        sa.Column("thread_id", sa.String(32), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("route", sa.String(32), nullable=True),
        sa.Column("contract_version", sa.SmallInteger(), nullable=False),
        sa.Column("state_schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("checkpoint_seq", sa.BigInteger(), nullable=False),
        sa.Column("error_code", sa.String(32), nullable=True),
        sa.Column("correlation_id", UUID, nullable=False),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            f"state IN ({_quoted(OPERATION_STATES)})", name="ck_agent_operations_state"
        ),
        sa.CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_quoted(RUNTIME_ERROR_CODES)})",
            name="ck_agent_operations_error_code",
        ),
        sa.CheckConstraint("checkpoint_seq >= 0", name="ck_agent_operations_checkpoint_seq"),
        sa.CheckConstraint(
            f"(state IN ({_quoted(TERMINAL_OPERATION_STATES)})) = (terminal_at IS NOT NULL)",
            name="ck_agent_operations_terminal_at",
        ),
        sa.CheckConstraint("contract_version >= 1", name="ck_agent_operations_contract_version"),
        sa.CheckConstraint(
            "state_schema_version >= 1", name="ck_agent_operations_state_schema_version"
        ),
        # BR-02-001: identical (tenant, actor, client_request_id) resolves to one operation.
        sa.UniqueConstraint(
            "tenant_id", "actor_id", "client_request_id", name="uq_agent_operations_request"
        ),
        sa.UniqueConstraint("tenant_id", "thread_id", name="uq_agent_operations_thread"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_agent_operations_tenant_id", "agent_operations", ["tenant_id"], schema=SCHEMA
    )
    op.create_index(
        "ix_agent_operations_tenant_actor",
        "agent_operations",
        ["tenant_id", "actor_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_agent_operations_conversation",
        "agent_operations",
        ["tenant_id", "conversation_id"],
        schema=SCHEMA,
    )

    op.create_table(
        "agent_operation_events",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("public.tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, sa.ForeignKey("public.users.id"), nullable=False),
        sa.Column(
            "operation_id",
            UUID,
            sa.ForeignKey(f"{SCHEMA}.agent_operations.id"),
            nullable=False,
        ),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("type", sa.String(40), nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.Column("contract_version", sa.SmallInteger(), nullable=False),
        sa.Column("emitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"type IN ({_quoted(STREAM_EVENT_TYPES)})", name="ck_agent_events_type"),
        sa.CheckConstraint("sequence >= 1", name="ck_agent_events_sequence"),
        sa.CheckConstraint("contract_version >= 1", name="ck_agent_events_contract_version"),
        # BR-02-003: the sequence is monotonic and stable per operation.
        sa.UniqueConstraint("operation_id", "sequence", name="uq_agent_events_sequence"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_agent_events_tenant_id", "agent_operation_events", ["tenant_id"], schema=SCHEMA
    )
    op.create_index(
        "ix_agent_events_operation_sequence",
        "agent_operation_events",
        ["operation_id", "sequence"],
        schema=SCHEMA,
    )
    # BR-02-003: the terminal event happens exactly once, enforced by the database
    # rather than by a service-side check that a concurrent worker could race.
    op.execute(
        f"CREATE UNIQUE INDEX uq_agent_events_terminal_once "
        f"ON {SCHEMA}.agent_operation_events (operation_id) "
        f"WHERE type = '{TERMINAL_EVENT_TYPE}'"
    )

    op.create_table(
        "agent_checkpoints",
        sa.Column("thread_id", sa.String(32), primary_key=True),
        sa.Column("checkpoint_ns", sa.String(128), primary_key=True),
        sa.Column("checkpoint_id", sa.String(64), primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("public.tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, sa.ForeignKey("public.users.id"), nullable=False),
        sa.Column("parent_checkpoint_id", sa.String(64), nullable=True),
        sa.Column("checkpoint_seq", sa.BigInteger(), nullable=False),
        sa.Column("state_schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("checkpoint_nonce", postgresql.BYTEA(), nullable=False),
        sa.Column("checkpoint_ciphertext", postgresql.BYTEA(), nullable=False),
        sa.Column("metadata_nonce", postgresql.BYTEA(), nullable=False),
        sa.Column("metadata_ciphertext", postgresql.BYTEA(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("checkpoint_seq >= 0", name="ck_agent_checkpoints_seq"),
        sa.CheckConstraint(
            "state_schema_version >= 1", name="ck_agent_checkpoints_state_schema_version"
        ),
        # A stale writer loses this race and is told CHECKPOINT_CONFLICT; the
        # latest durable sequence is never overwritten.
        sa.UniqueConstraint(
            "thread_id", "checkpoint_ns", "checkpoint_seq", name="uq_agent_checkpoints_seq"
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_agent_checkpoints_tenant_id", "agent_checkpoints", ["tenant_id"], schema=SCHEMA
    )
    op.create_index(
        "ix_agent_checkpoints_thread_seq",
        "agent_checkpoints",
        ["thread_id", "checkpoint_ns", "checkpoint_seq"],
        schema=SCHEMA,
    )

    op.create_table(
        "agent_checkpoint_writes",
        sa.Column("thread_id", sa.String(32), primary_key=True),
        sa.Column("checkpoint_ns", sa.String(128), primary_key=True),
        sa.Column("checkpoint_id", sa.String(64), primary_key=True),
        sa.Column("task_id", sa.String(64), primary_key=True),
        sa.Column("idx", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("public.tenants.id"), nullable=False),
        sa.Column("actor_id", UUID, sa.ForeignKey("public.users.id"), nullable=False),
        sa.Column("channel", sa.String(128), nullable=False),
        sa.Column("task_path", sa.String(256), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("value_nonce", postgresql.BYTEA(), nullable=False),
        sa.Column("value_ciphertext", postgresql.BYTEA(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("idx >= -1", name="ck_agent_checkpoint_writes_idx"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_agent_checkpoint_writes_tenant_id",
        "agent_checkpoint_writes",
        ["tenant_id"],
        schema=SCHEMA,
    )

    for table in AGENT_TABLES:
        _enable_rls(table)

    # The event ledger is append-oriented: an emitted lifecycle event is evidence
    # and is never rewritten to make a later replay look consistent.
    op.execute(
        f"""CREATE FUNCTION {SCHEMA}.reject_agent_event_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'agent event ledger is append-only' USING ERRCODE = '42501';
        END
        $$"""
    )
    op.execute(
        f"""CREATE TRIGGER trg_agent_events_append_only
        BEFORE UPDATE OR DELETE ON {SCHEMA}.agent_operation_events
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.reject_agent_event_change()"""
    )

    # Checkpoints are immutable once durable. Preserving an unsupported or corrupt
    # checkpoint is required by the packet; deleting one to make a resume pass is not.
    op.execute(
        f"""CREATE FUNCTION {SCHEMA}.reject_agent_checkpoint_change() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'agent checkpoints are immutable' USING ERRCODE = '42501';
        END
        $$"""
    )
    op.execute(
        f"""CREATE TRIGGER trg_agent_checkpoints_immutable
        BEFORE UPDATE OR DELETE ON {SCHEMA}.agent_checkpoints
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.reject_agent_checkpoint_change()"""
    )

    op.execute(
        f"""CREATE FUNCTION {SCHEMA}.protect_agent_operation_state() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
          allowed text[];
        BEGIN
          IF session_user <> 'nexora_runtime' THEN RETURN NEW; END IF;
          IF NEW.id IS DISTINCT FROM OLD.id
             OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
             OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
             OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
             OR NEW.client_request_id IS DISTINCT FROM OLD.client_request_id
             OR NEW.thread_id IS DISTINCT FROM OLD.thread_id
             OR NEW.contract_version IS DISTINCT FROM OLD.contract_version
             OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
             OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'immutable agent operation field changed' USING ERRCODE = '42501';
          END IF;
          IF OLD.state IN ({_quoted(TERMINAL_OPERATION_STATES)}) THEN
            RAISE EXCEPTION 'terminal agent operation is immutable' USING ERRCODE = '42501';
          END IF;
          allowed := CASE OLD.state
            WHEN 'RECEIVED' THEN ARRAY['RECEIVED', 'RUNNING', 'FAILED', 'CANCELLED']
            WHEN 'RUNNING' THEN ARRAY['RUNNING', 'WAITING', 'COMPLETED', 'FAILED', 'CANCELLED']
            WHEN 'WAITING' THEN ARRAY['WAITING', 'RUNNING', 'FAILED', 'CANCELLED']
            ELSE ARRAY[]::text[]
          END;
          IF NOT (NEW.state = ANY(allowed)) THEN
            RAISE EXCEPTION 'invalid agent operation transition' USING ERRCODE = '42501';
          END IF;
          IF NEW.checkpoint_seq < OLD.checkpoint_seq THEN
            RAISE EXCEPTION 'agent checkpoint sequence cannot move backwards'
              USING ERRCODE = '42501';
          END IF;
          RETURN NEW;
        END
        $$"""
    )
    op.execute(
        f"""CREATE TRIGGER trg_agent_operations_protect_state
        BEFORE UPDATE ON {SCHEMA}.agent_operations
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.protect_agent_operation_state()"""
    )

    op.execute(f"REVOKE ALL ON FUNCTION {SCHEMA}.reject_agent_event_change() FROM PUBLIC")
    op.execute(f"REVOKE ALL ON FUNCTION {SCHEMA}.reject_agent_checkpoint_change() FROM PUBLIC")
    op.execute(f"REVOKE ALL ON FUNCTION {SCHEMA}.protect_agent_operation_state() FROM PUBLIC")

    # Least privilege. No DELETE is granted anywhere in this schema: operations are
    # cancelled and retained, never hard-deleted, and checkpoints are preserved for
    # repair. The runtime role owns nothing here; nexora_migrator does.
    op.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO nexora_runtime")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {SCHEMA}.agent_operations TO nexora_runtime")
    op.execute(f"GRANT SELECT, INSERT ON {SCHEMA}.agent_operation_events TO nexora_runtime")
    op.execute(f"GRANT SELECT, INSERT ON {SCHEMA}.agent_checkpoints TO nexora_runtime")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON {SCHEMA}.agent_checkpoint_writes TO nexora_runtime"
    )

    # The downgrade guard must be able to see active operations despite FORCE RLS.
    op.execute(f"GRANT USAGE ON SCHEMA {SCHEMA} TO nexora_rls_guard")
    op.execute(f"GRANT SELECT ON {SCHEMA}.agent_operations TO nexora_rls_guard")


def active_operation_count(bind: sa.Connection) -> int:
    """Count operations that have not reached a terminal state.

    FORCE RLS applies to the table owner too, so the guard role performs the read.
    Extracted from `downgrade` so the refusal below can be tested directly rather
    than only as a side effect of a full migration run.
    """
    bind.execute(sa.text("SET LOCAL ROLE nexora_rls_guard"))
    try:
        return int(
            bind.execute(
                sa.text(
                    "SELECT count(*) FROM nexora_agent.agent_operations WHERE state = ANY(:states)"
                ),
                {"states": list(ACTIVE_OPERATION_STATES)},
            ).scalar_one()
        )
    finally:
        bind.execute(sa.text("RESET ROLE"))


def assert_downgrade_allowed(bind: sa.Connection) -> None:
    """Refuse to drop runtime storage outside a disposable environment or while busy."""
    if os.environ.get("NEXORA_ENVIRONMENT") not in {"test", "development"}:
        raise RuntimeError(
            "agent runtime downgrade requires a disposable test/development database"
        )
    if os.environ.get("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK") != "true":
        raise RuntimeError("agent runtime downgrade requires explicit destructive opt-in")
    active = active_operation_count(bind)
    if active:
        raise RuntimeError(
            f"refusing to drop agent runtime storage: {active} operations are active"
        )


def downgrade() -> None:
    """Disposable environments only, and only when nothing is still running."""
    assert_downgrade_allowed(op.get_bind())

    op.execute(f"DROP FUNCTION {SCHEMA}.protect_agent_operation_state() CASCADE")
    op.execute(f"DROP FUNCTION {SCHEMA}.reject_agent_checkpoint_change() CASCADE")
    op.execute(f"DROP FUNCTION {SCHEMA}.reject_agent_event_change() CASCADE")
    for table in reversed(AGENT_TABLES):
        op.drop_table(table, schema=SCHEMA)
    op.execute(f"DROP SCHEMA {SCHEMA}")
