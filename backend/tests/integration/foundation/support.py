from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_migration_settings, get_settings
from app.contracts import ActorContext
from app.db import build_engine, build_session_factory
from app.identity import TenantProvisioner

FIXED_NOW = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
TENANT_A = UUID("20000000-0000-0000-0000-000000000001")
TENANT_B = UUID("20000000-0000-0000-0000-000000000002")
ACTOR_A = UUID("30000000-0000-0000-0000-000000000001")
ACTOR_B = UUID("30000000-0000-0000-0000-000000000002")
CORRELATION_A = UUID("90000000-0000-0000-0000-000000000001")
CORRELATION_B = UUID("90000000-0000-0000-0000-000000000002")


def migration_engine() -> Engine:
    return create_engine(get_migration_settings().migration_database_url, pool_pre_ping=True)


def runtime_sessions(*, pool_size: int = 5) -> sessionmaker[Session]:
    engine = build_engine(
        get_settings().database_url,
        pool_size=pool_size,
        max_overflow=0 if pool_size == 1 else 10,
    )
    return build_session_factory(engine)


def reset_tenant_data(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE TABLE tenants CASCADE"))


def seed_tenant(
    engine: Engine,
    tenant_id: UUID,
    actor_id: UUID,
    slug: str,
    *,
    retain_provisioning_evidence: bool = False,
) -> None:
    settings = get_settings()
    provisioner = TenantProvisioner(
        migration_sessions=build_session_factory(engine),
        context_secret=settings.rls_context_secret.get_secret_value(),
        enabled=True,
    )
    provisioner.provision(
        tenant_id=tenant_id,
        slug=slug,
        owner_id=actor_id,
        owner_subject=f"auth0|{slug}-owner",
        owner_label=f"{slug} owner",
        correlation_id=CORRELATION_A if tenant_id == TENANT_A else CORRELATION_B,
        idempotency_key=f"fixture-provision-{slug}",
        now=FIXED_NOW,
    )
    if not retain_provisioning_evidence:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """TRUNCATE TABLE foundation_mutations, domain_events, outbox_events,
                    idempotency_records, audit_events CASCADE"""
                )
            )


def owner_actor(tenant_id: UUID = TENANT_A, actor_id: UUID = ACTOR_A) -> ActorContext:
    return ActorContext(
        tenant_id=tenant_id,
        actor_id=actor_id,
        subject="auth0|fixture-owner",
        auth_method="test_fixture",
        roles=("OWNER",),
        permissions=(
            "tenant.read",
            "tenant.manage",
            "membership.read",
            "membership.manage",
            "audit.read",
        ),
        correlation_id=CORRELATION_A if tenant_id == TENANT_A else CORRELATION_B,
    )
