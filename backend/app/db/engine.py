import hashlib
import hmac
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def build_engine(database_url: str, *, pool_size: int = 5, max_overflow: int = 10) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def context_signature(tenant_id: UUID, actor_id: UUID, secret: str) -> str:
    message = f"{tenant_id}:{actor_id}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def set_request_context(
    session: Session,
    tenant_id: UUID,
    actor_id: UUID,
    *,
    context_secret: str | None = None,
) -> None:
    secret = context_secret or get_settings().rls_context_secret.get_secret_value()
    session.execute(
        text(
            "SELECT set_config('app.tenant_id', :tenant_id, true), "
            "set_config('app.actor_id', :actor_id, true), "
            "set_config('app.context_signature', :signature, true)"
        ),
        {
            "tenant_id": str(tenant_id),
            "actor_id": str(actor_id),
            "signature": context_signature(tenant_id, actor_id, secret),
        },
    )


@contextmanager
def tenant_transaction(
    factory: sessionmaker[Session], tenant_id: UUID, actor_id: UUID
) -> Iterator[Session]:
    with factory() as session, session.begin():
        set_request_context(session, tenant_id, actor_id)
        yield session
