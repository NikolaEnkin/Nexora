from datetime import datetime
from uuid import UUID, uuid5

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.audit import safe_audit_metadata
from app.authz import authorize
from app.contracts import ActorContext, AuthorizationEffect
from app.db import set_request_context
from app.errors import AuthorizationDenied
from app.events.service import FOUNDATION_NAMESPACE, canonical_json


class TenantUserRepository:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions

    def get_display_label(self, actor: ActorContext, user_id: UUID, *, now: datetime) -> str | None:
        decision = authorize(actor, "membership.read", object_tenant_id=actor.tenant_id)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            label = None
            if decision.effect is AuthorizationEffect.ALLOW:
                label = session.execute(
                    text("SELECT display_label FROM users WHERE id = :id"), {"id": user_id}
                ).scalar_one_or_none()
            if label is not None:
                return str(label)
            audit_id = uuid5(
                FOUNDATION_NAMESPACE,
                f"denial:{actor.tenant_id}:{actor.actor_id}:{user_id}:{actor.correlation_id}",
            )
            metadata = safe_audit_metadata({"operation": "user.read", "outcome": "DENIED"})
            session.execute(
                text(
                    """INSERT INTO audit_events (
                        id, tenant_id, actor_id, action, target_type, target_id, result, reason,
                        correlation_id, metadata, contract_version, occurred_at
                    ) VALUES (
                        :id, :tenant_id, :actor_id, 'user.read', 'user', :target_id,
                        'DENIED', 'AUTHORIZATION_DENIED', :correlation_id,
                        CAST(:metadata AS jsonb), 1, :now
                    )"""
                ),
                {
                    "id": audit_id,
                    "tenant_id": actor.tenant_id,
                    "actor_id": actor.actor_id,
                    "target_id": user_id,
                    "correlation_id": actor.correlation_id,
                    "metadata": canonical_json(metadata),
                    "now": now,
                },
            )
        if decision.effect is AuthorizationEffect.DENY:
            raise AuthorizationDenied
        return None
