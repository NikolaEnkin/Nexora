from uuid import UUID

from app.contracts import (
    ActorContext,
    AuthorizationDecision,
    AuthorizationEffect,
)


def authorize(
    actor: ActorContext,
    permission: str,
    *,
    object_tenant_id: UUID,
    object_scope: str = "tenant",
) -> AuthorizationDecision:
    if actor.tenant_id != object_tenant_id:
        return AuthorizationDecision(
            effect=AuthorizationEffect.DENY,
            permission=permission,
            object_scope=object_scope,
            reason_code="AUTHORIZATION_DENIED",
        )
    if permission not in actor.permissions:
        return AuthorizationDecision(
            effect=AuthorizationEffect.DENY,
            permission=permission,
            object_scope=object_scope,
            reason_code="PERMISSION_MISSING",
        )
    return AuthorizationDecision(
        effect=AuthorizationEffect.ALLOW,
        permission=permission,
        object_scope=object_scope,
        reason_code="AUTHORIZED",
    )
