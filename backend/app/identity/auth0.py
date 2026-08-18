from dataclasses import dataclass
from uuid import UUID

from app.contracts import ActorContext
from app.errors import ApplicationError
from app.identity.ports import MembershipPort, VerifiedIdentity


@dataclass(frozen=True, slots=True)
class Auth0IdentityAdapter:
    issuer: str
    audience: str
    memberships: MembershipPort

    def actor_context(
        self, identity: VerifiedIdentity, tenant_id: UUID, correlation_id: UUID
    ) -> ActorContext:
        if identity.issuer != self.issuer or identity.audience != self.audience:
            raise ApplicationError(
                code="AUTHENTICATION_REQUIRED",
                message="Authentication is required.",
                status_code=401,
            )
        membership = self.memberships.load_active_membership(identity.subject, tenant_id)
        if membership is None or not membership.active:
            raise ApplicationError(
                code="AUTHENTICATION_REQUIRED",
                message="Authentication is required.",
                status_code=401,
            )
        return ActorContext(
            tenant_id=membership.tenant_id,
            actor_id=membership.actor_id,
            subject=identity.subject,
            auth_method="auth0_oidc",
            roles=membership.roles,
            permissions=membership.permissions,
            correlation_id=correlation_id,
        )
