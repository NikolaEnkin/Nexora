from dataclasses import replace
from uuid import UUID

import pytest

from app.authz import authorize
from app.config import Settings
from app.contracts import AuthorizationEffect
from app.errors import ApplicationError
from app.identity.auth0 import Auth0IdentityAdapter
from app.identity.fake import FakeIdentityAdapter
from app.identity.ports import MembershipSnapshot, VerifiedIdentity

TENANT = UUID("20000000-0000-0000-0000-000000000001")
OTHER_TENANT = UUID("20000000-0000-0000-0000-000000000002")
ACTOR = UUID("30000000-0000-0000-0000-000000000001")
CORRELATION = UUID("90000000-0000-0000-0000-000000000001")


@pytest.mark.unit
def test_authorization_requires_permission_and_exact_tenant() -> None:
    adapter = FakeIdentityAdapter(Settings(environment="test"))
    actor = adapter.actor_context(
        tenant_id=TENANT,
        actor_id=ACTOR,
        subject="auth0|fixture-owner",
        roles=("OWNER",),
        permissions=("tenant.manage",),
        correlation_id=CORRELATION,
    )
    assert (
        authorize(actor, "tenant.manage", object_tenant_id=TENANT).effect
        is AuthorizationEffect.ALLOW
    )
    cross_tenant = authorize(actor, "tenant.manage", object_tenant_id=OTHER_TENANT)
    assert cross_tenant.effect is AuthorizationEffect.DENY
    assert cross_tenant.reason_code == "AUTHORIZATION_DENIED"
    missing = authorize(actor, "audit.read", object_tenant_id=TENANT)
    assert missing.effect is AuthorizationEffect.DENY
    assert missing.reason_code == "PERMISSION_MISSING"


class FixedMemberships:
    def __init__(self, membership: MembershipSnapshot | None) -> None:
        self.membership = membership

    def load_active_membership(self, subject: str, tenant_id: UUID) -> MembershipSnapshot | None:
        return self.membership


@pytest.mark.unit
def test_auth0_adapter_rejects_untrusted_claims_and_inactive_membership() -> None:
    active = MembershipSnapshot(
        tenant_id=TENANT,
        actor_id=ACTOR,
        roles=("VIEWER",),
        permissions=("tenant.read",),
        active=True,
    )
    adapter = Auth0IdentityAdapter(
        issuer="https://tenant.auth0.com/",
        audience="https://api.example.test",
        memberships=FixedMemberships(active),
    )
    trusted = VerifiedIdentity(
        subject="auth0|user",
        issuer="https://tenant.auth0.com/",
        audience="https://api.example.test",
    )
    actor = adapter.actor_context(trusted, TENANT, CORRELATION)
    assert actor.roles == ("VIEWER",)
    with pytest.raises(ApplicationError) as wrong_issuer:
        adapter.actor_context(
            trusted.__class__(
                subject=trusted.subject,
                issuer="https://evil.example/",
                audience=trusted.audience,
            ),
            TENANT,
            CORRELATION,
        )
    assert wrong_issuer.value.code == "AUTHENTICATION_REQUIRED"
    inactive = Auth0IdentityAdapter(
        issuer=adapter.issuer,
        audience=adapter.audience,
        memberships=FixedMemberships(replace(active, active=False)),
    )
    with pytest.raises(ApplicationError):
        inactive.actor_context(trusted, TENANT, CORRELATION)
