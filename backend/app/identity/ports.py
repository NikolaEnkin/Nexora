from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.contracts import ActorContext


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    subject: str
    issuer: str
    audience: str


@dataclass(frozen=True, slots=True)
class MembershipSnapshot:
    tenant_id: UUID
    actor_id: UUID
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    active: bool


class MembershipPort(Protocol):
    def load_active_membership(
        self, subject: str, tenant_id: UUID
    ) -> MembershipSnapshot | None: ...


class IdentityAdapter(Protocol):
    def actor_context(
        self, identity: VerifiedIdentity, tenant_id: UUID, correlation_id: UUID
    ) -> ActorContext: ...
