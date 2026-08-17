from dataclasses import dataclass
from uuid import UUID

from app.config import Settings
from app.contracts import ActorContext


@dataclass(frozen=True, slots=True)
class FakeIdentityAdapter:
    settings: Settings

    def __post_init__(self) -> None:
        if self.settings.environment not in {"development", "test"}:
            raise RuntimeError("fake identity adapter is forbidden outside development/test")
        if not self.settings.fake_identity_enabled:
            raise RuntimeError("fake identity adapter is disabled")

    def actor_context(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        subject: str,
        roles: tuple[str, ...],
        permissions: tuple[str, ...],
        correlation_id: UUID,
    ) -> ActorContext:
        return ActorContext(
            tenant_id=tenant_id,
            actor_id=actor_id,
            subject=subject,
            auth_method="test_fixture",
            roles=roles,
            permissions=permissions,
            correlation_id=correlation_id,
        )
