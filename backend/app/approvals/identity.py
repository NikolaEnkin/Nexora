"""Derived, stable approval identifiers.

Identifiers are derived rather than random so that a retried submission resolves
to the same row without a read-then-write race: the unique constraint and the
primary key collide together, exactly as `app.agent.operations` documents for
Phase 02. Nothing here is a secret, and nothing here is guessable across tenants
without already knowing the tenant, actor and key.
"""

from uuid import UUID, uuid5

APPROVAL_NAMESPACE = UUID("6f1d5a4e-4c2b-5f8a-9d31-6b0f2c7ae410")


def derive_approval_id(
    tenant_id: UUID, requester_id: UUID, action_key: str, idempotency_key: str
) -> UUID:
    return uuid5(
        APPROVAL_NAMESPACE, f"approval:{tenant_id}:{requester_id}:{action_key}:{idempotency_key}"
    )


def derive_decision_id(approval_id: UUID, actor_id: UUID) -> UUID:
    """One decision per actor per approval; the identifier says so structurally."""
    return uuid5(APPROVAL_NAMESPACE, f"decision:{approval_id}:{actor_id}")


def derive_consumption_id(approval_id: UUID) -> UUID:
    """Single use: one consumption identity per approval, whoever writes it."""
    return uuid5(APPROVAL_NAMESPACE, f"consumption:{approval_id}")
