"""Deterministic runtime identifiers.

Every identifier here is derived, never chosen by a caller, a model, or message
content. Thread IDs are opaque UUID-derived hex rather than display names, so a
conversation title can never become an addressable storage key. Event IDs are a
pure function of operation and sequence, which is what makes SSE `Last-Event-ID`
reconnect stable across process restarts.
"""

from uuid import UUID, uuid5

AGENT_NAMESPACE = UUID("70000000-0000-0000-0000-000000000002")


def derive_thread_id(tenant_id: UUID, conversation_id: UUID) -> str:
    """Opaque per-tenant thread key. Two tenants cannot collide on one thread."""
    return uuid5(AGENT_NAMESPACE, f"thread:{tenant_id}:{conversation_id}").hex


def derive_operation_id(tenant_id: UUID, actor_id: UUID, client_request_id: str) -> UUID:
    """Operation identity is the idempotency scope from `BR-02-001`."""
    return uuid5(AGENT_NAMESPACE, f"operation:{tenant_id}:{actor_id}:{client_request_id}")


def derive_conversation_id(tenant_id: UUID, actor_id: UUID, client_request_id: str) -> UUID:
    """Conversation for a request that did not name an existing one."""
    return uuid5(AGENT_NAMESPACE, f"conversation:{tenant_id}:{actor_id}:{client_request_id}")


def derive_event_id(operation_id: UUID, sequence: int) -> UUID:
    """Stable SSE event ID: the same (operation, sequence) always yields the same ID."""
    return uuid5(AGENT_NAMESPACE, f"event:{operation_id}:{sequence}")


def derive_message_id(operation_id: UUID, ordinal: int) -> UUID:
    return uuid5(AGENT_NAMESPACE, f"message:{operation_id}:{ordinal}")
