"""The trace boundary.

Langfuse-compatible in shape, but Phase 02 adds no network-capable tracer. A
deterministic local sink is enough to prove the contract, and it keeps an
outbound telemetry dependency out of a phase whose whole point is that nothing
escapes.

Telemetry is allowlisted, not filtered. A span carries only the keys named in
`ALLOWED_SPAN_FIELDS`; anything else is dropped before the sink ever sees it. That
is the difference between "we redact secrets" and "there is no field a secret
could travel in".
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

# Packet §17: identifiers, route, lifecycle, latency, retries, conflicts,
# reconnects, token/cost aggregates and stable error codes. Nothing else.
ALLOWED_SPAN_FIELDS: frozenset[str] = frozenset(
    {
        "operation_id",
        "correlation_id",
        "conversation_id",
        "route",
        "lifecycle_state",
        "node",
        "latency_ms",
        "retry_count",
        "checkpoint_conflicts",
        "checkpoint_seq",
        "sse_reconnects",
        "event_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cost_micros",
        "error_code",
        "outcome",
    }
)

# Never traced, even if a caller passes them. Listed explicitly so the security
# test can assert the boundary rather than infer it.
FORBIDDEN_SPAN_FIELDS: frozenset[str] = frozenset(
    {
        "message",
        "messages",
        "content",
        "prompt",
        "completion",
        "checkpoint",
        "checkpoint_payload",
        "state",
        "session",
        "session_token",
        "cookie",
        "authorization",
        "api_key",
        "secret",
        "password",
        "token_hash",
        "database_url",
    }
)


@dataclass(frozen=True, slots=True)
class Span:
    """One traced runtime step. `fields` is already allowlisted."""

    name: str
    fields: Mapping[str, Any]


class TracePort(Protocol):
    def record(self, name: str, /, **fields: Any) -> Span: ...

    @property
    def spans(self) -> tuple[Span, ...]: ...
