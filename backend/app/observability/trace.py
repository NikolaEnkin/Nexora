"""A deterministic in-process trace sink.

Two layers of protection, deliberately not one. First the field name must be in
`ALLOWED_SPAN_FIELDS`, so raw message content, checkpoints and credentials have
no field to travel in. Then every surviving value still passes through the
Phase-01 `redact_data`, so a secret that somehow reached an allowlisted field —
say inside an `error_code` string — is scrubbed rather than emitted.

Spans are also written to the structured logger, which applies the same Phase-01
redaction processor configured with the running secrets.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.logging import redact_data
from app.observability.ports import ALLOWED_SPAN_FIELDS, Span


def allowlist_fields(
    fields: Mapping[str, Any], *, secret_values: Iterable[str] = ()
) -> dict[str, Any]:
    """Keep only allowlisted keys, then redact what remains."""
    kept = {key: value for key, value in fields.items() if key in ALLOWED_SPAN_FIELDS}
    redacted = redact_data(kept, tuple(secret_values))
    if not isinstance(redacted, dict):
        raise TypeError("span fields must remain a mapping")
    return redacted


@dataclass(slots=True)
class DeterministicTraceSink:
    """Records spans in memory and emits them as redacted structured logs.

    Shaped like a Langfuse client so a future adapter can replace it without
    changing a single call site, but it opens no socket.
    """

    secret_values: tuple[str, ...] = ()  # mutable after construction so a test can add one
    _spans: list[Span] = field(default_factory=list, init=False)

    def record(self, name: str, /, **fields: Any) -> Span:
        span = Span(name=name, fields=allowlist_fields(fields, secret_values=self.secret_values))
        self._spans.append(span)
        structlog.get_logger("agent-runtime").info(name, **span.fields)
        return span

    @property
    def spans(self) -> tuple[Span, ...]:
        return tuple(self._spans)

    def field_names(self) -> set[str]:
        names: set[str] = set()
        for span in self._spans:
            names.update(span.fields)
        return names

    def rendered(self) -> str:
        """Every recorded value as one string, for absence assertions."""
        return " ".join(
            f"{span.name} " + " ".join(f"{key}={value}" for key, value in span.fields.items())
            for span in self._spans
        )
