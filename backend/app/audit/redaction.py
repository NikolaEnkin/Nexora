from collections.abc import Mapping
from typing import Any

from app.logging import redact_data

AUDIT_METADATA_ALLOWLIST = frozenset(
    {"operation", "request_hash", "event_id", "idempotency_record_id", "outcome"}
)


def safe_audit_metadata(
    metadata: Mapping[str, Any], *, secret_values: tuple[str, ...] = ()
) -> dict[str, Any]:
    allowlisted = {key: value for key, value in metadata.items() if key in AUDIT_METADATA_ALLOWLIST}
    redacted = redact_data(allowlisted, secret_values)
    if not isinstance(redacted, dict):
        raise TypeError("audit metadata must remain a mapping")
    return redacted
