from collections.abc import Mapping
from typing import Any

from app.logging import redact_data

AUDIT_METADATA_ALLOWLIST = frozenset(
    {
        "operation",
        "request_hash",
        "event_id",
        "idempotency_record_id",
        "outcome",
        # Phase 03. Identifiers, codes and versions only — never the approval
        # payload, the rendered text shown to the approver, or an amount.
        "approval_id",
        "action_key",
        "risk",
        "decision",
        "path_id",
        "result_code",
        "policy_version",
        "catalogue_version",
        "normalization_version",
        "payload_hash",
    }
)


def safe_audit_metadata(
    metadata: Mapping[str, Any], *, secret_values: tuple[str, ...] = ()
) -> dict[str, Any]:
    allowlisted = {key: value for key, value in metadata.items() if key in AUDIT_METADATA_ALLOWLIST}
    redacted = redact_data(allowlisted, secret_values)
    if not isinstance(redacted, dict):
        raise TypeError("audit metadata must remain a mapping")
    return redacted
