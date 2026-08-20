"""Payload normalization v1 and the approval-binding hash.

`ARCH-007` binds an approval to a *normalized* payload rather than to the bytes a
caller happened to send. Two requests that mean the same thing must produce the
same hash, and two that differ in any material way must not — otherwise either
approvals break on cosmetic reserialization, or a material edit slips past a
stale grant.

The normalizer is deliberately closed. An unsupported Python type raises rather
than being coerced to `str`, because a silent `str()` is how a `float`, a naive
`datetime` or an arbitrary object would produce a hash that depends on repr
details instead of on meaning. Fail-closed here means a new argument type has to
be added on purpose, with a test.

Excluded keys carry correlation, tracing or display text. They vary between
otherwise identical requests and are not part of what a human approves, so
including them would invalidate approvals for no security gain.

Numeric canonical form applies to `Decimal` values only. A string stays a string:
`"500.00"` and `"500.0"` are different payloads, because `"00500"` may be a
customer reference whose leading zeros matter. Erring toward more invalidation is
the safe direction — an approval that breaks costs a second click, while one that
silently spans two different values costs the amount.

This is deliberately *not* `app.events.service.canonical_json`. That helper hashes
idempotency requests for Phase 01 and has no key exclusions, no `Decimal`, date or
`UUID` forms, and no version of its own. Reusing it would either weaken approval
binding or change every stored idempotency hash in the system; normalization v1 is
a separate, independently versioned contract, as packet §8 requires.
"""

import hmac
import json
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from hashlib import sha256
from typing import Any, Final
from uuid import UUID

NORMALIZATION_VERSION: Final = 1

# Not part of the approved meaning of a request.
EXCLUDED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "correlation_id",
        "causation_id",
        "trace_id",
        "span_id",
        "display_text",
        "rendered_text",
        "render",
    }
)


class NormalizationError(ValueError):
    """A payload contains a value this version cannot canonicalize deterministically."""


def _normalize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        # bool first: bool is a subclass of int.
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise NormalizationError("a non-finite decimal has no canonical form")
        # Normalize removes trailing-zero differences so 10.50 and 10.5 agree;
        # the exponent is then fixed so 1E+2 renders as 100 rather than 1E+2.
        normalized = value.normalize()
        if normalized == normalized.to_integral_value():
            normalized = normalized.quantize(Decimal(1))
        return f"{normalized:f}"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise NormalizationError("a naive datetime has no canonical instant")
        return _iso_utc(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, float):
        raise NormalizationError("float is not canonicalizable; use Decimal")
    raise NormalizationError(f"unsupported payload type: {type(value).__name__}")


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize(value: Any) -> Any:
    """Recursively canonicalize a payload value.

    Mapping key order is normalized; sequence order is preserved, because the
    order of line items or recipients is material to what is approved.
    """
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise NormalizationError("payload keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in EXCLUDED_KEYS:
                continue
            result[key] = normalize(raw_value)
        return dict(sorted(result.items()))
    if isinstance(value, str | bytes):
        if isinstance(value, bytes):
            raise NormalizationError("bytes are not canonicalizable")
        return _normalize_scalar(value)
    if isinstance(value, Sequence):
        return [normalize(item) for item in value]
    return _normalize_scalar(value)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """The exact bytes that are hashed. Stable across processes and versions."""
    return json.dumps(
        normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def payload_hash(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical bytes, lowercase hex."""
    return sha256(canonical_bytes(payload)).hexdigest()


def hashes_match(left: str, right: str) -> bool:
    """Constant-time comparison (packet §12)."""
    return hmac.compare_digest(left, right)
