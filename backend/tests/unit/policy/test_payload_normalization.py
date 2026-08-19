"""Normalization v1 determinism and fail-closed typing."""

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from app.policy.canonical import (
    NormalizationError,
    canonical_bytes,
    hashes_match,
    normalize,
    payload_hash,
)


@pytest.mark.unit
def test_key_order_and_unicode_form_do_not_change_the_hash() -> None:
    decomposed = {"z": 1, "name": "Café"}
    composed = {"name": "Café", "z": 1}
    assert payload_hash(decomposed) == payload_hash(composed)


@pytest.mark.unit
def test_sequence_order_is_material() -> None:
    assert payload_hash({"items": ["a", "b"]}) != payload_hash({"items": ["b", "a"]})


@pytest.mark.unit
def test_excluded_keys_do_not_affect_the_hash() -> None:
    base = {"amount": Decimal("10.00"), "recipient": "a@example.test"}
    noisy = {
        **base,
        "correlation_id": "11111111-1111-1111-1111-111111111111",
        "trace_id": "abc",
        "display_text": "Send €10.00 to Anna",
        "render": {"html": "<b>x</b>"},
    }
    assert payload_hash(base) == payload_hash(noisy)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("left", "right"),
    [
        (Decimal("10.50"), Decimal("10.5")),
        (Decimal("1E+2"), Decimal("100")),
        (Decimal("100.00"), Decimal("100")),
    ],
)
def test_equal_decimals_share_one_canonical_form(left: Decimal, right: Decimal) -> None:
    assert payload_hash({"amount": left}) == payload_hash({"amount": right})


@pytest.mark.unit
def test_different_amounts_have_different_hashes() -> None:
    assert payload_hash({"amount": Decimal("9999.99")}) != payload_hash(
        {"amount": Decimal("10000.00")}
    )


@pytest.mark.unit
def test_datetimes_canonicalize_to_utc_instants() -> None:
    from datetime import timedelta, timezone

    utc = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    offset = datetime(2026, 1, 15, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    assert payload_hash({"at": utc}) == payload_hash({"at": offset})


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [1.5, float("nan"), b"bytes", object(), {1: "int key"}],
)
def test_unsupported_types_fail_closed(value: object) -> None:
    with pytest.raises(NormalizationError):
        normalize({"value": value} if not isinstance(value, dict) else value)


@pytest.mark.unit
def test_naive_datetime_is_refused() -> None:
    with pytest.raises(NormalizationError):
        normalize({"at": datetime(2026, 1, 15, 10, 0)})


@pytest.mark.unit
def test_non_finite_decimal_is_refused() -> None:
    with pytest.raises(NormalizationError):
        normalize({"amount": Decimal("Infinity")})


@pytest.mark.unit
def test_canonical_bytes_are_stable_and_hash_is_lowercase_hex() -> None:
    payload = {
        "amount": Decimal("10000.00"),
        "currency": "EUR",
        "invoice_id": UUID("40000000-0000-0000-0000-000000000001"),
    }
    assert canonical_bytes(payload) == (
        b'{"amount":"10000","currency":"EUR","invoice_id":"40000000-0000-0000-0000-000000000001"}'
    )
    digest = payload_hash(payload)
    assert len(digest) == 64
    assert digest == digest.lower()


@pytest.mark.unit
def test_hash_comparison_is_constant_time_and_exact() -> None:
    digest = payload_hash({"a": 1})
    assert hashes_match(digest, digest)
    assert not hashes_match(digest, digest[:-1] + ("0" if digest[-1] != "0" else "1"))
