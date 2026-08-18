from datetime import UTC, datetime, timedelta

import pytest

from app.identity.session import (
    ABSOLUTE_TIMEOUT,
    IDLE_TIMEOUT,
    SESSION_COOKIE_ATTRIBUTES,
    SESSION_COOKIE_NAME,
    calculate_session_expiry,
    hash_session_token,
    issue_session_token,
    validate_csrf_and_origin,
)


@pytest.mark.unit
def test_session_contract_is_server_side_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.identity.session.secrets.token_urlsafe", lambda _size: "x" * 43)
    token = issue_session_token()
    assert len(token) >= 40
    assert hash_session_token(token, "pepper") != token
    assert SESSION_COOKIE_NAME.startswith("__Host-")
    assert SESSION_COOKIE_ATTRIBUTES == {
        "secure": True,
        "httponly": True,
        "samesite": "lax",
        "path": "/",
    }
    now = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    expiry = calculate_session_expiry(now)
    assert expiry.idle_expires_at == now + timedelta(minutes=30) == now + IDLE_TIMEOUT
    assert expiry.absolute_expires_at == now + timedelta(hours=12) == now + ABSOLUTE_TIMEOUT


@pytest.mark.unit
def test_csrf_and_origin_both_fail_closed() -> None:
    csrf = "fixed-csrf-token"
    stored = hash_session_token(csrf, "pepper")
    assert validate_csrf_and_origin(
        stored_csrf_hash=stored,
        supplied_csrf_token=csrf,
        supplied_origin="https://app.example.test/form",
        allowed_origin="https://app.example.test",
        pepper="pepper",
    )
    assert not validate_csrf_and_origin(
        stored_csrf_hash=stored,
        supplied_csrf_token=csrf,
        supplied_origin="https://evil.example.test",
        allowed_origin="https://app.example.test",
        pepper="pepper",
    )
    assert not validate_csrf_and_origin(
        stored_csrf_hash=stored,
        supplied_csrf_token=None,
        supplied_origin="https://app.example.test",
        allowed_origin="https://app.example.test",
        pepper="pepper",
    )
