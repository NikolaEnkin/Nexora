import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

SESSION_COOKIE_NAME = "__Host-nexora_session"
SESSION_COOKIE_ATTRIBUTES = {
    "secure": True,
    "httponly": True,
    "samesite": "lax",
    "path": "/",
}
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=12)


def issue_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(raw_token: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), raw_token.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class SessionExpiry:
    idle_expires_at: datetime
    absolute_expires_at: datetime


def calculate_session_expiry(now: datetime) -> SessionExpiry:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return SessionExpiry(
        idle_expires_at=now + IDLE_TIMEOUT,
        absolute_expires_at=now + ABSOLUTE_TIMEOUT,
    )


def validate_csrf_and_origin(
    *,
    stored_csrf_hash: str,
    supplied_csrf_token: str | None,
    supplied_origin: str | None,
    allowed_origin: str,
    pepper: str,
) -> bool:
    if supplied_csrf_token is None or supplied_origin is None:
        return False
    supplied = urlsplit(supplied_origin)
    allowed = urlsplit(allowed_origin)
    if (supplied.scheme, supplied.netloc) != (allowed.scheme, allowed.netloc):
        return False
    supplied_hash = hash_session_token(supplied_csrf_token, pepper)
    return hmac.compare_digest(stored_csrf_hash, supplied_hash)
