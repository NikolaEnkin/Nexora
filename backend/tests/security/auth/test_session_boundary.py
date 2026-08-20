"""`P04-AUTH-001` … `P04-AUTH-009` — the HTTP authentication boundary.

The point of every case here is that authority comes from PostgreSQL, never from
anything the caller holds. The cookie is opaque, so there is no claim to forge;
the roles come out of the database on each request, so there is no cached set to
go stale; and the four ways of not having a session are indistinguishable.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.api.approvals import ApprovalApiDependencies
from app.api.approvals import router as approvals_router
from app.api.auth import (
    CSRF_HEADER,
    AuthDependencies,
    SessionAuthenticationMiddleware,
)
from app.api.auth import router as auth_router
from app.config import Settings, get_settings
from app.errors import install_error_handlers
from app.identity import PostgresSessionStore
from app.identity.session import SESSION_COOKIE_NAME
from tests.integration.approvals.support import (
    CFO_ID,
    OPERATOR_1_ID,
    build_harness,
)
from tests.integration.foundation.support import TENANT_A

pytestmark = pytest.mark.security

# The session cookie carries the `__Host-` prefix and `Secure`, so it is only ever
# sent over https. Testing against an http base URL would silently drop it and turn
# every case below into "no cookie", which would pass for the wrong reason.
ORIGIN = "https://app.example.test"
LOOPBACK_ORIGIN = "http://127.0.0.1:8091"


def _now() -> datetime:
    return datetime.now(UTC)


def _build(harness, *, settings: Settings | None = None):  # type: ignore[no-untyped-def]
    active = (settings or get_settings()).model_copy(update={"allowed_origin": ORIGIN})
    store = PostgresSessionStore(
        sessions=harness.sessions, pepper=active.session_hash_pepper.get_secret_value()
    )
    dependencies = AuthDependencies(store=store, settings=active, clock=_now)

    app = FastAPI()
    install_error_handlers(app)
    app.state.auth = dependencies
    app.state.approvals = ApprovalApiDependencies(service=harness.service)
    app.add_middleware(SessionAuthenticationMiddleware, dependencies=dependencies)
    app.include_router(auth_router)
    app.include_router(approvals_router)

    @app.post("/probe")
    async def probe(request: Request) -> JSONResponse:
        actor = getattr(request.state, "actor", None)
        return JSONResponse({"authenticated": actor is not None})

    return TestClient(app, raise_server_exceptions=False, base_url=ORIGIN)


def _login(client, actor_id=OPERATOR_1_ID):  # type: ignore[no-untyped-def]
    response = client.post(
        "/auth/dev-login",
        json={"version": "1", "tenant_id": str(TENANT_A), "actor_id": str(actor_id)},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def test_a_request_without_a_session_is_refused() -> None:
    """`P04-AUTH-001`."""
    client = _build(build_harness())
    response = client.get("/auth/session")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"


def test_a_valid_session_carries_roles_read_from_the_database() -> None:
    """`P04-AUTH-002` — the cookie carries none of this; PostgreSQL does."""
    harness = build_harness()
    client = _build(harness)
    _login(client, CFO_ID)

    response = client.get("/auth/session")

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == str(TENANT_A)
    assert body["actor_id"] == str(CFO_ID)
    # The CFO holds OPERATOR + DEPUTY. Nothing in the login request said so.
    assert set(body["roles"]) == {"OPERATOR", "DEPUTY"}
    assert "approval.decide.high" in body["permissions"]
    assert body["assurance"] == "standard"


def test_a_forged_cookie_is_indistinguishable_from_no_cookie() -> None:
    """`P04-AUTH-003`."""
    client = _build(build_harness())
    client.cookies.set(SESSION_COOKIE_NAME, "forged-value-that-is-long-enough-to-look-real")

    response = client.get("/auth/session")

    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"
    assert response.json()["details"] == {}


def test_a_revoked_session_stops_working_immediately() -> None:
    """`P04-AUTH-004`."""
    harness = build_harness()
    client = _build(harness)
    csrf = _login(client)
    assert client.get("/auth/session").status_code == 200

    logout = client.post("/auth/logout", headers={CSRF_HEADER: csrf, "origin": ORIGIN})
    assert logout.status_code == 200

    client.cookies.set(SESSION_COOKIE_NAME, "irrelevant")
    assert client.get("/auth/session").status_code == 401


def test_a_state_changing_request_without_a_csrf_token_is_refused() -> None:
    """`P04-AUTH-005`."""
    harness = build_harness()
    client = _build(harness)
    _login(client)

    response = client.post("/probe", headers={"origin": ORIGIN})

    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_FAILED"


def test_a_state_changing_request_from_a_foreign_origin_is_refused() -> None:
    """`P04-AUTH-006`."""
    harness = build_harness()
    client = _build(harness)
    csrf = _login(client)

    response = client.post("/probe", headers={CSRF_HEADER: csrf, "origin": "https://evil.example"})

    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_FAILED"


def test_a_correct_csrf_token_and_origin_reach_the_endpoint() -> None:
    """`P04-AUTH-007` — the positive twin, so the refusals above mean something."""
    harness = build_harness()
    client = _build(harness)
    csrf = _login(client)

    response = client.post("/probe", headers={CSRF_HEADER: csrf, "origin": ORIGIN})

    assert response.status_code == 200
    assert response.json() == {"authenticated": True}


def test_a_get_needs_no_csrf_token() -> None:
    """Reads never mutate, so they carry no token requirement."""
    harness = build_harness()
    client = _build(harness)
    _login(client)
    assert client.get("/auth/session").status_code == 200


def test_the_login_body_cannot_smuggle_roles_or_permissions() -> None:
    """`P04-AUTH-008` — `extra="forbid"`, and authority comes from the database anyway."""
    harness = build_harness()
    client = _build(harness)

    for smuggled in (
        {"roles": ["OWNER"]},
        {"permissions": ["approval.decide.high"]},
        {"assurance": "step_up"},
        {"auth_method": "auth0_oidc"},
    ):
        response = client.post(
            "/auth/dev-login",
            json={
                "version": "1",
                "tenant_id": str(TENANT_A),
                "actor_id": str(OPERATOR_1_ID),
                **smuggled,
            },
        )
        assert response.status_code == 422, smuggled


def test_a_login_for_an_unknown_actor_is_refused() -> None:
    """A session cannot be minted for somebody who is not an active member."""
    harness = build_harness()
    client = _build(harness)

    response = client.post(
        "/auth/dev-login",
        json={"version": "1", "tenant_id": str(TENANT_A), "actor_id": str(uuid4())},
    )

    assert response.status_code == 401


def test_the_development_login_does_not_exist_in_production_configuration() -> None:
    """`P04-AUTH-009` — structurally unreachable, not merely discouraged."""
    harness = build_harness()
    production_like = get_settings().model_copy(
        update={"environment": "production", "fake_identity_enabled": False}
    )
    client = _build(harness, settings=production_like)

    response = client.post(
        "/auth/dev-login",
        json={"version": "1", "tenant_id": str(TENANT_A), "actor_id": str(OPERATOR_1_ID)},
    )

    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        (LOOPBACK_ORIGIN, "production origin must be https"),
        ("https://localhost:8443", "production origin cannot be a loopback fixture"),
    ],
)
def test_a_production_boundary_refuses_an_unusable_origin(origin: str, expected: str) -> None:
    """The Origin check is worthless if production is configured against localhost."""
    harness = build_harness()
    store = PostgresSessionStore(sessions=harness.sessions, pepper="x" * 32)
    production_like = get_settings().model_copy(
        update={"environment": "production", "allowed_origin": origin}
    )
    with pytest.raises(ValueError, match=expected):
        AuthDependencies(store=store, settings=production_like, clock=_now)


def test_the_boundary_feeds_a_real_protected_endpoint() -> None:
    """The whole point: `/approvals` stopped answering 401 for an authenticated caller."""
    harness = build_harness()
    client = _build(harness)
    _login(client)

    absent = uuid4()
    response = client.get(f"/approvals/{absent}")

    # Not 401 any more: the caller is authenticated, and the approval simply is
    # not there. Before this boundary existed, every response here was 401.
    assert response.status_code == 404
    assert response.json()["code"] == "APPROVAL_NOT_FOUND"
