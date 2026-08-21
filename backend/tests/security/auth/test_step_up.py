"""Step-up — `ADR-004` §4 with Amendment 2, signed 2026-08-21.

Before this, `assurance` was a field the fixture asserted. These cases exist to
make it a *proof*: it is derived on the server from a recorded instant, it expires
on the server clock, and the factor must be strong enough for what the actor can
do alone.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.auth import (
    CSRF_HEADER,
    AuthDependencies,
    SessionAuthenticationMiddleware,
)
from app.api.auth import router as auth_router
from app.config import get_settings
from app.errors import install_error_handlers
from app.identity import PostgresSessionStore
from app.identity.step_up import (
    FakeStepUpVerifier,
    StepUpFactor,
    required_factor,
    satisfies,
)
from tests.integration.approvals.support import CFO_ID, OPERATOR_1_ID, OWNER_ID, VIEWER_ID
from tests.integration.foundation.support import TENANT_A
from tests.integration.mcp.support import build_mcp_harness

pytestmark = pytest.mark.security

ORIGIN = "https://app.example.test"


class Clock:
    """A movable clock, starting in the past by default.

    It starts behind real time on purpose. The Phase-01 session trigger refuses a
    `last_seen_at` more than a minute ahead of the database clock, so a test cannot
    simply jump five minutes forward to watch a window close. Starting ten minutes
    back and walking forward keeps every write in the past while still crossing the
    five-minute boundary.
    """

    def __init__(self, behind: timedelta = timedelta(minutes=10)) -> None:
        self._now = datetime.now(UTC) - behind

    def __call__(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


def _build(harness, clock: Clock):  # type: ignore[no-untyped-def]
    settings = get_settings().model_copy(update={"allowed_origin": ORIGIN})
    store = PostgresSessionStore(
        sessions=harness.sessions, pepper=settings.session_hash_pepper.get_secret_value()
    )
    dependencies = AuthDependencies(
        store=store,
        settings=settings,
        clock=clock,
        step_up=FakeStepUpVerifier(settings=settings, clock=clock),
    )
    app = FastAPI()
    install_error_handlers(app)
    app.state.auth = dependencies
    app.add_middleware(SessionAuthenticationMiddleware, dependencies=dependencies)
    app.include_router(auth_router)

    @app.get("/probe")
    async def probe(request: Request) -> JSONResponse:
        actor = getattr(request.state, "actor", None)
        return JSONResponse({"assurance": actor.assurance if actor else None})

    return TestClient(app, raise_server_exceptions=False, base_url=ORIGIN)


def _login(client, actor_id):  # type: ignore[no-untyped-def]
    response = client.post(
        "/auth/dev-login",
        json={"version": "1", "tenant_id": str(TENANT_A), "actor_id": str(actor_id)},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _step_up(client, csrf, factor):  # type: ignore[no-untyped-def]
    return client.post(
        "/auth/step-up",
        json={"version": "1", "evidence": factor},
        headers={CSRF_HEADER: csrf, "origin": ORIGIN},
    )


# -- the policy itself ---------------------------------------------------


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (("OWNER",), StepUpFactor.WEBAUTHN),
        (("DEPUTY",), StepUpFactor.WEBAUTHN),
        (("OPERATOR", "DEPUTY"), StepUpFactor.WEBAUTHN),
        (("OPERATOR",), StepUpFactor.TOTP),
        (("VIEWER",), StepUpFactor.TOTP),
    ],
)
def test_the_required_factor_follows_amendment_2(roles, expected) -> None:  # type: ignore[no-untyped-def]
    """WebAuthn goes exactly where one account can approve any amount alone."""
    assert required_factor(roles) is expected


def test_a_stronger_factor_always_satisfies_a_weaker_requirement() -> None:
    assert satisfies(StepUpFactor.WEBAUTHN, ("OPERATOR",))
    assert satisfies(StepUpFactor.TOTP, ("OPERATOR",))
    assert satisfies(StepUpFactor.WEBAUTHN, ("OWNER",))
    # The reverse never does.
    assert not satisfies(StepUpFactor.TOTP, ("OWNER",))
    assert not satisfies(StepUpFactor.TOTP, ("DEPUTY",))


def test_sms_and_email_are_not_admissible_factors() -> None:
    """Amendment 2 rejects both at every level; they are absent from the enum."""
    assert {factor.value for factor in StepUpFactor} == {"webauthn", "totp"}


# -- the derived assurance -----------------------------------------------


def test_a_new_session_starts_at_standard() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    _login(client, OPERATOR_1_ID)

    assert client.get("/auth/session").json()["assurance"] == "standard"


def test_a_proven_factor_raises_assurance() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, OPERATOR_1_ID)

    response = _step_up(client, csrf, "totp")

    assert response.status_code == 200
    assert response.json()["assurance"] == "step_up"
    assert response.json()["factor"] == "totp"
    assert client.get("/auth/session").json()["assurance"] == "step_up"


def test_assurance_expires_on_the_server_clock() -> None:
    """Five minutes, measured by the server. No client input reaches this."""
    harness = build_mcp_harness()
    clock = Clock()
    client = _build(harness, clock)
    csrf = _login(client, OPERATOR_1_ID)
    _step_up(client, csrf, "totp")

    clock.advance(timedelta(minutes=4, seconds=50))
    assert client.get("/auth/session").json()["assurance"] == "step_up"

    clock.advance(timedelta(seconds=20))  # 5 min 10 s since the proof
    assert client.get("/auth/session").json()["assurance"] == "standard"


def test_the_window_does_not_reopen_by_itself() -> None:
    """Once closed it stays closed until a new factor is proven."""
    harness = build_mcp_harness()
    clock = Clock()
    client = _build(harness, clock)
    csrf = _login(client, OPERATOR_1_ID)
    _step_up(client, csrf, "totp")

    clock.advance(timedelta(minutes=6))
    assert client.get("/auth/session").json()["assurance"] == "standard"
    assert client.get("/auth/session").json()["assurance"] == "standard"

    _step_up(client, csrf, "totp")
    assert client.get("/auth/session").json()["assurance"] == "step_up"


def test_an_owner_cannot_step_up_with_totp() -> None:
    """The case Amendment 2 exists for."""
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, OWNER_ID)

    refused = _step_up(client, csrf, "totp")
    assert refused.status_code == 403
    assert refused.json()["code"] == "STEP_UP_FAILED"
    assert client.get("/auth/session").json()["assurance"] == "standard"

    accepted = _step_up(client, csrf, "webauthn")
    assert accepted.status_code == 200
    assert client.get("/auth/session").json()["assurance"] == "step_up"


def test_a_deputy_also_needs_webauthn() -> None:
    """The CFO holds OPERATOR + DEPUTY, and the stronger requirement wins."""
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, CFO_ID)

    assert _step_up(client, csrf, "totp").status_code == 403
    assert _step_up(client, csrf, "webauthn").status_code == 200


def test_a_viewer_may_use_totp() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, VIEWER_ID)
    assert _step_up(client, csrf, "totp").status_code == 200


# -- what cannot be forged ----------------------------------------------


def test_an_unknown_factor_is_refused() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, OPERATOR_1_ID)

    for evidence in ("sms", "email", "password", "", "WEBAUTHN "):
        response = _step_up(client, csrf, evidence)
        assert response.status_code in (403, 422), evidence
        assert client.get("/auth/session").json()["assurance"] == "standard"


def test_step_up_needs_a_session_and_a_csrf_token() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())

    assert (
        client.post("/auth/step-up", json={"version": "1", "evidence": "totp"}).status_code == 401
    )

    _login(client, OPERATOR_1_ID)
    without_csrf = client.post(
        "/auth/step-up", json={"version": "1", "evidence": "totp"}, headers={"origin": ORIGIN}
    )
    assert without_csrf.status_code == 403
    assert client.get("/auth/session").json()["assurance"] == "standard"


def test_the_body_cannot_declare_an_assurance() -> None:
    """`extra="forbid"`: there is no field for a caller to claim a level."""
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    csrf = _login(client, OPERATOR_1_ID)

    for smuggled in (
        {"assurance": "step_up"},
        {"factor": "webauthn"},
        {"step_up_at": "2099-01-01"},
    ):
        response = client.post(
            "/auth/step-up",
            json={"version": "1", "evidence": "totp", **smuggled},
            headers={CSRF_HEADER: csrf, "origin": ORIGIN},
        )
        assert response.status_code == 422, smuggled


def test_step_up_is_recorded_on_the_session_not_the_user() -> None:
    """A second session of the same person must not inherit the proof."""
    harness = build_mcp_harness()
    clock = Clock()
    first = _build(harness, clock)
    csrf = _login(first, OPERATOR_1_ID)
    _step_up(first, csrf, "totp")
    assert first.get("/auth/session").json()["assurance"] == "step_up"

    second = _build(harness, clock)
    _login(second, OPERATOR_1_ID)
    assert second.get("/auth/session").json()["assurance"] == "standard"


def test_the_database_refuses_a_future_step_up_time() -> None:
    """A defect in the service still cannot widen the window."""
    harness = build_mcp_harness()
    engine = harness.engine
    from tests.integration.approvals.support import _set_seed_context

    with pytest.raises(Exception, match="future"):
        with engine.begin() as connection:
            _set_seed_context(connection)
            connection.execute(
                text(
                    """INSERT INTO auth_sessions (
                        id, tenant_id, user_id, token_hash, csrf_hash, status, last_seen_at,
                        idle_expires_at, absolute_expires_at, revoked_at, created_at,
                        updated_at, step_up_at, step_up_factor
                    ) VALUES (
                        gen_random_uuid(), :tenant, :user, 'future-hash', 'csrf', 'ACTIVE',
                        now(), now() + interval '10 minutes', now() + interval '1 hour',
                        NULL, now(), now(), now() + interval '1 hour', 'totp'
                    )"""
                ),
                {"tenant": TENANT_A, "user": OPERATOR_1_ID},
            )


def test_the_required_factor_endpoint_tells_a_client_what_to_prompt_for() -> None:
    harness = build_mcp_harness()
    client = _build(harness, Clock())
    _login(client, OWNER_ID)

    body = client.get("/auth/step-up/required").json()

    assert body["required_factor"] == "webauthn"
    assert body["current_assurance"] == "standard"
    assert body["accepted_factors"] == ["webauthn"]
