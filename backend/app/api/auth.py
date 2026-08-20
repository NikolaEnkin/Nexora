"""The HTTP authentication boundary.

This is the hop that Phase 02 and Phase 03 both left unbuilt: `app/api/chat.py`
and `app/api/approvals.py` read `request.state.actor` and, until now, nothing put
it there. Every protected endpoint therefore answered `AUTHENTICATION_REQUIRED`,
and `app/config.py` refuses production startup for the same reason.

Three properties carry the security weight.

**The cookie is opaque.** It carries a high-entropy identifier and nothing else.
Tenant, roles, permissions and assurance are read from PostgreSQL on every single
request, so a caller cannot widen their own authority by editing anything they
hold — there is no signed claim to tamper with and no cached role set to go stale.

**Expiry lives in the database.** `nexora_resolve_session` enforces idle and
absolute expiry, and revocation, inside the query. This module does not
re-implement any of it in Python, because two implementations of an expiry rule
means the more permissive one is the real one.

**Absent, unknown, expired and revoked are indistinguishable.** All four produce
the same 401 with the same code and no details, so probing a cookie value reveals
nothing about whether a session ever existed.

Step-up is deliberately absent. `ADR-004` Amendment 2 fixes the factor — TOTP for
everyone, WebAuthn for `OWNER` and `DEPUTY` — but it is unsigned, and the
amendment itself forbids writing step-up code before it is signed.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import Settings
from app.contracts import ActorContext
from app.contracts.foundation import FrozenContract
from app.errors import ApplicationError, AuthenticationRequired
from app.identity.session import SESSION_COOKIE_NAME, validate_csrf_and_origin
from app.identity.session_store import PostgresSessionStore

router = APIRouter(prefix="/auth", tags=["auth"])

CSRF_HEADER = "X-Nexora-CSRF"
# `GET` and `HEAD` never mutate, so they carry no CSRF requirement. Every other
# method does, including `DELETE` — the list is of safe methods, not of unsafe
# ones, so a method nobody thought about is protected by default.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Paths that must work before a session exists.
UNAUTHENTICATED_PATHS = frozenset(
    {"/health/live", "/health/ready", "/auth/dev-login", "/openapi.json", "/docs", "/redoc"}
)


class CsrfFailed(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="CSRF_FAILED",
            message="The request origin or token could not be verified.",
            status_code=403,
        )


@dataclass(slots=True)
class AuthDependencies:
    store: PostgresSessionStore
    settings: Settings
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        """Fail closed on a production origin that would defeat the Origin check.

        The guard lives here rather than in `Settings` deliberately: Phase-02
        finding R-04 recorded that adding another required production field to the
        settings validator changes which error a Phase-01 test observes. Guarding
        at construction also means it fires wherever the boundary is built, not
        only at settings load.
        """
        if self.settings.environment != "production":
            return
        origin = self.settings.allowed_origin
        if not origin.startswith("https://"):
            raise ValueError("production origin must be https")
        if "127.0.0.1" in origin or "localhost" in origin:
            raise ValueError("production origin cannot be a loopback fixture")


class SessionAuthenticationMiddleware(BaseHTTPMiddleware):
    """Resolves the session cookie into a trusted `ActorContext`.

    An unauthenticated request is *not* rejected here. The middleware simply
    leaves `request.state.actor` unset and lets the endpoint decide, which keeps
    the health and login routes reachable without special-casing them into the
    authorization logic.
    """

    def __init__(self, app: ASGIApp, dependencies: AuthDependencies) -> None:
        super().__init__(app)
        self.dependencies = dependencies

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if raw_token is None:
            return await call_next(request)

        correlation_id = _correlation_id(request)
        try:
            resolved = self.dependencies.store.resolve_credentials(
                raw_token, correlation_id, self.dependencies.clock()
            )
        except AuthenticationRequired:
            # An unknown, expired or revoked cookie is treated exactly as no
            # cookie. The endpoint answers 401 with the same non-disclosing code.
            return await call_next(request)

        if request.method not in SAFE_METHODS and request.url.path not in UNAUTHENTICATED_PATHS:
            if not validate_csrf_and_origin(
                stored_csrf_hash=resolved.csrf_hash,
                supplied_csrf_token=request.headers.get(CSRF_HEADER),
                supplied_origin=request.headers.get("origin"),
                allowed_origin=self.dependencies.settings.allowed_origin,
                pepper=self.dependencies.settings.session_hash_pepper.get_secret_value(),
            ):
                error = CsrfFailed()
                return JSONResponse(
                    status_code=error.status_code,
                    content={
                        "version": "1",
                        "code": error.code,
                        "message": error.message,
                        "correlation_id": str(correlation_id),
                        "retryable": False,
                        "details": {},
                    },
                )

        request.state.actor = resolved.actor
        return await call_next(request)


def _correlation_id(request: Request) -> UUID:
    existing = getattr(request.state, "correlation_id", None)
    if isinstance(existing, UUID):
        return existing
    if isinstance(existing, str):
        try:
            return UUID(existing)
        except ValueError:
            return uuid4()
    return uuid4()


class DevLoginRequest(FrozenContract):
    """Development-only. `extra="forbid"`, but the real control is that this
    endpoint cannot exist outside development and test at all."""

    version: Literal["1"] = "1"
    tenant_id: UUID
    actor_id: UUID
    subject: str = "auth0|dev"


class SessionView(FrozenContract):
    version: Literal["1"] = "1"
    tenant_id: UUID
    actor_id: UUID
    subject: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    assurance: str


def _dependencies(request: Request) -> AuthDependencies:
    dependencies = getattr(request.app.state, "auth", None)
    if not isinstance(dependencies, AuthDependencies):
        raise AuthenticationRequired
    return dependencies


@router.post("/dev-login")
async def dev_login(request: Request) -> Response:
    """Mint a session for an existing user, for local development only.

    Structurally unreachable in production: it refuses unless the environment is
    development or test *and* the fake identity adapter is enabled, and
    `app/config.py` already refuses to start in production while that flag is on.
    It grants nothing — roles and permissions still come from the database, so a
    dev login cannot manufacture authority the user does not have.
    """
    dependencies = _dependencies(request)
    settings = dependencies.settings
    if settings.environment not in {"development", "test"} or not settings.fake_identity_enabled:
        raise ApplicationError(
            code="NOT_FOUND",
            message="Not found.",
            status_code=404,
        )

    try:
        body = DevLoginRequest.model_validate(await request.json())
    except Exception as error:
        raise ApplicationError(
            code="VALIDATION_FAILED",
            message="The login request is not valid.",
            status_code=422,
        ) from error

    now = dependencies.clock()
    # A minimal actor is enough to create the session row; every later request
    # reads the real roles and permissions back out of PostgreSQL.
    seed = ActorContext(
        tenant_id=body.tenant_id,
        actor_id=body.actor_id,
        subject=body.subject,
        auth_method="test_fixture",
        roles=(),
        permissions=(),
        correlation_id=_correlation_id(request),
    )
    credentials = dependencies.store.create(seed, now)

    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "version": "1",
            "csrf_token": credentials.csrf_token,
            "idle_expires_at": credentials.idle_expires_at.isoformat(),
            "absolute_expires_at": credentials.absolute_expires_at.isoformat(),
        },
    )
    # Spelled out rather than splatted from `SESSION_COOKIE_ATTRIBUTES` so the
    # type checker verifies each attribute; the constant is asserted against these
    # values by `test_the_session_cookie_carries_the_adr_001_attributes`.
    response.set_cookie(
        SESSION_COOKIE_NAME,
        credentials.raw_session_token,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/session")
async def read_session(request: Request) -> Response:
    """What the server believes about the caller. Useful for driving the API by hand."""
    actor = getattr(request.state, "actor", None)
    if not isinstance(actor, ActorContext):
        raise AuthenticationRequired
    view = SessionView(
        tenant_id=actor.tenant_id,
        actor_id=actor.actor_id,
        subject=actor.subject,
        roles=actor.roles,
        permissions=actor.permissions,
        assurance=actor.assurance,
    )
    return JSONResponse(status_code=status.HTTP_200_OK, content=view.model_dump(mode="json"))


@router.post("/logout")
async def logout(request: Request) -> Response:
    actor = getattr(request.state, "actor", None)
    if not isinstance(actor, ActorContext):
        raise AuthenticationRequired
    dependencies = _dependencies(request)
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token is not None:
        dependencies.store.revoke(raw_token, actor.actor_id, dependencies.clock())
    response = JSONResponse(status_code=status.HTTP_200_OK, content={"version": "1"})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
