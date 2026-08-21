import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.contracts import ActorContext
from app.db import set_request_context
from app.errors import AuthenticationRequired
from app.identity.session import (
    IDLE_TIMEOUT,
    STEP_UP_WINDOW,
    calculate_session_expiry,
    hash_session_token,
    issue_session_token,
)
from app.identity.step_up import StepUpFactor


@dataclass(frozen=True, slots=True)
class SessionCredentials:
    raw_session_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    idle_expires_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class ResolvedSession:
    """A resolved session plus the stored CSRF hash.

    `validate_csrf_and_origin` needs the stored hash, and `resolve` already reads
    it but does not return it. Phase 04 adds this rather than changing `resolve`,
    whose exact signature and behaviour Phase-01 tests assert (amendment A-1:
    additive only).

    The hash never leaves the server and is not part of `ActorContext`, so it
    cannot travel into a trace, an audit payload or a stream event.
    """

    actor: ActorContext
    csrf_hash: str = field(repr=False)


def _assurance(step_up_at: datetime | None, now: datetime) -> Literal["standard", "step_up"]:
    """`ADR-004` §4 — derived, never stored, never supplied by a caller.

    `NULL` means the session never proved a factor, which resolves to `standard`.
    That is the fail-closed default and the value every session starts with.
    """
    if step_up_at is None or now - step_up_at >= STEP_UP_WINDOW:
        return "standard"
    return "step_up"


@dataclass(slots=True)
class PostgresSessionStore:
    sessions: sessionmaker[Session]
    pepper: str
    session_id_factory: Callable[[], UUID] = uuid4
    session_token_factory: Callable[[], str] = issue_session_token
    csrf_token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32)

    def create(self, actor: ActorContext, now: datetime) -> SessionCredentials:
        raw_token = self.session_token_factory()
        csrf_token = self.csrf_token_factory()
        expiry = calculate_session_expiry(now)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            valid_actor = session.execute(
                text(
                    """SELECT 1 FROM users JOIN tenants ON tenants.id = users.tenant_id
                    WHERE users.id = :actor_id AND users.status = 'ACTIVE'
                      AND tenants.status = 'ACTIVE'"""
                ),
                {"actor_id": actor.actor_id},
            ).scalar_one_or_none()
            if valid_actor is None:
                raise AuthenticationRequired
            session.execute(
                text(
                    """INSERT INTO auth_sessions (
                        id, tenant_id, user_id, token_hash, csrf_hash, status, last_seen_at,
                        idle_expires_at, absolute_expires_at, revoked_at, created_at, updated_at
                    ) VALUES (
                        :id, :tenant_id, :user_id, :token_hash, :csrf_hash, 'ACTIVE', :now,
                        :idle_expires_at, :absolute_expires_at, NULL, :now, :now
                    )"""
                ),
                {
                    "id": self.session_id_factory(),
                    "tenant_id": actor.tenant_id,
                    "user_id": actor.actor_id,
                    "token_hash": hash_session_token(raw_token, self.pepper),
                    "csrf_hash": hash_session_token(csrf_token, self.pepper),
                    "now": now,
                    "idle_expires_at": expiry.idle_expires_at,
                    "absolute_expires_at": expiry.absolute_expires_at,
                },
            )
        return SessionCredentials(
            raw_session_token=raw_token,
            csrf_token=csrf_token,
            idle_expires_at=expiry.idle_expires_at,
            absolute_expires_at=expiry.absolute_expires_at,
        )

    def resolve(self, raw_token: str, correlation_id: UUID, now: datetime) -> ActorContext:
        token_hash = hash_session_token(raw_token, self.pepper)
        with self.sessions() as session, session.begin():
            row = (
                session.execute(
                    text(
                        """SELECT tenant_id, user_id, external_subject, csrf_hash,
                                  absolute_expires_at
                        FROM nexora_resolve_session(:token_hash, :now)"""
                    ),
                    {"token_hash": token_hash, "now": now},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise AuthenticationRequired
            tenant_id = row["tenant_id"]
            set_request_context(session, tenant_id, row["user_id"])
            role_rows = session.execute(
                text(
                    """SELECT DISTINCT roles.name, permissions.permission_key
                    FROM user_roles
                    JOIN roles ON roles.tenant_id = user_roles.tenant_id
                              AND roles.id = user_roles.role_id
                    JOIN role_permissions ON role_permissions.tenant_id = roles.tenant_id
                                         AND role_permissions.role_id = roles.id
                    JOIN permissions ON permissions.id = role_permissions.permission_id
                    WHERE user_roles.user_id = :user_id
                    ORDER BY roles.name, permissions.permission_key"""
                ),
                {"user_id": row["user_id"]},
            ).all()
            if not role_rows:
                raise AuthenticationRequired
            refreshed_idle = min(now + IDLE_TIMEOUT, row["absolute_expires_at"])
            refreshed = (
                session.execute(
                    text(
                        """UPDATE auth_sessions SET last_seen_at = :now,
                    idle_expires_at = :idle_expires_at, updated_at = :now
                    WHERE token_hash = :token_hash AND status = 'ACTIVE'
                      AND idle_expires_at > :now AND absolute_expires_at > :now
                    RETURNING id, step_up_at"""
                    ),
                    {"now": now, "idle_expires_at": refreshed_idle, "token_hash": token_hash},
                )
                .mappings()
                .one_or_none()
            )
            if refreshed is None:
                raise AuthenticationRequired
            return ActorContext(
                tenant_id=tenant_id,
                actor_id=row["user_id"],
                subject=row["external_subject"],
                auth_method="auth0_oidc",
                assurance=_assurance(refreshed["step_up_at"], now),
                roles=tuple(sorted({role for role, _permission in role_rows})),
                permissions=tuple(sorted({permission for _role, permission in role_rows})),
                correlation_id=correlation_id,
            )

    def resolve_credentials(
        self, raw_token: str, correlation_id: UUID, now: datetime
    ) -> ResolvedSession:
        """Resolve a session and return the stored CSRF hash with it.

        Deliberately a thin wrapper over `resolve` plus one scoped read rather
        than a second copy of the resolution logic: expiry, revocation, role
        loading and the idle refresh must have exactly one implementation, or the
        two would drift and the weaker one would become the real boundary.
        """
        actor = self.resolve(raw_token, correlation_id, now)
        token_hash = hash_session_token(raw_token, self.pepper)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            csrf_hash = session.execute(
                text(
                    """SELECT csrf_hash FROM auth_sessions
                    WHERE token_hash = :token_hash AND status = 'ACTIVE'"""
                ),
                {"token_hash": token_hash},
            ).scalar_one_or_none()
        if csrf_hash is None:
            raise AuthenticationRequired
        return ResolvedSession(actor=actor, csrf_hash=str(csrf_hash))

    def record_step_up(
        self, raw_token: str, actor: ActorContext, factor: StepUpFactor, now: datetime
    ) -> None:
        """Stamp the session with a proven factor.

        The value is the server's own clock, never the provider's claim: a
        provider that reported a future `auth_time` would otherwise extend the
        window. A database trigger refuses a future or backwards value as well,
        so a defect here still cannot widen it.
        """
        token_hash = hash_session_token(raw_token, self.pepper)
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            updated = session.execute(
                text(
                    """UPDATE auth_sessions
                    SET step_up_at = :now, step_up_factor = :factor, updated_at = :now
                    WHERE token_hash = :token_hash AND status = 'ACTIVE'
                      AND user_id = :actor_id
                      AND idle_expires_at > :now AND absolute_expires_at > :now
                    RETURNING id"""
                ),
                {
                    "now": now,
                    "factor": factor.value,
                    "token_hash": token_hash,
                    "actor_id": actor.actor_id,
                },
            ).scalar_one_or_none()
        if updated is None:
            raise AuthenticationRequired

    def revoke(self, raw_token: str, actor_id: UUID, now: datetime) -> None:
        token_hash = hash_session_token(raw_token, self.pepper)
        with self.sessions() as session, session.begin():
            row = session.execute(
                text("SELECT tenant_id, user_id FROM nexora_resolve_session(:token_hash, :now)"),
                {"token_hash": token_hash, "now": now},
            ).one_or_none()
            if row is None or row.user_id != actor_id:
                return
            tenant_id = row.tenant_id
            set_request_context(session, tenant_id, actor_id)
            session.execute(
                text(
                    """UPDATE auth_sessions SET status = 'REVOKED', revoked_at = :now,
                    updated_at = :now WHERE token_hash = :token_hash AND user_id = :actor_id"""
                ),
                {
                    "now": now,
                    "token_hash": token_hash,
                    "actor_id": actor_id,
                },
            )
