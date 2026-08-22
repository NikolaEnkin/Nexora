"""Step-up verification — `ADR-004` §4 with Amendment 2.

Amendment 2 matches factor strength to what one compromised account can do alone:

* `OPERATOR` and `VIEWER` use **TOTP**. A phished `OPERATOR` still cannot satisfy
  an R3 path, because paths 4 and 5 need two or three other people.
* `OWNER` and `DEPUTY` must use **WebAuthn**. Those two can approve any amount
  alone via paths 1 and 2, so the phishing-resistant factor goes exactly where the
  whole chain rests.

A stronger factor is always acceptable for a weaker requirement; the reverse never
is. SMS and email OTP are absent by decision — the amendment rejects both at every
level.

**The verification is a port.** `Auth0StepUpVerifier` is the production shape and
is not implemented: no Auth0 tenant is configured, and the project forbids
production credentials in tests. `FakeStepUpVerifier` is what runs in development
and test, and it refuses to construct outside them — the same guard the fake
identity adapter already carries.

Nothing here decides `assurance`. It records *that a factor was proven and when*;
`assurance` is derived per request from that timestamp against the five-minute
window, in `PostgresSessionStore`.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from app.config import Settings
from app.errors import ApplicationError


class StepUpFactor(StrEnum):
    """The two factors Amendment 2 admits. SMS and email are deliberately absent."""

    WEBAUTHN = "webauthn"
    TOTP = "totp"


# Ordered strongest first. Acceptability is "at least as strong as required".
_STRENGTH = {StepUpFactor.WEBAUTHN: 2, StepUpFactor.TOTP: 1}

# Roles that may approve an R3 action alone, and therefore owe the stronger factor.
_SOLE_AUTHORITY_ROLES = frozenset({"OWNER", "DEPUTY"})


class StepUpFailed(ApplicationError):
    """Non-disclosing: it never says which factor was expected or presented."""

    def __init__(self) -> None:
        super().__init__(
            code="STEP_UP_FAILED",
            message="The second factor could not be verified.",
            status_code=403,
        )


class StepUpRequired(ApplicationError):
    def __init__(self, required: StepUpFactor) -> None:
        super().__init__(
            code="STEP_UP_REQUIRED",
            message="A recent second factor is required for this action.",
            status_code=403,
            details={"reason": f"required factor: {required.value}"},
        )


@dataclass(frozen=True, slots=True)
class StepUpEvidence:
    """What a verifier returns: who proved what, and when the provider says so."""

    subject: str
    factor: StepUpFactor
    authenticated_at: datetime


def required_factor(roles: tuple[str, ...]) -> StepUpFactor:
    """The weakest factor this actor may use — Amendment 2."""
    if _SOLE_AUTHORITY_ROLES & set(roles):
        return StepUpFactor.WEBAUTHN
    return StepUpFactor.TOTP


def satisfies(presented: StepUpFactor, roles: tuple[str, ...]) -> bool:
    """Whether a presented factor is at least as strong as the role requires."""
    return _STRENGTH[presented] >= _STRENGTH[required_factor(roles)]


class StepUpVerifier(Protocol):
    def verify(self, *, subject: str, evidence: str) -> StepUpEvidence:  # pragma: no cover
        """Exchange provider evidence for a verified factor and instant."""
        ...


@dataclass(frozen=True, slots=True)
class FakeStepUpVerifier:
    """Development and test only.

    Refuses to construct outside development or test, and refuses when the fake
    identity adapter is disabled — the same two conditions that gate
    `/auth/dev-login`. `app/config.py` already refuses production startup while
    that flag is on, so there is no configuration in which this reaches
    production.

    The evidence string names the factor to simulate, so a test can exercise both
    the WebAuthn and the TOTP path, and the refusal when an `OWNER` presents TOTP.
    """

    settings: Settings
    clock: object  # Callable[[], datetime]; kept loose to avoid a circular import

    def __post_init__(self) -> None:
        if self.settings.environment not in {"development", "test"}:
            raise RuntimeError("fake step-up verifier is forbidden outside development/test")
        if not self.settings.fake_identity_enabled:
            raise RuntimeError("fake step-up verifier is disabled")

    def verify(self, *, subject: str, evidence: str) -> StepUpEvidence:
        try:
            factor = StepUpFactor(evidence)
        except ValueError as error:
            raise StepUpFailed from error
        now = self.clock()  # type: ignore[operator]
        return StepUpEvidence(subject=subject, factor=factor, authenticated_at=now)


@dataclass(frozen=True, slots=True)
class Auth0StepUpVerifier:
    """Production shape. **Not implemented.**

    The real flow is a fresh authorization-code round trip through Auth0 with
    `acr_values` demanding multi-factor, then reading `amr` and `auth_time` out of
    the returned ID token. `ADR-001` stores no refresh token, so a silent
    background refresh is not available and must not be invented.

    It is left unimplemented rather than stubbed because no Auth0 tenant is
    configured and the project forbids production credentials in tests. A stub
    that returned success would be worse than nothing: it would make the suite
    green while the control did not exist.
    """

    issuer: str
    audience: str

    def verify(self, *, subject: str, evidence: str) -> StepUpEvidence:
        raise NotImplementedError(
            "the Auth0 step-up round trip is not implemented; no tenant is configured"
        )
