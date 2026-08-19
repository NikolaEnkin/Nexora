"""Phase-03 failure taxonomy — packet §11.

Every code here is non-disclosing. `APPROVAL_NOT_AUTHORIZED` in particular must
not reveal whether the approval exists, who its approvers are, or which tenant
owns it, so it carries no details and reads identically to the absent case.
"""

from app.errors import ApplicationError


class PolicyDenied(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="POLICY_DENIED",
            message="The action is not permitted by policy.",
            status_code=403,
        )


class ActionUnclassified(ApplicationError):
    """An action absent from the catalogue. `ARCH-015` makes this a stop condition."""

    def __init__(self) -> None:
        super().__init__(
            code="POLICY_DENIED",
            message="The action is not permitted by policy.",
            status_code=403,
        )


class RateLimited(ApplicationError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            code="RATE_LIMITED",
            message="The action rate limit was exceeded.",
            status_code=429,
            retryable=True,
            details={"retry_after": retry_after_seconds},
        )
