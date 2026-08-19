"""Approval-lifecycle failure taxonomy — packet §11."""

from app.errors import ApplicationError


class ApprovalRequired(ApplicationError):
    """Not an error condition so much as a durable instruction to go get a human."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(
            code="APPROVAL_REQUIRED",
            message="The action requires an approval decision.",
            status_code=409,
            details={"approval_id": approval_id},
        )


class ApprovalNotAuthorized(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_NOT_AUTHORIZED",
            message="The approval decision is not permitted.",
            status_code=403,
        )


class ApprovalStale(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_STALE",
            message="The approved payload no longer matches the requested action.",
            status_code=409,
        )


class ApprovalExpired(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_EXPIRED",
            message="The approval is no longer current.",
            status_code=409,
        )


class ApprovalRevoked(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_REVOKED",
            message="The approval is no longer current.",
            status_code=409,
        )


class ApprovalReplayed(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_REPLAYED",
            message="The approval was already consumed.",
            status_code=409,
        )


class ApprovalNotFound(ApplicationError):
    """Absent and unauthorized are indistinguishable, exactly as in Phase 02."""

    def __init__(self) -> None:
        super().__init__(
            code="APPROVAL_NOT_FOUND",
            message="The approval was not found.",
            status_code=404,
        )
