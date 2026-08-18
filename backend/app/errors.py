from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.contracts.foundation import ErrorEnvelope


@dataclass(slots=True)
class ApplicationError(Exception):
    code: str
    message: str
    status_code: int
    retryable: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)


class DependencyUnavailable(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="DEPENDENCY_UNAVAILABLE",
            message="A required dependency is unavailable.",
            status_code=503,
            retryable=True,
        )


class AuthenticationRequired(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="AUTHENTICATION_REQUIRED",
            message="Authentication is required.",
            status_code=401,
        )


class ContractVersionUnsupported(ApplicationError):
    def __init__(self, version: object) -> None:
        super().__init__(
            code="CONTRACT_VERSION_UNSUPPORTED",
            message="The contract major version is not supported.",
            status_code=422,
            details={"supported_major": "1"},
        )


class AuthorizationDenied(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="AUTHORIZATION_DENIED",
            message="The operation is not permitted.",
            status_code=403,
        )


class IdempotencyConflict(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="IDEMPOTENCY_CONFLICT",
            message="The idempotency key was already used for a different request.",
            status_code=409,
        )


class IdempotencyInProgress(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="IDEMPOTENCY_IN_PROGRESS",
            message="The idempotent operation is currently in progress.",
            status_code=409,
            retryable=True,
        )


class IdempotencyFinalFailure(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code="IDEMPOTENCY_FINAL_FAILURE",
            message="The idempotent operation previously failed permanently.",
            status_code=409,
            retryable=False,
        )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApplicationError)
    async def handle_application_error(request: Request, error: ApplicationError) -> JSONResponse:
        correlation_id = getattr(
            request.state, "correlation_id", "00000000-0000-0000-0000-000000000000"
        )
        envelope = ErrorEnvelope(
            code=error.code,
            message=error.message,
            correlation_id=correlation_id,
            retryable=error.retryable,
            details={
                key: value for key, value in error.details.items() if key in {"supported_major"}
            },
        )
        return JSONResponse(status_code=error.status_code, content=envelope.model_dump(mode="json"))
