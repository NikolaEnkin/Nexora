"""`RuntimeError v1` codes mapped onto the Phase-01 `ErrorEnvelope` boundary.

`install_error_handlers` filters `details` down to an allowlist, so none of these
errors can leak a stack trace, a DSN, database internals, a secret, or the
existence of a foreign object. `OperationNotFound` is deliberately identical for
"absent" and "not yours".
"""

from enum import StrEnum

from app.errors import ApplicationError

STATE_SUPPORTED_MAJOR = 1


class RuntimeErrorCode(StrEnum):
    INVALID_STATE = "INVALID_STATE"
    CHECKPOINT_CONFLICT = "CHECKPOINT_CONFLICT"
    OPERATION_NOT_FOUND = "OPERATION_NOT_FOUND"
    DEPENDENCY_TIMEOUT = "DEPENDENCY_TIMEOUT"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    INTERNAL = "INTERNAL"
    STATE_VERSION_UNSUPPORTED = "STATE_VERSION_UNSUPPORTED"


class InvalidState(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code=RuntimeErrorCode.INVALID_STATE,
            message="The operation is not in a state that allows this transition.",
            status_code=409,
        )


class CheckpointConflict(ApplicationError):
    """Bounded retry: the caller must reload the latest sequence, never overwrite."""

    def __init__(self) -> None:
        super().__init__(
            code=RuntimeErrorCode.CHECKPOINT_CONFLICT,
            message="The checkpoint sequence was advanced by another writer.",
            status_code=409,
            retryable=True,
        )


class OperationNotFound(ApplicationError):
    """Identical response for an absent operation and an unauthorized one."""

    def __init__(self) -> None:
        super().__init__(
            code=RuntimeErrorCode.OPERATION_NOT_FOUND,
            message="The operation was not found.",
            status_code=404,
        )


class DependencyTimeout(ApplicationError):
    def __init__(self) -> None:
        super().__init__(
            code=RuntimeErrorCode.DEPENDENCY_TIMEOUT,
            message="A required dependency did not respond in time.",
            status_code=504,
            retryable=True,
        )


class StateVersionUnsupported(ApplicationError):
    """Blocks resume and preserves the stored checkpoint untouched."""

    def __init__(self, version: object) -> None:
        super().__init__(
            code=RuntimeErrorCode.STATE_VERSION_UNSUPPORTED,
            message="The agent state schema major version is not supported.",
            status_code=409,
            details={"supported_major": str(STATE_SUPPORTED_MAJOR)},
        )


class RuntimeInternalError(ApplicationError):
    """No blind retry: the caller gets a safe message and a correlation reference."""

    def __init__(self) -> None:
        super().__init__(
            code=RuntimeErrorCode.INTERNAL,
            message="The runtime could not complete the operation.",
            status_code=500,
        )
