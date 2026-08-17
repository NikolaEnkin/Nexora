import logging
from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any

import structlog

REDACTED = "[REDACTED]"
SENSITIVE_FRAGMENTS = (
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "database_url",
    "password",
    "pepper",
    "secret",
    "session",
    "token",
)


def redact_data(value: Any, secret_values: Iterable[str] = ()) -> Any:
    secrets = tuple(secret for secret in secret_values if secret)
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if any(fragment in str(key).lower() for fragment in SENSITIVE_FRAGMENTS)
            else redact_data(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item, secrets) for item in value)
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            redacted = redacted.replace(secret, REDACTED)
        return redacted
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return REDACTED


def redaction_processor(
    _logger: object, _method_name: str, event_dict: MutableMapping[str, Any]
) -> Mapping[str, Any]:
    redacted = redact_data(event_dict)
    if not isinstance(redacted, dict):
        raise TypeError("structured log event must remain a mapping")
    return redacted


def make_redaction_processor(
    secret_values: Iterable[str],
) -> structlog.types.Processor:
    secrets = tuple(secret_values)

    def processor(
        _logger: object, _method_name: str, event_dict: MutableMapping[str, Any]
    ) -> Mapping[str, Any]:
        redacted = redact_data(event_dict, secrets)
        if not isinstance(redacted, dict):
            raise TypeError("structured log event must remain a mapping")
        return redacted

    return processor


def configure_logging(level: str = "INFO", *, secret_values: Iterable[str] = ()) -> None:
    logging.basicConfig(level=getattr(logging, level), format="%(message)s")
    structlog.configure(
        processors=[
            make_redaction_processor(secret_values),
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        cache_logger_on_first_use=True,
    )
