"""The Phase-02 tool registry, which is empty and has no way to stop being empty.

`ARCH-008` forbids generic SQL, shell, arbitrary HTTP, Cypher, filesystem and
administrator tools. Phase 02 goes further: it exposes *no* tool at all, and
provides no registration function, no plugin hook, no entry-point scan and no
mutable container. There is therefore no code path — reachable from a prompt, a
model response, a retrieved document or an email — that can add one.

Narrow, typed, versioned, authorized and audited business tools arrive in Phase 04
behind the policy and approval engine built in Phase 03. Adding one here would
skip both gates.
"""

from types import MappingProxyType
from typing import Final

from app.errors import ApplicationError


class ToolNotAllowed(ApplicationError):
    """Raised for every tool name, including ones that do not exist.

    The response is identical whether a tool is unknown or merely unavailable, so
    probing the registry teaches an attacker nothing about a future catalogue.
    """

    def __init__(self) -> None:
        super().__init__(
            code="TOOL_NOT_ALLOWED",
            message="No tool is available to this runtime.",
            status_code=403,
        )


# Deliberately immutable and deliberately empty. A later phase that needs a tool
# must add it through its own packet, migration, policy binding and audit path.
TOOL_REGISTRY: Final[MappingProxyType[str, object]] = MappingProxyType({})


def available_tool_names() -> tuple[str, ...]:
    """Always empty. Present so callers never reach for the mapping directly."""
    return tuple(sorted(TOOL_REGISTRY))


def resolve_tool(name: str) -> object:
    """Always refuses.

    There is no name — `send_email`, `execute_sql`, `run_shell` or anything else —
    for which this returns a callable.
    """
    raise ToolNotAllowed
