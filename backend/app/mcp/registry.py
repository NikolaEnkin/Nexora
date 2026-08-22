"""The tool catalogue. Closed by construction.

`ARCH-008` forbids a generic SQL, shell, HTTP, Cypher, filesystem or administrator
tool. That prohibition is not enforced by a denylist of forbidden names — a
denylist only stops the names somebody thought of. It is enforced structurally:

* the catalogue is a fixed tuple in this module, and nothing appends to it at
  runtime;
* every schema sets `additionalProperties: false`, so an argument the tool did not
  declare is a validation error rather than a passthrough;
* no tool accepts a free-text query, a path, a URL or a statement of any kind.

`P04-002` asserts the exact set, so adding a tool without updating that test
fails the build rather than silently widening the surface.

The `risk` and `required_permission` values are **not** decided here. They come
from `ADR-004` §1 via `app.policy.catalogue`, and a mismatch between the two is a
defect in one of them — `test_tool_risk_matches_the_accepted_catalogue` fails if
they drift.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.mcp.contracts import ToolAudience
from app.policy.catalogue import CATALOGUE
from app.policy.contracts import RiskLevel

TOOL_VERSION = 1

# Argument names that must never appear in any schema. This is a *belt* over the
# structural control, not the control itself: the real guarantee is that each
# schema below is closed and lists only business fields.
FORBIDDEN_ARGUMENT_NAMES = frozenset(
    {
        "sql",
        "query",
        "statement",
        "command",
        "shell",
        "script",
        "path",
        "file",
        "url",
        "endpoint",
        "cypher",
        "eval",
        "exec",
        "tenant_id",
        "actor_id",
        "roles",
        "permissions",
        "assurance",
        "approved",
        "risk",
    }
)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One narrow tool. Everything a reviewer needs is on this object."""

    name: str
    purpose: str
    audiences: frozenset[ToolAudience]
    input_schema: Mapping[str, Any]
    writes: bool
    requires_idempotency_key: bool

    @property
    def risk(self) -> RiskLevel:
        return CATALOGUE[self.name].risk

    @property
    def required_permission(self) -> str:
        return CATALOGUE[self.name].required_permission


_BOTH = frozenset({ToolAudience.AGENT, ToolAudience.OPERATOR_UI})


def _schema(properties: Mapping[str, Any], required: list[str]) -> Mapping[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": required,
    }


_UUID = {"type": "string", "format": "uuid"}
_NAME = {"type": "string", "minLength": 1, "maxLength": 255}

CLIENT_GET = ToolDefinition(
    name="client_get",
    purpose="Resolve one client by canonical id or by exact legal name.",
    audiences=_BOTH,
    input_schema=_schema(
        {"client_id": _UUID, "legal_name": _NAME},
        required=[],  # exactly one is required; the service enforces which
    ),
    writes=False,
    requires_idempotency_key=False,
)

CLIENT_CREATE = ToolDefinition(
    name="client_create",
    purpose="Create a client record with a canonical normalized identity.",
    audiences=_BOTH,
    input_schema=_schema(
        {
            "legal_name": _NAME,
            "display_name": _NAME,
            "contact_ref": {"type": "object", "additionalProperties": True},
        },
        required=["legal_name", "display_name"],
    ),
    writes=True,
    requires_idempotency_key=True,
)

CLIENT_UPDATE = ToolDefinition(
    name="client_update",
    purpose="Patch a client under an optimistic version check.",
    audiences=_BOTH,
    input_schema=_schema(
        {
            "client_id": _UUID,
            "expected_version": {"type": "integer", "minimum": 1},
            "legal_name": _NAME,
            "display_name": _NAME,
            "status": {"type": "string", "enum": ["ACTIVE", "ARCHIVED"]},
        },
        required=["client_id", "expected_version"],
    ),
    writes=True,
    requires_idempotency_key=True,
)

# The complete catalogue. Phase 04's remaining tools are absent on purpose:
# offer and invoice tools are blocked by HD-004, and adding a stub would be the
# guessed default that packet §8 forbids.
TOOLS: tuple[ToolDefinition, ...] = (CLIENT_GET, CLIENT_CREATE, CLIENT_UPDATE)

BY_NAME: Mapping[str, ToolDefinition] = {tool.name: tool for tool in TOOLS}


def visible_to(audience: ToolAudience) -> tuple[ToolDefinition, ...]:
    """The tools an audience may even see.

    A tool outside the audience is not merely refused on call — it is absent from
    discovery, so its name and schema leak nothing (packet §12).
    """
    return tuple(tool for tool in TOOLS if audience in tool.audiences)


def lookup(name: str, audience: ToolAudience) -> ToolDefinition | None:
    tool = BY_NAME.get(name)
    if tool is None or audience not in tool.audiences:
        return None
    return tool
