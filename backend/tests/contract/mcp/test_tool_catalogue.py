"""`P04-001` — the tool catalogue is exact, closed, and carries no generic power."""

import pytest

from app.mcp.contracts import ToolAudience
from app.mcp.registry import FORBIDDEN_ARGUMENT_NAMES, TOOLS, lookup, visible_to
from app.policy.catalogue import CATALOGUE

pytestmark = pytest.mark.contract

# Phase 04 ships the three client tools. The other nine from packet §4 are absent
# on purpose: they are blocked by HD-004, and a stub would be the guessed default
# packet §8 forbids. This list changing is a deliberate act, not a side effect.
EXPECTED_TOOLS = {"client_get", "client_create", "client_update"}


def test_exact_closed_v1_catalogue() -> None:
    """`P04-001` — the exact set, nothing more."""
    assert {tool.name for tool in TOOLS} == EXPECTED_TOOLS
    assert len(TOOLS) == len(EXPECTED_TOOLS), "a duplicate tool name would shadow another"


def test_every_schema_is_closed() -> None:
    """`additionalProperties: false` is what stops an undeclared argument."""
    for tool in TOOLS:
        assert tool.input_schema["additionalProperties"] is False, tool.name
        assert tool.input_schema["type"] == "object", tool.name


def test_no_tool_accepts_a_generic_capability() -> None:
    """`ARCH-008`. Checked over declared argument names, not over a tool blocklist."""
    for tool in TOOLS:
        for argument in tool.input_schema["properties"]:
            assert argument not in FORBIDDEN_ARGUMENT_NAMES, f"{tool.name}.{argument}"


def test_no_tool_accepts_identity_or_a_verdict() -> None:
    """Identity comes from the session boundary; risk comes from the catalogue."""
    smuggling = {"tenant_id", "actor_id", "roles", "permissions", "assurance", "approved", "risk"}
    for tool in TOOLS:
        assert not (smuggling & set(tool.input_schema["properties"])), tool.name


def test_tool_risk_matches_the_accepted_catalogue() -> None:
    """The registry must not hold a second opinion about risk.

    `ADR-004` §1 is the authority. If these ever disagree, one of them is wrong and
    the build should say so rather than let the looser one win at runtime.
    """
    for tool in TOOLS:
        assert tool.name in CATALOGUE, f"{tool.name} is not classified by ADR-004"
        assert tool.risk is CATALOGUE[tool.name].risk
        assert tool.required_permission == CATALOGUE[tool.name].required_permission


def test_every_write_tool_requires_an_idempotency_key() -> None:
    """`ARCH-004`: a write without a key cannot be made exactly-once."""
    for tool in TOOLS:
        assert tool.writes == tool.requires_idempotency_key, tool.name


def test_reads_are_r1_and_writes_are_not() -> None:
    for tool in TOOLS:
        if tool.writes:
            assert tool.risk.value != "R1", f"{tool.name} writes but is classified R1"
        else:
            assert tool.risk.value == "R1", f"{tool.name} only reads but is not R1"


@pytest.mark.parametrize("audience", list(ToolAudience))
def test_discovery_is_audience_scoped(audience: ToolAudience) -> None:
    for tool in visible_to(audience):
        assert audience in tool.audiences


def test_an_unknown_tool_resolves_to_nothing() -> None:
    for name in ("sql_query", "shell", "http_request", "admin", "client_delete", ""):
        assert lookup(name, ToolAudience.AGENT) is None


def test_every_tool_declares_a_purpose() -> None:
    """`P04-UAT-01` has Nikola read this matrix; an undocumented tool cannot be signed."""
    for tool in TOOLS:
        assert tool.purpose.strip(), tool.name
        assert tool.audiences, tool.name
