"""P02-008 — message content cannot expose or call a business tool.

The negative assertions are the point: after every malicious message the registry
is still empty, no tool resolves, no protected side effect exists, and no socket
was opened. `backend/tests/conftest.py` blocks non-loopback connections globally,
so an attempted outbound call fails the test rather than escaping quietly.
"""

import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from app.agent.model import DeterministicModelAdapter, ModelRequest
from app.agent.routing import select_route
from app.agent.state import AgentMessage, AgentRoute, MessageRole
from app.agent.tools import TOOL_REGISTRY, ToolNotAllowed, available_tool_names, resolve_tool
from app.config import Settings

FIXTURE = Path("backend/tests/fixtures/agent/malicious-tool-request.json")
FROZEN_NOW = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


def _message(content: str) -> AgentMessage:
    return AgentMessage(
        message_id=UUID("c0000000-0000-0000-0000-000000000001"),
        role=MessageRole.USER,
        content=content,
        created_at=FROZEN_NOW,
    )


@pytest.mark.security
def test_prompt_cannot_expose_or_call_business_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture()
    adapter = DeterministicModelAdapter(Settings(environment="test"))
    operation_id = UUID(fixture["operation_id"])

    opened_sockets: list[object] = []
    original_connect = socket.socket.connect

    def record_connect(sock: socket.socket, address: object) -> object:
        opened_sockets.append(address)
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", record_connect)

    assert fixture["malicious_messages"], "the malicious fixture must not be empty"
    for case in fixture["malicious_messages"]:
        messages = (_message(case["content"]),)

        # The route is chosen by the deterministic rule, never by the content's demand.
        route = select_route(messages)
        assert route in {AgentRoute.ECHO, AgentRoute.CLARIFY}, case["name"]
        assert route is not AgentRoute.CONTROLLED_FAILURE, case["name"]

        response = adapter.respond(
            ModelRequest(operation_id=operation_id, route=route, messages=messages)
        )

        # The model may say anything at all; none of it becomes authority.
        assert isinstance(response.route_hint, str), case["name"]
        assert response.text == "".join(response.deltas), case["name"]

        # Zero protected side effects.
        assert TOOL_REGISTRY == {}, case["name"]
        assert available_tool_names() == (), case["name"]
        assert opened_sockets == [], case["name"]


@pytest.mark.security
def test_no_business_tool_resolves_by_any_name() -> None:
    fixture = _fixture()

    assert TOOL_REGISTRY == {}
    assert available_tool_names() == ()

    for name in fixture["forbidden_tool_names"]:
        assert name not in TOOL_REGISTRY
        with pytest.raises(ToolNotAllowed) as captured:
            resolve_tool(name)
        # Unknown and forbidden are indistinguishable, so probing leaks nothing.
        assert captured.value.code == "TOOL_NOT_ALLOWED"
        assert captured.value.status_code == 403
        assert captured.value.details == {}


@pytest.mark.security
def test_registry_has_no_registration_path() -> None:
    import app.agent.tools as tools_module

    # No mutation API exists, by name or by type.
    exported = {name for name in dir(tools_module) if not name.startswith("_")}
    for forbidden in ("register_tool", "add_tool", "register", "load_plugins", "discover_tools"):
        assert forbidden not in exported

    # The container itself is immutable, so a reference leak cannot be exploited.
    with pytest.raises(TypeError):
        TOOL_REGISTRY["send_email"] = object()  # type: ignore[index]
    assert TOOL_REGISTRY == {}


@pytest.mark.security
def test_deterministic_adapter_is_forbidden_in_production() -> None:
    # A production Settings instance cannot even be constructed, so the adapter can
    # never be reached with production configuration.
    with pytest.raises(ValueError, match="production"):
        Settings(environment="production", fake_identity_enabled=False)
