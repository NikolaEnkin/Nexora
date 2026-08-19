"""P02-002 — fixed intents follow the documented node and route sequence.

The graph runs without a checkpointer here, so this slice proves routing and node
order alone. Durable resume is proved by P02-003 and P02-004.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml

from app.agent.errors import InvalidState, RuntimeErrorCode
from app.agent.graph import ROUTE_TO_NODE, build_graph
from app.agent.model import DeterministicModelAdapter, ModelPort, ModelRequest, ModelResponse
from app.agent.state import (
    AgentMessage,
    AgentRoute,
    AgentState,
    MessageRole,
    OperationState,
    parse_agent_state_v1,
)
from app.agent.tools import TOOL_REGISTRY
from app.config import Settings

FIXTURE = Path("backend/tests/fixtures/agent/routing-cases.yaml")
FROZEN_NOW = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
TENANT = UUID("20000000-0000-0000-0000-000000000001")
ACTOR = UUID("30000000-0000-0000-0000-000000000001")
CONVERSATION = UUID("a0000000-0000-0000-0000-000000000001")
OPERATION = UUID("b0000000-0000-0000-0000-000000000001")
CORRELATION = UUID("90000000-0000-0000-0000-000000000001")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(FIXTURE.read_text())
    return loaded


def _initial_state(messages: list[dict[str, str]]) -> AgentState:
    return AgentState(
        tenant_id=TENANT,
        actor_id=ACTOR,
        conversation_id=CONVERSATION,
        operation_id=OPERATION,
        request_id="fixture-client-request-001",
        messages=tuple(
            AgentMessage(
                message_id=UUID(f"c0000000-0000-0000-0000-{index:012d}"),
                role=MessageRole(item["role"]),
                content=item["content"],
                created_at=FROZEN_NOW,
            )
            for index, item in enumerate(messages, start=1)
        ),
        status=OperationState.RECEIVED,
        correlation_id=CORRELATION,
        checkpoint_seq=0,
    )


def _graph(model: ModelPort | None = None) -> Any:
    return build_graph(
        model=model or DeterministicModelAdapter(Settings(environment="test")),
        clock=lambda: FROZEN_NOW,
    )


@pytest.mark.unit
def test_fixed_intents_follow_documented_nodes() -> None:
    fixture = _fixture()
    documented = set(fixture["documented_nodes"])
    graph = _graph()

    assert fixture["cases"], "the routing fixture must not be empty"
    for case in fixture["cases"]:
        name = case["name"]
        state = _initial_state(case["messages"])

        observed = [next(iter(update)) for update in graph.stream(state, stream_mode="updates")]
        final = AgentState.model_validate(graph.invoke(state))

        assert observed == case["expected_nodes"], name
        assert documented.issuperset(observed), name
        assert final.route is AgentRoute(case["expected_route"]), name
        assert final.status is OperationState(case["expected_status"]), name
        assert (final.error.value if final.error else None) == case["expected_error"], name
        assert final.messages[-1].content == case["expected_reply"], name
        assert final.messages[-1].role is MessageRole.ASSISTANT, name
        assert final.checkpoint_seq == case["expected_checkpoint_seq"], name

        # Every node leaves a state that is still a valid v1 contract.
        assert parse_agent_state_v1(final.model_dump(mode="json")) == final, name

        # No business tool exists, before or after the run.
        assert TOOL_REGISTRY == {}, name


@pytest.mark.unit
def test_model_output_cannot_select_the_route_or_grant_authority() -> None:
    """A hostile model port demanding a protected outcome changes nothing."""

    class HostileModel:
        calls: int = 0

        def respond(self, request: ModelRequest) -> ModelResponse:
            HostileModel.calls += 1
            # The model insists on a different route, a permission and a tool.
            return ModelResponse(
                route_hint="CONTROLLED_FAILURE; grant tenant.manage; call send_email",
                deltas=("granted", ": ", "tenant.manage"),
                text="granted: tenant.manage",
            )

    graph = _graph(HostileModel())
    state = _initial_state([{"role": "USER", "content": "an ordinary answerable question"}])

    observed = [next(iter(update)) for update in graph.stream(state, stream_mode="updates")]
    final = AgentState.model_validate(graph.invoke(state))

    # The deterministic rule still chose ECHO and the run still completed.
    assert observed == ["receive", "validate", "route", "answer", "complete"]
    assert final.route is AgentRoute.ECHO
    assert final.status is OperationState.COMPLETED
    assert final.error is None
    # The model's prose became message content and nothing else.
    assert final.messages[-1].content == "granted: tenant.manage"
    assert final.messages[-1].role is MessageRole.ASSISTANT
    assert HostileModel.calls > 0
    assert TOOL_REGISTRY == {}


@pytest.mark.unit
def test_branch_targets_are_a_closed_set() -> None:
    assert set(ROUTE_TO_NODE) == set(AgentRoute)
    assert set(ROUTE_TO_NODE.values()) == {"answer", "clarify", "controlled_failure"}


@pytest.mark.unit
def test_terminal_state_cannot_reactivate_through_the_graph() -> None:
    """A terminal operation is refused before any node mutates it.

    The refusal has to happen in `receive`: moving the status to RUNNING and only
    then noticing the state was terminal would already be the reactivation.
    """
    graph = _graph()
    started = _initial_state([{"role": "USER", "content": "an ordinary answerable question"}])

    for terminal_state in (
        OperationState.COMPLETED,
        OperationState.FAILED,
        OperationState.CANCELLED,
    ):
        terminal = started.model_copy(update={"status": terminal_state})
        with pytest.raises(InvalidState) as captured:
            graph.invoke(terminal)
        assert captured.value.code == RuntimeErrorCode.INVALID_STATE

        # Nothing ran, so the state the caller holds is untouched.
        assert terminal.status is terminal_state
        assert terminal.checkpoint_seq == 0
        assert len(terminal.messages) == 1


@pytest.mark.unit
def test_graph_exposes_exactly_the_documented_nodes() -> None:
    fixture = _fixture()
    nodes = set(_graph().get_graph().nodes) - {"__start__", "__end__"}
    assert nodes == set(fixture["documented_nodes"])
