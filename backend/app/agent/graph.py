"""The deterministic master graph.

`AgentState v1` is used directly as the LangGraph state schema, so the graph
cannot carry a field the contract does not declare — LangGraph merges each node's
partial update back into the same `extra="forbid"` model.

Node order is fixed:

    receive -> validate -> route -> {answer | clarify | controlled_failure} -> complete

Which branch runs is decided by `app.agent.routing.select_route`, a pure function
of message text, and by structural validity. Never by model output: the model is
asked for prose only, after the route is already chosen.

`CONTROLLED_FAILURE` is reachable only from a structurally invalid conversation —
one with no user turn at all. No message content routes there, so a prompt cannot
steer an operation into the failure path any more than it can steer one into a
tool. An already-terminal operation does not reach routing: `receive` refuses it.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agent.errors import InvalidState, RuntimeErrorCode
from app.agent.identity import derive_message_id
from app.agent.model import ModelPort, ModelRequest
from app.agent.routing import select_route
from app.agent.state import (
    TERMINAL_STATES,
    AgentMessage,
    AgentRoute,
    AgentState,
    MessageRole,
    OperationState,
)

NODE_RECEIVE = "receive"
NODE_VALIDATE = "validate"
NODE_ROUTE = "route"
NODE_ANSWER = "answer"
NODE_CLARIFY = "clarify"
NODE_CONTROLLED_FAILURE = "controlled_failure"
NODE_COMPLETE = "complete"

ROUTE_TO_NODE: dict[AgentRoute, str] = {
    AgentRoute.ECHO: NODE_ANSWER,
    AgentRoute.CLARIFY: NODE_CLARIFY,
    AgentRoute.CONTROLLED_FAILURE: NODE_CONTROLLED_FAILURE,
}

Clock = Callable[[], datetime]


def _has_user_turn(state: AgentState) -> bool:
    return any(message.role is MessageRole.USER for message in state.messages)


def build_graph(
    *,
    model: ModelPort,
    clock: Clock,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[AgentState, Any, Any, Any]:
    """Compile the Phase-02 graph.

    `model` and `clock` are injected so a test can fix both and assert exact
    output rather than plausible prose.
    """

    def receive(state: AgentState) -> dict[str, Any]:
        # Refuse before anything is mutated. This is the first of three
        # independent barriers against reactivating a terminal operation: the
        # runtime service will not schedule one, this node will not run one, and
        # the `trg_agent_operations_protect_state` trigger will not persist one.
        # The check belongs here rather than in `validate`, because moving the
        # status to RUNNING first would itself be the reactivation.
        if state.status in TERMINAL_STATES:
            raise InvalidState
        return {
            "status": OperationState.RUNNING,
            "checkpoint_seq": state.checkpoint_seq + 1,
        }

    def validate(state: AgentState) -> dict[str, Any]:
        update: dict[str, Any] = {"checkpoint_seq": state.checkpoint_seq + 1}
        if not _has_user_turn(state):
            update["route"] = AgentRoute.CONTROLLED_FAILURE
            update["error"] = RuntimeErrorCode.INVALID_STATE
        return update

    def route(state: AgentState) -> dict[str, Any]:
        update: dict[str, Any] = {"checkpoint_seq": state.checkpoint_seq + 1}
        if state.route is None:
            update["route"] = select_route(state.messages)
        return update

    def _append_assistant(state: AgentState, text: str) -> tuple[AgentMessage, ...]:
        message = AgentMessage(
            message_id=derive_message_id(state.operation_id, len(state.messages)),
            role=MessageRole.ASSISTANT,
            content=text,
            created_at=clock(),
        )
        return (*state.messages, message)

    def answer(state: AgentState) -> dict[str, Any]:
        response = model.respond(
            ModelRequest(
                operation_id=state.operation_id,
                route=AgentRoute.ECHO,
                messages=state.messages,
            )
        )
        return {
            "messages": _append_assistant(state, response.text),
            "checkpoint_seq": state.checkpoint_seq + 1,
        }

    def clarify(state: AgentState) -> dict[str, Any]:
        response = model.respond(
            ModelRequest(
                operation_id=state.operation_id,
                route=AgentRoute.CLARIFY,
                messages=state.messages,
            )
        )
        return {
            "messages": _append_assistant(state, response.text),
            "checkpoint_seq": state.checkpoint_seq + 1,
        }

    def controlled_failure(state: AgentState) -> dict[str, Any]:
        response = model.respond(
            ModelRequest(
                operation_id=state.operation_id,
                route=AgentRoute.CONTROLLED_FAILURE,
                messages=state.messages,
            )
        )
        return {
            "messages": _append_assistant(state, response.text),
            "error": state.error or RuntimeErrorCode.INTERNAL,
            "checkpoint_seq": state.checkpoint_seq + 1,
        }

    def complete(state: AgentState) -> dict[str, Any]:
        return {
            "status": OperationState.FAILED if state.error else OperationState.COMPLETED,
            "checkpoint_seq": state.checkpoint_seq + 1,
        }

    def branch(state: AgentState) -> str:
        # `state.route` is always set by this point, by a deterministic rule.
        return ROUTE_TO_NODE[state.route or AgentRoute.CONTROLLED_FAILURE]

    graph: StateGraph[AgentState, Any, Any, Any] = StateGraph(AgentState)
    graph.add_node(NODE_RECEIVE, receive)
    graph.add_node(NODE_VALIDATE, validate)
    graph.add_node(NODE_ROUTE, route)
    graph.add_node(NODE_ANSWER, answer)
    graph.add_node(NODE_CLARIFY, clarify)
    graph.add_node(NODE_CONTROLLED_FAILURE, controlled_failure)
    graph.add_node(NODE_COMPLETE, complete)

    graph.add_edge(START, NODE_RECEIVE)
    graph.add_edge(NODE_RECEIVE, NODE_VALIDATE)
    graph.add_edge(NODE_VALIDATE, NODE_ROUTE)
    # The path map is the exact closed set of branch targets, so an unexpected
    # return value fails at compile time rather than dispatching somewhere new.
    graph.add_conditional_edges(NODE_ROUTE, branch, sorted(set(ROUTE_TO_NODE.values())))
    graph.add_edge(NODE_ANSWER, NODE_COMPLETE)
    graph.add_edge(NODE_CLARIFY, NODE_COMPLETE)
    graph.add_edge(NODE_CONTROLLED_FAILURE, NODE_COMPLETE)
    graph.add_edge(NODE_COMPLETE, END)

    return graph.compile(checkpointer=checkpointer)
