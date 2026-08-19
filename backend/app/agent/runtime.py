"""The runtime driver: operation lifecycle, graph execution, and event emission.

Recovery is the point of this module.

* An unknown outcome is always resolved by reading PostgreSQL first. A retry of a
  completed operation returns the durable result and re-executes nothing.
* Resume continues from the durable checkpoint, so completed nodes are not
  repeated (`BR-02-004`).
* The terminal event is appended exactly once, arbitrated by a partial unique
  index rather than by a service-side check that a concurrent worker could race.
* A stale checkpoint write loses the sequence uniqueness race and surfaces
  `CHECKPOINT_CONFLICT`; the latest durable sequence is never overwritten.

`FailurePoint` exists so those paths are exercised deterministically instead of
being hoped for. It is test-only injection: nothing reads it from configuration,
a request body, or message content.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from langchain_core.runnables import RunnableConfig
from sqlalchemy.orm import Session, sessionmaker

from app.agent.checkpointer import (
    PostgresCheckpointSaver,
    agent_state_from_checkpoint,
    latest_checkpoint_seq,
)
from app.agent.contracts import (
    MessageCompletedData,
    MessageDeltaData,
    OperationFailedData,
    OperationRef,
    OperationStartedData,
    StateChangedData,
    StreamCompletedData,
    StreamEvent,
    StreamEventType,
)
from app.agent.crypto import CheckpointCipherPort
from app.agent.errors import (
    CheckpointConflict,
    DependencyTimeout,
    InvalidState,
    RuntimeErrorCode,
)
from app.agent.events import EventLedger
from app.agent.graph import build_graph
from app.agent.identity import derive_message_id
from app.agent.model import ModelPort, ModelRequest
from app.agent.operations import OperationRepository
from app.agent.state import (
    TERMINAL_STATES,
    AgentMessage,
    AgentRoute,
    AgentState,
    MessageRole,
    OperationState,
    ReasonCode,
)
from app.contracts import ActorContext

MAX_DEPENDENCY_ATTEMPTS = 3


class FailurePoint(StrEnum):
    """Deterministic injection points. Test-only; never read from input."""

    NONE = "NONE"
    AFTER_CHECKPOINT_BEFORE_RESPONSE = "AFTER_CHECKPOINT_BEFORE_RESPONSE"
    AFTER_TERMINAL_BEFORE_RESPONSE = "AFTER_TERMINAL_BEFORE_RESPONSE"
    DEPENDENCY_TIMEOUT = "DEPENDENCY_TIMEOUT"


class InjectedCrash(RuntimeError):
    """A simulated process death. Never surfaces to a client."""


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    operation: OperationRef
    state: AgentState
    events: tuple[StreamEvent, ...]
    resumed: bool


@dataclass(slots=True)
class AgentRuntime:
    """Drives one operation from submission to a durable terminal state."""

    sessions: sessionmaker[Session]
    operations: OperationRepository
    events: EventLedger
    model: ModelPort
    cipher: CheckpointCipherPort
    clock: Callable[[], datetime]
    failure_point: FailurePoint = FailurePoint.NONE
    dependency_failures_remaining: int = 0
    _observed_attempts: int = field(default=0, init=False)

    # -- helpers ---------------------------------------------------------

    def _saver(self, actor: ActorContext) -> PostgresCheckpointSaver:
        return PostgresCheckpointSaver(
            sessions=self.sessions,
            cipher=self.cipher,
            actor=actor,
            clock=self.clock,
        )

    def _config(self, operation: OperationRef) -> RunnableConfig:
        return {"configurable": {"thread_id": operation.thread_id}}

    def _emit(
        self,
        actor: ActorContext,
        operation_id: UUID,
        event_type: StreamEventType,
        data: Any,
    ) -> StreamEvent:
        return self.events.append(
            actor=actor,
            operation_id=operation_id,
            event_type=event_type,
            data=data,
            now=self.clock(),
        )

    def _initial_state(self, operation: OperationRef, message: str) -> AgentState:
        return AgentState(
            tenant_id=operation.tenant_id,
            actor_id=operation.actor_id,
            conversation_id=operation.conversation_id,
            operation_id=operation.operation_id,
            request_id=str(operation.operation_id),
            messages=(
                AgentMessage(
                    message_id=derive_message_id(operation.operation_id, 0),
                    role=MessageRole.USER,
                    content=message,
                    created_at=self.clock(),
                ),
            ),
            status=OperationState.RECEIVED,
            correlation_id=actor_correlation(operation),
            checkpoint_seq=operation.checkpoint_seq,
        )

    # -- execution -------------------------------------------------------

    def execute(
        self,
        *,
        actor: ActorContext,
        operation: OperationRef,
        message: str,
    ) -> RuntimeResult:
        """Run or resume one operation to a durable terminal state.

        Safe to call repeatedly for the same operation: a terminal operation is
        never re-executed, and a partially executed one resumes from its
        checkpoint rather than starting over.
        """
        # Unknown outcome resolution: always read durable state before deciding.
        current = self.operations.load(actor=actor, operation_id=operation.operation_id)
        if current.state in TERMINAL_STATES:
            return RuntimeResult(
                operation=current,
                state=self._durable_state(actor, current),
                events=tuple(self.events.read(actor=actor, operation_id=current.operation_id)),
                resumed=True,
            )

        saver = self._saver(actor)
        config = self._config(current)
        existing = saver.get_tuple(config)
        resuming = existing is not None

        if not resuming:
            self._emit(
                actor,
                current.operation_id,
                StreamEventType.OPERATION_STARTED,
                OperationStartedData(conversation_id=current.conversation_id),
            )
            self._emit(
                actor,
                current.operation_id,
                StreamEventType.OPERATION_STATE_CHANGED,
                StateChangedData(state=OperationState.RECEIVED, reason_code=ReasonCode.ACCEPTED),
            )

        current = self.operations.transition(
            actor=actor,
            operation_id=current.operation_id,
            target=OperationState.RUNNING,
            now=self.clock(),
        )
        self._emit(
            actor,
            current.operation_id,
            StreamEventType.OPERATION_STATE_CHANGED,
            StateChangedData(
                state=OperationState.RUNNING,
                reason_code=ReasonCode.RESUMED if resuming else ReasonCode.NODE_ADVANCED,
            ),
        )

        graph = build_graph(model=self.model, clock=self.clock, checkpointer=saver)
        graph_input = None if resuming else self._initial_state(current, message)

        self._run_with_bounded_retry(graph, graph_input, config)

        if self.failure_point is FailurePoint.AFTER_CHECKPOINT_BEFORE_RESPONSE:
            # Durable state is already written; the caller simply never hears back.
            raise InjectedCrash(FailurePoint.AFTER_CHECKPOINT_BEFORE_RESPONSE)

        final_tuple = saver.get_tuple(config)
        if final_tuple is None:
            raise InvalidState
        final_state = agent_state_from_checkpoint(final_tuple.checkpoint)

        return self._finalize(actor, current, final_state)

    def _run_with_bounded_retry(
        self, graph: Any, graph_input: AgentState | None, config: RunnableConfig
    ) -> None:
        """Bounded, deterministic retry. Never an unbounded loop, never blind."""
        attempts = 0
        while True:
            attempts += 1
            self._observed_attempts = attempts
            if (
                self.failure_point is FailurePoint.DEPENDENCY_TIMEOUT
                and self.dependency_failures_remaining > 0
            ):
                self.dependency_failures_remaining -= 1
                if attempts >= MAX_DEPENDENCY_ATTEMPTS:
                    raise DependencyTimeout
                continue
            graph.invoke(graph_input, config)
            return

    def _durable_state(self, actor: ActorContext, operation: OperationRef) -> AgentState:
        saver = self._saver(actor)
        stored = saver.get_tuple(self._config(operation))
        if stored is None:
            raise InvalidState
        return agent_state_from_checkpoint(stored.checkpoint)

    def _finalize(
        self, actor: ActorContext, operation: OperationRef, final_state: AgentState
    ) -> RuntimeResult:
        """Emit the message, terminal lifecycle and terminal stream event exactly once."""
        reply = final_state.messages[-1] if final_state.messages else None
        if reply is not None and reply.role is MessageRole.ASSISTANT:
            model_response = self.model.respond(
                ModelRequest(
                    operation_id=operation.operation_id,
                    route=final_state.route or AgentRoute.CLARIFY,
                    messages=final_state.messages[:-1],
                )
            )
            for index, delta in enumerate(model_response.deltas):
                self._emit(
                    actor,
                    operation.operation_id,
                    StreamEventType.MESSAGE_DELTA,
                    MessageDeltaData(message_id=reply.message_id, index=index, text=delta),
                )
            self._emit(
                actor,
                operation.operation_id,
                StreamEventType.MESSAGE_COMPLETED,
                MessageCompletedData(message_id=reply.message_id, text=reply.content),
            )

        terminal_state = final_state.status
        updated = self.operations.transition(
            actor=actor,
            operation_id=operation.operation_id,
            target=terminal_state,
            now=self.clock(),
            route=final_state.route,
            error_code=final_state.error,
            checkpoint_seq=final_state.checkpoint_seq,
        )
        self._emit(
            actor,
            operation.operation_id,
            StreamEventType.OPERATION_STATE_CHANGED,
            StateChangedData(
                state=terminal_state,
                reason_code=(
                    ReasonCode.RUNTIME_ERROR if final_state.error else ReasonCode.COMPLETED
                ),
            ),
        )
        if final_state.error is not None:
            self._emit(
                actor,
                operation.operation_id,
                StreamEventType.OPERATION_FAILED,
                OperationFailedData(error_code=final_state.error),
            )

        if self.failure_point is FailurePoint.AFTER_TERMINAL_BEFORE_RESPONSE:
            raise InjectedCrash(FailurePoint.AFTER_TERMINAL_BEFORE_RESPONSE)

        self._emit(
            actor,
            operation.operation_id,
            StreamEventType.STREAM_COMPLETED,
            StreamCompletedData(final_state=terminal_state),
        )
        return RuntimeResult(
            operation=updated,
            state=final_state,
            events=tuple(self.events.read(actor=actor, operation_id=operation.operation_id)),
            resumed=False,
        )

    def close_stream(self, *, actor: ActorContext, operation: OperationRef) -> StreamEvent:
        """Append the terminal stream event, converging if it already exists."""
        return self._emit(
            actor,
            operation.operation_id,
            StreamEventType.STREAM_COMPLETED,
            StreamCompletedData(final_state=operation.state),
        )

    def durable_checkpoint_seq(self, *, actor: ActorContext, operation: OperationRef) -> int | None:
        return latest_checkpoint_seq(self.sessions, actor, operation.thread_id)


def actor_correlation(operation: OperationRef) -> UUID:
    """Correlation identity travels with the operation, not with a request header."""
    return operation.operation_id


__all__ = [
    "MAX_DEPENDENCY_ATTEMPTS",
    "AgentRuntime",
    "CheckpointConflict",
    "FailurePoint",
    "InjectedCrash",
    "RuntimeErrorCode",
    "RuntimeResult",
]
