"""Composition root for the agent runtime.

Kept separate from `app.main` so a test can build exactly the same object graph
the application uses, with only the clock and the model swapped for fixed ones.

Graph execution runs on a worker thread. LangGraph is driven synchronously here,
and `POST /chat` must return `202` immediately rather than blocking until the
operation reaches a terminal state.
"""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.agent.crypto import AesGcmCheckpointCipher, CheckpointCipherPort
from app.agent.events import EventLedger
from app.agent.model import DeterministicModelAdapter, ModelPort
from app.agent.operations import OperationRepository
from app.agent.runtime import AgentRuntime
from app.api.chat import ChatDependencies
from app.config import Settings
from app.contracts import ActorContext
from app.db import build_engine, build_session_factory
from app.observability.ports import TracePort
from app.observability.trace import DeterministicTraceSink

WORKER_THREADS = 4


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class RuntimeScheduler:
    """Runs operations off the request thread.

    Failures are swallowed *here* on purpose: the operation's durable state and
    its event ledger are the record of what happened, and a background exception
    must not take down the HTTP worker. The client observes the outcome through
    the stream, not through this call.
    """

    runtime: AgentRuntime
    executor: ThreadPoolExecutor
    _pending: list[Future[None]] = field(default_factory=list, init=False)

    def schedule(self, actor: ActorContext, operation_id: UUID, message: str) -> None:
        self._pending.append(self.executor.submit(self._run, actor, operation_id, message))

    def _run(self, actor: ActorContext, operation_id: UUID, message: str) -> None:
        logger = structlog.get_logger("agent-scheduler")
        try:
            operation = self.runtime.operations.load(actor=actor, operation_id=operation_id)
            self.runtime.execute(actor=actor, operation=operation, message=message)
        except Exception:
            # Identifiers only. The message and any state stay out of the log.
            logger.warning(
                "agent_operation_failed",
                operation_id=str(operation_id),
                correlation_id=str(actor.correlation_id),
                outcome="FAILED",
            )

    def wait(self, timeout: float = 30.0) -> None:
        """Block until scheduled work settles. Used by tests, not by request paths."""
        for pending in list(self._pending):
            pending.result(timeout=timeout)
        self._pending.clear()

    def shutdown(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=False)


@dataclass(frozen=True, slots=True)
class AgentComposition:
    """The assembled runtime, exposed so tests can reach each part."""

    sessions: sessionmaker[Session]
    operations: OperationRepository
    events: EventLedger
    runtime: AgentRuntime
    scheduler: RuntimeScheduler
    trace: DeterministicTraceSink
    dependencies: ChatDependencies


def build_agent_composition(
    settings: Settings,
    *,
    clock: Callable[[], datetime] = utc_now,
    model: ModelPort | None = None,
    cipher: CheckpointCipherPort | None = None,
    sessions: sessionmaker[Session] | None = None,
) -> AgentComposition:
    """Assemble the runtime from configuration."""
    session_factory = sessions or build_session_factory(build_engine(settings.database_url))
    operations = OperationRepository(sessions=session_factory)
    events = EventLedger(sessions=session_factory)
    trace = DeterministicTraceSink(
        secret_values=(
            settings.session_hash_pepper.get_secret_value(),
            settings.rls_context_secret.get_secret_value(),
            settings.checkpoint_encryption_key.get_secret_value(),
            settings.database_url,
            settings.redis_url,
        )
    )
    runtime = AgentRuntime(
        sessions=session_factory,
        operations=operations,
        events=events,
        model=model or DeterministicModelAdapter(settings),
        cipher=cipher or AesGcmCheckpointCipher.from_settings(settings),
        clock=clock,
    )
    scheduler = RuntimeScheduler(
        runtime=runtime,
        executor=ThreadPoolExecutor(max_workers=WORKER_THREADS, thread_name_prefix="agent"),
    )
    dependencies = ChatDependencies(
        operations=operations,
        events=events,
        trace=trace,
        clock=clock,
        schedule=scheduler.schedule,
    )
    return AgentComposition(
        sessions=session_factory,
        operations=operations,
        events=events,
        runtime=runtime,
        scheduler=scheduler,
        trace=trace,
        dependencies=dependencies,
    )


def trace_port(composition: AgentComposition) -> TracePort:
    return composition.trace
