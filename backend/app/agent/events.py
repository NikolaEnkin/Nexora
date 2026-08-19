"""The durable lifecycle event ledger.

Events are persisted before any HTTP layer exists, because SSE `Last-Event-ID`
reconnect has to replay from durable storage rather than from a process's memory —
a reconnect after a restart must still work.

Three invariants are enforced by PostgreSQL rather than by this module alone
(`BR-02-003`, `BR-02-006`):

* `UNIQUE (operation_id, sequence)` makes the sequence monotonic and stable.
* A partial unique index on the terminal type makes `stream.completed` happen at
  most once per operation, even if two workers resume concurrently.
* A `CHECK` on `type` and an append-only trigger mean an unregistered event type
  cannot be stored and a stored event cannot later be rewritten.

Only this module writes events, and it only accepts a registered type with a
typed payload. Message content therefore has no path to becoming an event.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.agent.contracts import (
    EVENT_DATA_MODELS,
    TERMINAL_EVENT_TYPE,
    StreamEvent,
    StreamEventType,
    build_stream_event,
)
from app.agent.errors import OperationNotFound
from app.agent.identity import derive_event_id
from app.contracts import ActorContext
from app.contracts.foundation import FrozenContract
from app.db import set_request_context

CONTRACT_VERSION = 1
SEQUENCE_RETRY_LIMIT = 8

_NEXT_SEQUENCE = text(
    """SELECT COALESCE(max(sequence), 0) + 1 FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id"""
)
_INSERT_EVENT = text(
    """INSERT INTO nexora_agent.agent_operation_events (
        id, tenant_id, actor_id, operation_id, sequence, type, data,
        contract_version, emitted_at, created_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :operation_id, :sequence, :type, CAST(:data AS jsonb),
        :contract_version, :emitted_at, :now
    )"""
)
_SELECT_EVENTS = text(
    """SELECT id, sequence, operation_id, type, data, emitted_at
    FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id
      AND sequence > COALESCE(CAST(:after_sequence AS bigint), 0)
    ORDER BY sequence"""
)
_SELECT_TERMINAL = text(
    """SELECT id, sequence, operation_id, type, data, emitted_at
    FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id AND type = :type"""
)
_OPERATION_EXISTS = text("SELECT 1 FROM nexora_agent.agent_operations WHERE id = :operation_id")


def _to_event(row: dict[str, object]) -> StreamEvent:
    return StreamEvent.model_validate(
        {
            "event_id": row["id"],
            "sequence": row["sequence"],
            "operation_id": row["operation_id"],
            "type": row["type"],
            "data": row["data"],
            "emitted_at": row["emitted_at"],
        }
    )


@dataclass(slots=True)
class EventLedger:
    """Append-only, tenant/actor-scoped lifecycle events."""

    sessions: sessionmaker[Session]

    def append(
        self,
        *,
        actor: ActorContext,
        operation_id: UUID,
        event_type: StreamEventType,
        data: FrozenContract,
        now: datetime,
    ) -> StreamEvent:
        """Append one registered event and return it.

        Appending the terminal event twice is a durable no-op that returns the
        first one, so a concurrent resume converges instead of failing.
        """
        expected = EVENT_DATA_MODELS[event_type]
        if not isinstance(data, expected):
            raise TypeError(f"{event_type} requires {expected.__name__}")
        payload = data.model_dump_json()

        for _attempt in range(SEQUENCE_RETRY_LIMIT):
            try:
                with self.sessions() as session, session.begin():
                    set_request_context(session, actor.tenant_id, actor.actor_id)
                    if (
                        session.execute(
                            _OPERATION_EXISTS, {"operation_id": operation_id}
                        ).scalar_one_or_none()
                        is None
                    ):
                        raise OperationNotFound
                    sequence = int(
                        session.execute(_NEXT_SEQUENCE, {"operation_id": operation_id}).scalar_one()
                    )
                    session.execute(
                        _INSERT_EVENT,
                        {
                            "id": derive_event_id(operation_id, sequence),
                            "tenant_id": actor.tenant_id,
                            "actor_id": actor.actor_id,
                            "operation_id": operation_id,
                            "sequence": sequence,
                            "type": event_type.value,
                            "data": payload,
                            "contract_version": CONTRACT_VERSION,
                            "emitted_at": now,
                            "now": now,
                        },
                    )
                return build_stream_event(
                    operation_id=operation_id,
                    sequence=sequence,
                    event_type=event_type,
                    data=data,
                    emitted_at=now,
                )
            except IntegrityError:
                if event_type is TERMINAL_EVENT_TYPE:
                    existing = self.terminal_event(actor=actor, operation_id=operation_id)
                    if existing is not None:
                        return existing
                    raise
                # A concurrent writer took this sequence; recompute and retry.
                continue
        raise RuntimeError("could not allocate a durable event sequence")

    def read(
        self,
        *,
        actor: ActorContext,
        operation_id: UUID,
        after_sequence: int | None = None,
    ) -> list[StreamEvent]:
        """Events after `after_sequence`, in order. This is the SSE replay source."""
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            rows = (
                session.execute(
                    _SELECT_EVENTS,
                    {"operation_id": operation_id, "after_sequence": after_sequence},
                )
                .mappings()
                .all()
            )
        return [_to_event(dict(row)) for row in rows]

    def terminal_event(self, *, actor: ActorContext, operation_id: UUID) -> StreamEvent | None:
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            row = (
                session.execute(
                    _SELECT_TERMINAL,
                    {"operation_id": operation_id, "type": TERMINAL_EVENT_TYPE.value},
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _to_event(dict(row))
