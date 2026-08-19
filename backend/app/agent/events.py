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

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.agent.contracts import (
    EVENT_DATA_MODELS,
    TERMINAL_EVENT_TYPE,
    StreamEvent,
    StreamEventType,
    build_stream_event,
)
from app.agent.crypto import CheckpointCipherPort, SealedPayload, event_aad
from app.agent.errors import OperationNotFound
from app.agent.identity import derive_event_id
from app.contracts import ActorContext
from app.contracts.foundation import FrozenContract
from app.db import set_request_context

CONTRACT_VERSION = 1
SEQUENCE_RETRY_LIMIT = 3

_NEXT_SEQUENCE = text(
    """SELECT COALESCE(max(sequence), 0) + 1 FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id"""
)
_INSERT_EVENT = text(
    """INSERT INTO nexora_agent.agent_operation_events (
        id, tenant_id, actor_id, operation_id, sequence, type, key_id,
        data_nonce, data_ciphertext, contract_version, emitted_at, created_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :operation_id, :sequence, :type, :key_id,
        :data_nonce, :data_ciphertext, :contract_version, :emitted_at, :now
    )"""
)
_SELECT_EVENTS = text(
    """SELECT id, sequence, operation_id, type, key_id, data_nonce, data_ciphertext, emitted_at
    FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id
      AND sequence > COALESCE(CAST(:after_sequence AS bigint), 0)
    ORDER BY sequence"""
)
_SELECT_TERMINAL = text(
    """SELECT id, sequence, operation_id, type, key_id, data_nonce, data_ciphertext, emitted_at
    FROM nexora_agent.agent_operation_events
    WHERE operation_id = :operation_id AND type = :type"""
)
# Locking the parent operation both proves the caller owns it and serializes
# sequence allocation. An event log for one operation is totally ordered by
# definition, so serializing per operation is the semantics, not a compromise.
# Optimistic allocation was tried first and lost the race under ten concurrent
# writers, exhausting its retry budget.
_LOCK_OPERATION = text(
    "SELECT 1 FROM nexora_agent.agent_operations WHERE id = :operation_id FOR UPDATE"
)


@dataclass(slots=True)
class EventLedger:
    """Append-only, tenant/actor-scoped lifecycle events.

    Payloads are sealed before they reach PostgreSQL. `type`, `sequence` and
    `emitted_at` stay in the clear because ordering, the registered-type CHECK and
    the terminal-once index depend on them and none of them carries user content.
    The payload does carry message text, so leaving it as plaintext JSONB would
    have left readable at rest exactly the content `agent_checkpoints` encrypts.
    """

    sessions: sessionmaker[Session]
    cipher: CheckpointCipherPort

    def _seal(
        self, actor: ActorContext, operation_id: UUID, sequence: int, event_type: str, payload: str
    ) -> SealedPayload:
        return self.cipher.seal(
            payload.encode(),
            aad=event_aad(
                tenant_id=str(actor.tenant_id),
                actor_id=str(actor.actor_id),
                operation_id=str(operation_id),
                sequence=sequence,
                event_type=event_type,
            ),
        )

    def _to_event(self, actor: ActorContext, row: RowMapping) -> StreamEvent:
        plaintext = self.cipher.open(
            SealedPayload(
                key_id=str(row["key_id"]),
                nonce=bytes(row["data_nonce"]),
                ciphertext=bytes(row["data_ciphertext"]),
            ),
            aad=event_aad(
                tenant_id=str(actor.tenant_id),
                actor_id=str(actor.actor_id),
                operation_id=str(row["operation_id"]),
                sequence=int(str(row["sequence"])),
                event_type=str(row["type"]),
            ),
        )
        return StreamEvent.model_validate(
            {
                "event_id": row["id"],
                "sequence": row["sequence"],
                "operation_id": row["operation_id"],
                "type": row["type"],
                "data": json.loads(plaintext),
                "emitted_at": row["emitted_at"],
            }
        )

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
                            _LOCK_OPERATION, {"operation_id": operation_id}
                        ).scalar_one_or_none()
                        is None
                    ):
                        raise OperationNotFound
                    sequence = int(
                        session.execute(_NEXT_SEQUENCE, {"operation_id": operation_id}).scalar_one()
                    )
                    sealed = self._seal(actor, operation_id, sequence, event_type.value, payload)
                    session.execute(
                        _INSERT_EVENT,
                        {
                            "id": derive_event_id(operation_id, sequence),
                            "tenant_id": actor.tenant_id,
                            "actor_id": actor.actor_id,
                            "operation_id": operation_id,
                            "sequence": sequence,
                            "type": event_type.value,
                            "key_id": self.cipher.key_id,
                            "data_nonce": sealed.nonce,
                            "data_ciphertext": sealed.ciphertext,
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
                # With the operation row locked, the only remaining collision is the
                # terminal-once index, which is a convergence rather than an error.
                if event_type is TERMINAL_EVENT_TYPE:
                    existing = self.terminal_event(actor=actor, operation_id=operation_id)
                    if existing is not None:
                        return existing
                raise
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
        return [self._to_event(actor, row) for row in rows]

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
        return None if row is None else self._to_event(actor, row)
