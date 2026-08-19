"""Operation identity, ownership and lifecycle persistence.

`BR-02-001`: identical `(tenant_id, actor_id, client_request_id)` resolves to one
operation. The arbiter is a database unique constraint, not an application check,
so ten concurrent identical starts converge on one row rather than racing.

`BR-02-002`: loading an operation requires tenant *and* actor ownership. Row-level
security already refuses foreign rows, and this module additionally reports the
same `OPERATION_NOT_FOUND` for an absent operation and an unauthorized one, so a
guessed identifier discloses nothing.

The `ON CONFLICT` clause below carries no column target deliberately. `operation_id`
is derived from the same three values as the scoped unique constraint, so both
indexes collide together; naming only one as arbiter would leave the other
unhandled, which is precisely the Phase-01 defect this phase fixed in
`app.events.service` (finding F-01).

Every statement is a literal string with bound parameters. Nothing here composes
SQL from a variable, including from module constants.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session, sessionmaker

from app.agent.contracts import OperationRef
from app.agent.errors import InvalidState, OperationNotFound, RuntimeErrorCode
from app.agent.identity import derive_conversation_id, derive_operation_id, derive_thread_id
from app.agent.state import (
    STATE_SCHEMA_VERSION,
    TERMINAL_STATES,
    AgentRoute,
    OperationState,
    is_allowed_transition,
)
from app.contracts import ActorContext
from app.db import set_request_context

CONTRACT_VERSION = 1

_SELECT_BY_ID = text(
    """SELECT id, tenant_id, actor_id, conversation_id, thread_id, state, route,
              checkpoint_seq, error_code
    FROM nexora_agent.agent_operations WHERE id = :id"""
)
_SELECT_BY_ID_FOR_UPDATE = text(
    """SELECT id, tenant_id, actor_id, conversation_id, thread_id, state, route,
              checkpoint_seq, error_code
    FROM nexora_agent.agent_operations WHERE id = :id FOR UPDATE"""
)
_SELECT_BY_REQUEST = text(
    """SELECT id, tenant_id, actor_id, conversation_id, thread_id, state, route,
              checkpoint_seq, error_code
    FROM nexora_agent.agent_operations
    WHERE tenant_id = :tenant_id AND actor_id = :actor_id
      AND client_request_id = :client_request_id"""
)
_INSERT_OPERATION = text(
    """INSERT INTO nexora_agent.agent_operations (
        id, tenant_id, actor_id, conversation_id, client_request_id, thread_id,
        state, route, contract_version, state_schema_version, checkpoint_seq,
        error_code, correlation_id, terminal_at, created_at, updated_at
    ) VALUES (
        :id, :tenant_id, :actor_id, :conversation_id, :client_request_id, :thread_id,
        'RECEIVED', NULL, :contract_version, :state_schema_version, 0,
        NULL, :correlation_id, NULL, :now, :now
    ) ON CONFLICT DO NOTHING
    RETURNING id, tenant_id, actor_id, conversation_id, thread_id, state, route,
              checkpoint_seq, error_code"""
)
_UPDATE_STATE = text(
    """UPDATE nexora_agent.agent_operations
    SET state = :state,
        route = COALESCE(:route, route),
        error_code = :error_code,
        checkpoint_seq = :checkpoint_seq,
        terminal_at = CASE WHEN :is_terminal THEN :now ELSE terminal_at END,
        updated_at = :now
    WHERE id = :id
    RETURNING id, tenant_id, actor_id, conversation_id, thread_id, state, route,
              checkpoint_seq, error_code"""
)
_COUNT_ACTIVE = text(
    """SELECT count(*) FROM nexora_agent.agent_operations
    WHERE state IN ('RECEIVED', 'RUNNING', 'WAITING')"""
)


@dataclass(frozen=True, slots=True)
class OperationCreation:
    """The resolved operation plus whether this caller created it."""

    operation: OperationRef
    created: bool


def _to_ref(row: RowMapping) -> OperationRef:
    route = row["route"]
    error_code = row["error_code"]
    return OperationRef(
        operation_id=row["id"],
        tenant_id=row["tenant_id"],
        actor_id=row["actor_id"],
        conversation_id=row["conversation_id"],
        thread_id=row["thread_id"],
        state=OperationState(row["state"]),
        route=None if route is None else AgentRoute(route),
        checkpoint_seq=row["checkpoint_seq"],
        error_code=None if error_code is None else RuntimeErrorCode(error_code),
    )


@dataclass(slots=True)
class OperationRepository:
    """All reads and writes run inside a signed tenant/actor transaction context."""

    sessions: sessionmaker[Session]

    def create_or_restore(
        self,
        *,
        actor: ActorContext,
        client_request_id: str,
        conversation_id: UUID | None,
        now: datetime,
    ) -> OperationCreation:
        """Return the single operation for this request identity.

        A retry of the exact same request returns the existing operation untouched:
        it never resets lifecycle state and never produces a second terminal result.
        """
        resolved_conversation = conversation_id or derive_conversation_id(
            actor.tenant_id, actor.actor_id, client_request_id
        )
        operation_id = derive_operation_id(actor.tenant_id, actor.actor_id, client_request_id)

        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            inserted = (
                session.execute(
                    _INSERT_OPERATION,
                    {
                        "id": operation_id,
                        "tenant_id": actor.tenant_id,
                        "actor_id": actor.actor_id,
                        "conversation_id": resolved_conversation,
                        "client_request_id": client_request_id,
                        "thread_id": derive_thread_id(actor.tenant_id, resolved_conversation),
                        "contract_version": CONTRACT_VERSION,
                        "state_schema_version": STATE_SCHEMA_VERSION,
                        "correlation_id": actor.correlation_id,
                        "now": now,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if inserted is not None:
                return OperationCreation(operation=_to_ref(inserted), created=True)

            existing = (
                session.execute(
                    _SELECT_BY_REQUEST,
                    {
                        "tenant_id": actor.tenant_id,
                        "actor_id": actor.actor_id,
                        "client_request_id": client_request_id,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if existing is None:
                # A row blocked the insert but this actor cannot see it, so it is
                # not theirs. Report the same not-found as for an absent operation.
                raise OperationNotFound
            return OperationCreation(operation=_to_ref(existing), created=False)

    def load(self, *, actor: ActorContext, operation_id: UUID) -> OperationRef:
        """Reauthorize ownership on every load.

        Absent and unauthorized are indistinguishable by design: both raise
        `OPERATION_NOT_FOUND` with no details, so probing reveals no existence.
        """
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            row = session.execute(_SELECT_BY_ID, {"id": operation_id}).mappings().one_or_none()
        if row is None:
            raise OperationNotFound
        return _to_ref(row)

    def transition(
        self,
        *,
        actor: ActorContext,
        operation_id: UUID,
        target: OperationState,
        now: datetime,
        route: AgentRoute | None = None,
        error_code: RuntimeErrorCode | None = None,
        checkpoint_seq: int | None = None,
    ) -> OperationRef:
        """Advance lifecycle under row-level locking.

        The database enforces the same rules independently, so a defect here still
        cannot reactivate a terminal operation or rewind a checkpoint sequence.
        """
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            current = (
                session.execute(_SELECT_BY_ID_FOR_UPDATE, {"id": operation_id})
                .mappings()
                .one_or_none()
            )
            if current is None:
                raise OperationNotFound

            present = OperationState(current["state"])
            if present is target:
                return _to_ref(current)
            if not is_allowed_transition(present, target):
                raise InvalidState

            next_seq = current["checkpoint_seq"]
            if checkpoint_seq is not None:
                if checkpoint_seq < next_seq:
                    raise InvalidState
                next_seq = checkpoint_seq

            updated = (
                session.execute(
                    _UPDATE_STATE,
                    {
                        "id": operation_id,
                        "state": target.value,
                        "route": None if route is None else route.value,
                        "error_code": None if error_code is None else error_code.value,
                        "checkpoint_seq": next_seq,
                        "is_terminal": target in TERMINAL_STATES,
                        "now": now,
                    },
                )
                .mappings()
                .one()
            )
            return _to_ref(updated)

    def active_count(self, *, actor: ActorContext) -> int:
        """Per-actor concurrency bound input (packet §12).

        Row-level security scopes this to the calling actor, so it cannot be used
        to observe another tenant's load.
        """
        with self.sessions() as session, session.begin():
            set_request_context(session, actor.tenant_id, actor.actor_id)
            return int(session.execute(_COUNT_ACTIVE).scalar_one())
