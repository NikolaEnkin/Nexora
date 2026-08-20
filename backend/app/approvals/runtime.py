"""The runtime interrupt adapter — packet §7 and §8.

This adapter and the approval service are the *only* producers of the approval
lifecycle signal. That is the whole `ARCH-017` property: a client observing a
`WAITING` state with reason `APPROVAL_REQUIRED` knows a deterministic service put
it there, because there is no other code path that can emit it and no field in
`StateChangedData` for message text to occupy.

Phase 08 maps these values to `RobotVisualState v1`. Nothing here anticipates that
mapping: no animation name, asset, duration, colour or navigation target exists in
this module, and none may be added to it.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.agent.contracts import StateChangedData, StreamEvent, StreamEventType
from app.agent.errors import InvalidState, OperationNotFound
from app.agent.events import EventLedger
from app.agent.operations import OperationRepository
from app.agent.state import OperationState, ReasonCode
from app.contracts import ActorContext


@dataclass(slots=True)
class ApprovalRuntimeSignal:
    """Bridges an approval interrupt onto the Phase-02 lifecycle."""

    operations: OperationRepository
    events: EventLedger

    def signal_waiting(
        self, *, actor: ActorContext, operation_id: UUID, now: datetime
    ) -> StreamEvent | None:
        """Durable `APPROVAL_REQUIRED` becomes the registered `WAITING` transition.

        Idempotent: an operation already `WAITING` is left alone and no second
        transition event is appended, so a replayed interrupt cannot produce a
        duplicate wait (`BR-03-007`).
        """
        return self._transition(
            actor=actor,
            operation_id=operation_id,
            target=OperationState.WAITING,
            reason=ReasonCode.APPROVAL_REQUIRED,
            now=now,
        )

    def signal_resumed(
        self, *, actor: ActorContext, operation_id: UUID, now: datetime
    ) -> StreamEvent | None:
        """Authorized exact resume emits `RUNNING`."""
        return self._transition(
            actor=actor,
            operation_id=operation_id,
            target=OperationState.RUNNING,
            reason=ReasonCode.APPROVAL_GRANTED,
            now=now,
        )

    def signal_terminal(
        self,
        *,
        actor: ActorContext,
        operation_id: UUID,
        reason: ReasonCode,
        now: datetime,
    ) -> StreamEvent | None:
        """Rejection, expiry and cancellation use registered terminal semantics."""
        return self._transition(
            actor=actor,
            operation_id=operation_id,
            target=OperationState.CANCELLED,
            reason=reason,
            now=now,
        )

    def _transition(
        self,
        *,
        actor: ActorContext,
        operation_id: UUID,
        target: OperationState,
        reason: ReasonCode,
        now: datetime,
    ) -> StreamEvent | None:
        try:
            current = self.operations.load(actor=actor, operation_id=operation_id)
        except OperationNotFound:
            return None
        if current.state is target:
            return None
        try:
            self.operations.transition(
                actor=actor, operation_id=operation_id, target=target, now=now
            )
        except InvalidState:
            # A terminal operation is never reactivated by an approval decision.
            return None
        return self.events.append(
            actor=actor,
            operation_id=operation_id,
            event_type=StreamEventType.OPERATION_STATE_CHANGED,
            data=StateChangedData(state=target, reason_code=reason),
            now=now,
        )
