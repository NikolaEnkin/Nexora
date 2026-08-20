"""Approver composition — `ADR-004` §2.

`ADR-004` replaced a general quorum engine with a fixed set of enumerated paths.
That is the whole security property of this module: the set below is closed, so a
composition that is not listed executes nothing. There is no rule that computes a
threshold from team size, and no configuration that can widen it.

Two subtleties are worth stating, because both are ways a naive implementation
would silently weaken the control.

**Slot filling is a matching problem, not a count.** The CFO holds `OPERATOR` and
`DEPUTY`, so counting "two operator decisions and one deputy decision" against a
multiset of roles would let one person satisfy two slots of path 5. Each decision
therefore fills exactly one slot, and the assignment is searched exhaustively —
at most three slots, so exhaustive is cheap and obviously correct.

**Self-approval is asymmetric.** `OWNER` and `DEPUTY` may approve their own
requests; `OPERATOR` may never, at R2 or R3. `ADR-004` derives this rather than
stating it: without it an `OPERATOR` could satisfy R2 alone, which would make R2
no control at all for eight of ten people.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from app.policy.catalogue import (
    AMOUNT_THRESHOLD,
    COLLECTION_TTL_R2,
    COLLECTION_TTL_R3_SELF_APPROVABLE,
    COLLECTION_TTL_R3_SINGLE_OR_PAIR,
    COLLECTION_TTL_R3_THREE_PARTY,
    EXECUTION_TTL_R2,
    EXECUTION_TTL_R3,
    CatalogueEntry,
)
from app.policy.contracts import Assurance, RiskLevel


class ApproverRole(StrEnum):
    """Tenant roles relevant to approval. `VIEWER` appears in no slot by design."""

    OWNER = "OWNER"
    OPERATOR = "OPERATOR"
    DEPUTY = "DEPUTY"
    VIEWER = "VIEWER"


# Precedence for "whose request is this". The CFO holds OPERATOR and DEPUTY, and
# `ADR-004` path 2 treats their request as a DEPUTY's own request.
_REQUESTER_PRECEDENCE: Final = (ApproverRole.OWNER, ApproverRole.DEPUTY, ApproverRole.OPERATOR)

R2_PATH_ID: Final = 0


@dataclass(frozen=True, slots=True)
class ApprovalPath:
    """One valid composition. `slots` are unordered; order never matters."""

    path_id: int
    slots: tuple[frozenset[ApproverRole], ...]

    @property
    def required_decisions(self) -> int:
        return len(self.slots)


_OWNER_SLOT: Final = frozenset({ApproverRole.OWNER})
_DEPUTY_SLOT: Final = frozenset({ApproverRole.DEPUTY})
_OPERATOR_SLOT: Final = frozenset({ApproverRole.OPERATOR})
_ANY_APPROVER_SLOT: Final = frozenset(
    {ApproverRole.OWNER, ApproverRole.OPERATOR, ApproverRole.DEPUTY}
)

# `ADR-004` §1: R2 requires one decision from OWNER, OPERATOR or DEPUTY.
PATH_R2: Final = ApprovalPath(path_id=R2_PATH_ID, slots=(_ANY_APPROVER_SLOT,))

# `ADR-004` §2, verbatim. These are the only valid R3 compositions.
PATH_1_OWNER: Final = ApprovalPath(path_id=1, slots=(_OWNER_SLOT,))
PATH_2_DEPUTY_OWN: Final = ApprovalPath(path_id=2, slots=(_DEPUTY_SLOT,))
PATH_3_DEPUTY_SMALL: Final = ApprovalPath(path_id=3, slots=(_DEPUTY_SLOT,))
PATH_4_TWO_OPERATORS: Final = ApprovalPath(path_id=4, slots=(_OPERATOR_SLOT, _OPERATOR_SLOT))
PATH_5_TWO_OPERATORS_DEPUTY: Final = ApprovalPath(
    path_id=5, slots=(_OPERATOR_SLOT, _OPERATOR_SLOT, _DEPUTY_SLOT)
)


@dataclass(frozen=True, slots=True)
class ApproverDecision:
    """One recorded approval decision, as the composition evaluator sees it."""

    actor_id: UUID
    roles: frozenset[ApproverRole]
    assurance: Assurance


class AmountUndeterminable(ValueError):
    """The declared amount argument is missing or not canonically comparable."""


def requester_kind(roles: frozenset[ApproverRole]) -> ApproverRole | None:
    """The role that decides which paths open for this requester."""
    for role in _REQUESTER_PRECEDENCE:
        if role in roles:
            return role
    return None


def read_amount(entry: CatalogueEntry, normalized_arguments: dict[str, Any]) -> Decimal:
    """Read the declared amount argument.

    Phase 03 does not decide what the amount *means* — net or gross, which
    currency, how a non-EUR document converts. That is HD-004, and `ADR-004`
    explicitly forbids this phase from inventing it. This reads the field the
    catalogue declares and compares it.
    """
    if entry.amount_field is None:
        raise AmountUndeterminable("action declares no amount field")
    raw = normalized_arguments.get(entry.amount_field)
    if raw is None:
        raise AmountUndeterminable("declared amount argument is absent")
    try:
        return Decimal(str(raw))
    except (InvalidOperation, ValueError) as error:
        raise AmountUndeterminable("declared amount argument is not a decimal") from error


def is_at_or_above_threshold(entry: CatalogueEntry, normalized_arguments: dict[str, Any]) -> bool:
    """Fail closed: an unreadable amount is treated as the larger side.

    An absent or malformed amount must not open the cheaper path. Treating it as
    `>= threshold` means the request needs the three-party composition, which is
    the safe direction to be wrong in.
    """
    try:
        return read_amount(entry, normalized_arguments) >= AMOUNT_THRESHOLD
    except AmountUndeterminable:
        return True


def open_paths(
    *,
    risk: RiskLevel,
    requester: ApproverRole | None,
    at_or_above_threshold: bool,
) -> tuple[ApprovalPath, ...]:
    """Every composition that may satisfy this request. Closed set."""
    if risk is RiskLevel.R1:
        return ()
    if risk is RiskLevel.R2:
        return (PATH_R2,)
    # R3. Path 1 is always open: an OWNER approval is final at any amount and for
    # any requester.
    if requester is ApproverRole.OWNER:
        return (PATH_1_OWNER,)
    if requester is ApproverRole.DEPUTY:
        return (PATH_1_OWNER, PATH_2_DEPUTY_OWN)
    if requester is ApproverRole.OPERATOR:
        if at_or_above_threshold:
            return (PATH_1_OWNER, PATH_5_TWO_OPERATORS_DEPUTY)
        return (PATH_1_OWNER, PATH_3_DEPUTY_SMALL, PATH_4_TWO_OPERATORS)
    # A VIEWER or role-less requester opens no path. Authorization will already
    # have denied them; returning nothing keeps this fail-closed independently.
    return ()


def collection_ttl(
    *,
    risk: RiskLevel,
    requester: ApproverRole | None,
    at_or_above_threshold: bool,
) -> timedelta:
    """How long the required humans have to decide — `ADR-004` §3 as amended.

    Fixed when the request is created, so it is derived from what determines the
    open path set: the requester's authority and the amount. Nothing can execute
    during this window, so its length costs patience rather than exposure.

    A self-approvable request gets the short window because the person who may
    approve it is already at the keyboard. The three-party case gets a working
    day, because the superseded two-hour window reliably expired *after two of
    three people had already approved* — discarding human decisions already given.
    """
    if risk is RiskLevel.R2:
        return COLLECTION_TTL_R2
    if requester in (ApproverRole.OWNER, ApproverRole.DEPUTY):
        return COLLECTION_TTL_R3_SELF_APPROVABLE
    if at_or_above_threshold:
        return COLLECTION_TTL_R3_THREE_PARTY
    return COLLECTION_TTL_R3_SINGLE_OR_PAIR


def execution_ttl(risk: RiskLevel) -> timedelta:
    """How long a fully approved action stays usable — `ADR-004` §3 as amended.

    Uniform per risk level and independent of amount and path. This is the whole
    exposure window, so neither a larger amount nor a longer collection widens it:
    collecting three signatures buys time to decide, never time to stay loaded.
    """
    return EXECUTION_TTL_R3 if risk is RiskLevel.R3 else EXECUTION_TTL_R2


def _qualifies(decision: ApproverDecision, slot: frozenset[ApproverRole]) -> bool:
    """Whether one decision may fill one slot.

    The `OWNER` clause implements "`OWNER` cannot occupy an `OPERATOR` slot"
    strictly: an actor holding `OWNER` is excluded from any slot that does not
    itself accept `OWNER`, even when they also hold `OPERATOR`.
    """
    if ApproverRole.OWNER in decision.roles and ApproverRole.OWNER not in slot:
        return False
    return bool(decision.roles & slot)


def _can_fill(
    slots: Sequence[frozenset[ApproverRole]], decisions: Sequence[ApproverDecision]
) -> bool:
    """Exhaustive bipartite matching over at most three slots."""
    if not slots:
        return True
    head, rest = slots[0], slots[1:]
    for index, decision in enumerate(decisions):
        if _qualifies(decision, head):
            remaining = [*decisions[:index], *decisions[index + 1 :]]
            if _can_fill(rest, remaining):
                return True
    return False


def satisfied_path(
    *,
    paths: Sequence[ApprovalPath],
    decisions: Sequence[ApproverDecision],
    requester_id: UUID,
    risk: RiskLevel,
) -> ApprovalPath | None:
    """The path these decisions satisfy, or `None`.

    `None` means the request stays `PENDING` and its effect counter stays at
    zero — a partial composition executes nothing.
    """
    usable = [
        decision
        for decision in decisions
        if _decision_is_usable(decision, requester_id=requester_id, risk=risk)
    ]
    if not usable:
        return None
    # Distinct actors: one decision per actor is enforced by the database, and
    # this guards the invariant independently of that constraint.
    if len({decision.actor_id for decision in usable}) != len(usable):
        return None
    for path in paths:
        if len(usable) >= path.required_decisions and _can_fill(list(path.slots), usable):
            return path
    return None


def _decision_is_usable(decision: ApproverDecision, *, requester_id: UUID, risk: RiskLevel) -> bool:
    """Filter decisions that can never count, before any matching runs."""
    # `ADR-004` §4: every R3 approver needs step-up, in every slot.
    if risk is RiskLevel.R3 and decision.assurance is not Assurance.STEP_UP:
        return False
    if decision.actor_id == requester_id:
        # OWNER and DEPUTY may self-approve; OPERATOR may never, at R2 or R3.
        if not (decision.roles & {ApproverRole.OWNER, ApproverRole.DEPUTY}):
            return False
    return True


def parse_roles(roles: tuple[str, ...]) -> frozenset[ApproverRole]:
    """Map trusted `ActorContext.roles` onto approval roles, ignoring unknowns."""
    known = set()
    for role in roles:
        try:
            known.add(ApproverRole(role))
        except ValueError:
            continue
    return frozenset(known)
