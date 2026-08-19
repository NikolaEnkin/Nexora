"""Approver composition — the consequences `ADR-004` §Verification requires.

Every negative here asserts that no path is satisfied, which is the composition
layer's form of "the counter stays at zero". The durable counter itself is
asserted in the integration and security suites.
"""

from datetime import timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from app.approvals.composition import (
    PATH_1_OWNER,
    PATH_2_DEPUTY_OWN,
    PATH_3_DEPUTY_SMALL,
    PATH_4_TWO_OPERATORS,
    PATH_5_TWO_OPERATORS_DEPUTY,
    PATH_R2,
    ApproverDecision,
    ApproverRole,
    approval_ttl,
    is_at_or_above_threshold,
    open_paths,
    parse_roles,
    requester_kind,
    satisfied_path,
)
from app.policy.catalogue import CATALOGUE
from app.policy.contracts import Assurance, RiskLevel

OWNER_ID = UUID("30000000-0000-0000-0000-0000000000a1")
CFO_ID = UUID("30000000-0000-0000-0000-0000000000a2")
OPERATOR_1 = UUID("30000000-0000-0000-0000-0000000000a3")
OPERATOR_2 = UUID("30000000-0000-0000-0000-0000000000a4")
VIEWER_ID = UUID("30000000-0000-0000-0000-0000000000a5")
DEPUTY_ONLY = UUID("30000000-0000-0000-0000-0000000000a6")

OWNER_ROLES = frozenset({ApproverRole.OWNER})
# The CFO holds OPERATOR + DEPUTY; roles compose under ADR-002.
CFO_ROLES = frozenset({ApproverRole.OPERATOR, ApproverRole.DEPUTY})
OPERATOR_ROLES = frozenset({ApproverRole.OPERATOR})
VIEWER_ROLES = frozenset({ApproverRole.VIEWER})
DEPUTY_ROLES = frozenset({ApproverRole.DEPUTY})


def approve(
    actor_id: UUID, roles: frozenset[ApproverRole], *, step_up: bool = True
) -> ApproverDecision:
    return ApproverDecision(
        actor_id=actor_id,
        roles=roles,
        assurance=Assurance.STEP_UP if step_up else Assurance.STANDARD,
    )


def r3_paths(requester: ApproverRole, *, large: bool) -> tuple[object, ...]:
    return open_paths(risk=RiskLevel.R3, requester=requester, at_or_above_threshold=large)


# -- the five valid paths ------------------------------------------------


@pytest.mark.unit
def test_path_1_one_owner_satisfies_any_request_at_any_amount() -> None:
    for requester, large in (
        (ApproverRole.OPERATOR, False),
        (ApproverRole.OPERATOR, True),
        (ApproverRole.DEPUTY, True),
        (ApproverRole.OWNER, True),
    ):
        satisfied = satisfied_path(
            paths=r3_paths(requester, large=large),
            decisions=[approve(OWNER_ID, OWNER_ROLES)],
            requester_id=OPERATOR_1,
            risk=RiskLevel.R3,
        )
        assert satisfied is PATH_1_OWNER, (requester, large)


@pytest.mark.unit
def test_path_2_deputy_approves_their_own_request_at_any_amount() -> None:
    satisfied = satisfied_path(
        paths=r3_paths(ApproverRole.DEPUTY, large=True),
        decisions=[approve(CFO_ID, CFO_ROLES)],
        requester_id=CFO_ID,
        risk=RiskLevel.R3,
    )
    assert satisfied is PATH_2_DEPUTY_OWN


@pytest.mark.unit
def test_path_3_one_deputy_satisfies_a_small_operator_request() -> None:
    satisfied = satisfied_path(
        paths=r3_paths(ApproverRole.OPERATOR, large=False),
        decisions=[approve(CFO_ID, CFO_ROLES)],
        requester_id=OPERATOR_1,
        risk=RiskLevel.R3,
    )
    assert satisfied is PATH_3_DEPUTY_SMALL


@pytest.mark.unit
def test_path_4_two_operators_satisfy_a_small_operator_request() -> None:
    satisfied = satisfied_path(
        paths=r3_paths(ApproverRole.OPERATOR, large=False),
        decisions=[approve(OPERATOR_1, OPERATOR_ROLES), approve(OPERATOR_2, OPERATOR_ROLES)],
        requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
        risk=RiskLevel.R3,
    )
    assert satisfied is PATH_4_TWO_OPERATORS


@pytest.mark.unit
def test_path_5_two_operators_and_a_deputy_satisfy_a_large_operator_request() -> None:
    satisfied = satisfied_path(
        paths=r3_paths(ApproverRole.OPERATOR, large=True),
        decisions=[
            approve(OPERATOR_1, OPERATOR_ROLES),
            approve(OPERATOR_2, OPERATOR_ROLES),
            approve(DEPUTY_ONLY, DEPUTY_ROLES),
        ],
        requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
        risk=RiskLevel.R3,
    )
    assert satisfied is PATH_5_TWO_OPERATORS_DEPUTY


# -- compositions that are not in the table ------------------------------


@pytest.mark.unit
def test_one_operator_alone_satisfies_nothing() -> None:
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OPERATOR, large=False),
            decisions=[approve(OPERATOR_1, OPERATOR_ROLES)],
            requester_id=OPERATOR_2,
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
def test_two_operators_do_not_satisfy_a_large_request() -> None:
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OPERATOR, large=True),
            decisions=[approve(OPERATOR_1, OPERATOR_ROLES), approve(OPERATOR_2, OPERATOR_ROLES)],
            requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
def test_a_deputy_alone_does_not_satisfy_a_large_operator_request() -> None:
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OPERATOR, large=True),
            decisions=[approve(DEPUTY_ONLY, DEPUTY_ROLES)],
            requester_id=OPERATOR_1,
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
@pytest.mark.parametrize("risk", [RiskLevel.R2, RiskLevel.R3])
def test_a_viewer_decision_never_counts(risk: RiskLevel) -> None:
    paths = (PATH_R2,) if risk is RiskLevel.R2 else r3_paths(ApproverRole.OPERATOR, large=False)
    assert (
        satisfied_path(
            paths=paths,
            decisions=[approve(VIEWER_ID, VIEWER_ROLES)],
            requester_id=OPERATOR_1,
            risk=risk,
        )
        is None
    )


@pytest.mark.unit
def test_the_cfo_cannot_fill_two_slots_of_path_5() -> None:
    """One person, one slot. Counting roles instead of matching people would pass."""
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OPERATOR, large=True),
            decisions=[approve(CFO_ID, CFO_ROLES), approve(OPERATOR_1, OPERATOR_ROLES)],
            requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
def test_the_cfo_may_fill_exactly_one_slot_of_path_5() -> None:
    satisfied = satisfied_path(
        paths=r3_paths(ApproverRole.OPERATOR, large=True),
        decisions=[
            approve(CFO_ID, CFO_ROLES),
            approve(OPERATOR_1, OPERATOR_ROLES),
            approve(OPERATOR_2, OPERATOR_ROLES),
        ],
        requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
        risk=RiskLevel.R3,
    )
    assert satisfied is PATH_5_TWO_OPERATORS_DEPUTY


@pytest.mark.unit
def test_owner_cannot_substitute_for_an_operator_slot() -> None:
    """`ADR-004` §2: if a second OPERATOR is unavailable, path 4 is simply not open."""
    assert (
        satisfied_path(
            paths=(PATH_4_TWO_OPERATORS,),
            decisions=[approve(OWNER_ID, OWNER_ROLES), approve(OPERATOR_1, OPERATOR_ROLES)],
            requester_id=OPERATOR_2,
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
def test_owner_holding_operator_still_cannot_fill_an_operator_slot() -> None:
    dual = frozenset({ApproverRole.OWNER, ApproverRole.OPERATOR})
    assert (
        satisfied_path(
            paths=(PATH_4_TWO_OPERATORS,),
            decisions=[approve(OWNER_ID, dual), approve(OPERATOR_1, OPERATOR_ROLES)],
            requester_id=OPERATOR_2,
            risk=RiskLevel.R3,
        )
        is None
    )


# -- self-approval -------------------------------------------------------


@pytest.mark.unit
def test_owner_may_self_approve() -> None:
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OWNER, large=True),
            decisions=[approve(OWNER_ID, OWNER_ROLES)],
            requester_id=OWNER_ID,
            risk=RiskLevel.R3,
        )
        is PATH_1_OWNER
    )


@pytest.mark.unit
@pytest.mark.parametrize("risk", [RiskLevel.R2, RiskLevel.R3])
def test_operator_may_never_self_approve(risk: RiskLevel) -> None:
    paths = (PATH_R2,) if risk is RiskLevel.R2 else r3_paths(ApproverRole.OPERATOR, large=False)
    assert (
        satisfied_path(
            paths=paths,
            decisions=[approve(OPERATOR_1, OPERATOR_ROLES)],
            requester_id=OPERATOR_1,
            risk=risk,
        )
        is None
    )


@pytest.mark.unit
def test_deputy_alone_can_approve_r2() -> None:
    assert (
        satisfied_path(
            paths=(PATH_R2,),
            decisions=[approve(DEPUTY_ONLY, DEPUTY_ROLES, step_up=False)],
            requester_id=OPERATOR_1,
            risk=RiskLevel.R2,
        )
        is PATH_R2
    )


# -- step-up -------------------------------------------------------------


@pytest.mark.unit
def test_r3_refuses_any_approver_without_step_up() -> None:
    assert (
        satisfied_path(
            paths=r3_paths(ApproverRole.OPERATOR, large=True),
            decisions=[
                approve(OPERATOR_1, OPERATOR_ROLES),
                approve(OPERATOR_2, OPERATOR_ROLES, step_up=False),
                approve(DEPUTY_ONLY, DEPUTY_ROLES),
            ],
            requester_id=UUID("30000000-0000-0000-0000-0000000000ff"),
            risk=RiskLevel.R3,
        )
        is None
    )


@pytest.mark.unit
def test_r2_does_not_require_step_up() -> None:
    assert (
        satisfied_path(
            paths=(PATH_R2,),
            decisions=[approve(OPERATOR_1, OPERATOR_ROLES, step_up=False)],
            requester_id=OPERATOR_2,
            risk=RiskLevel.R2,
        )
        is PATH_R2
    )


# -- amount threshold ----------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("amount", "large"),
    [("9999.99", False), ("10000", True), ("10000.01", True), ("0", False)],
)
def test_both_sides_of_the_ten_thousand_comparison(amount: str, large: bool) -> None:
    entry = CATALOGUE["invoice_issue"]
    assert is_at_or_above_threshold(entry, {"amount": Decimal(amount)}) is large


@pytest.mark.unit
@pytest.mark.parametrize("arguments", [{}, {"amount": "not-a-number"}, {"amount": None}])
def test_an_unreadable_amount_fails_closed_to_the_larger_side(arguments: dict[str, object]) -> None:
    assert is_at_or_above_threshold(CATALOGUE["invoice_issue"], arguments) is True


# -- requester precedence and TTL ---------------------------------------


@pytest.mark.unit
def test_a_cfo_request_is_treated_as_a_deputy_request() -> None:
    assert requester_kind(CFO_ROLES) is ApproverRole.DEPUTY


@pytest.mark.unit
def test_unknown_role_names_are_ignored_rather_than_trusted() -> None:
    assert parse_roles(("OPERATOR", "SUPER_ADMIN", "")) == OPERATOR_ROLES


@pytest.mark.unit
@pytest.mark.parametrize(
    ("risk", "requester", "large", "expected"),
    [
        (RiskLevel.R2, ApproverRole.OPERATOR, False, timedelta(hours=1)),
        (RiskLevel.R3, ApproverRole.OWNER, True, timedelta(minutes=10)),
        (RiskLevel.R3, ApproverRole.DEPUTY, True, timedelta(minutes=10)),
        (RiskLevel.R3, ApproverRole.OPERATOR, False, timedelta(hours=1)),
        (RiskLevel.R3, ApproverRole.OPERATOR, True, timedelta(hours=2)),
    ],
)
def test_ttl_varies_with_the_required_decision_count(
    risk: RiskLevel, requester: ApproverRole, large: bool, expected: timedelta
) -> None:
    assert approval_ttl(risk=risk, requester=requester, at_or_above_threshold=large) == expected


@pytest.mark.unit
def test_r1_opens_no_approval_path() -> None:
    assert (
        open_paths(risk=RiskLevel.R1, requester=ApproverRole.OWNER, at_or_above_threshold=False)
        == ()
    )


@pytest.mark.unit
def test_a_roleless_requester_opens_no_r3_path() -> None:
    assert r3_paths(ApproverRole.VIEWER, large=False) == ()
    assert open_paths(risk=RiskLevel.R3, requester=None, at_or_above_threshold=False) == ()
