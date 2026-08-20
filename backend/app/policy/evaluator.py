"""Deterministic policy evaluation — `ARCH-006`.

Order is the security property. Authorization runs *before* policy, so a
`PolicyDecision` of `APPROVAL_REQUIRED` is never reachable by an actor who lacks
the permission: an unauthorized actor is denied at step 2 and never obtains an
approval request they could later have signed. That is what "approval cannot
grant a missing permission" means operationally — not that approval is checked
and then permission is checked, but that permission is checked first and the
approval path is never entered without it.

Nothing in this module reads message text, model output or retrieved content.
The only inputs are the trusted `ActorContext`, the caller-supplied descriptor of
what is being attempted, and the versioned catalogue.
"""

from uuid import UUID

from app.authz import authorize
from app.contracts import ActorContext
from app.contracts.foundation import AuthorizationEffect
from app.policy.canonical import NORMALIZATION_VERSION, payload_hash
from app.policy.catalogue import CATALOGUE_VERSION, CatalogueEntry, lookup
from app.policy.contracts import (
    POLICY_VERSION,
    ActionDescriptor,
    Assurance,
    PolicyDecision,
    PolicyEffect,
    PolicyReasonCode,
    RiskLevel,
)

_UNKNOWN_PERMISSION = "unclassified"


def _decision(
    *,
    effect: PolicyEffect,
    risk: RiskLevel,
    reason_code: PolicyReasonCode,
    required_permission: str,
    required_assurance: Assurance,
    hashed: str,
    approval_path_ids: tuple[int, ...] = (),
) -> PolicyDecision:
    return PolicyDecision(
        effect=effect,
        risk=risk,
        reason_code=reason_code,
        required_permission=required_permission,
        required_assurance=required_assurance,
        policy_version=POLICY_VERSION,
        catalogue_version=CATALOGUE_VERSION,
        normalization_version=NORMALIZATION_VERSION,
        payload_hash=hashed,
        approval_path_ids=approval_path_ids,
    )


def evaluate(
    *,
    actor: ActorContext,
    descriptor: ActionDescriptor,
    object_tenant_id: UUID,
) -> PolicyDecision:
    """Classify one attempted action for one trusted actor.

    `required_assurance` on an R3 decision describes what every *approver* must
    present (`ADR-004` §4). It is not a requirement on the requester: asking for a
    dangerous action is not itself the dangerous act, and requiring step-up to
    request would put an MFA prompt on the cheap half of the flow.
    """
    hashed = payload_hash(descriptor.normalized_arguments)
    entry = lookup(descriptor.action_type)

    # 1. Unclassified actions are denied, never guessed at.
    if entry is None:
        return _decision(
            effect=PolicyEffect.DENY,
            risk=RiskLevel.R3,
            reason_code=PolicyReasonCode.ACTION_UNKNOWN,
            required_permission=_UNKNOWN_PERMISSION,
            required_assurance=Assurance.STEP_UP,
            hashed=hashed,
        )

    # 2. Authorization precedes policy (`ARCH-006`).
    authorization = authorize(
        actor,
        entry.required_permission,
        object_tenant_id=object_tenant_id,
        object_scope=descriptor.target_type,
    )
    if authorization.effect is AuthorizationEffect.DENY:
        return _decision(
            effect=PolicyEffect.DENY,
            risk=entry.risk,
            reason_code=(
                PolicyReasonCode.PERMISSION_MISSING
                if authorization.reason_code == "PERMISSION_MISSING"
                else PolicyReasonCode.AUTHORIZATION_DENIED
            ),
            required_permission=entry.required_permission,
            required_assurance=entry.required_assurance,
            hashed=hashed,
        )

    # 3. Risk decides whether a human must look at it first.
    if entry.risk is RiskLevel.R1:
        return _decision(
            effect=PolicyEffect.ALLOW,
            risk=entry.risk,
            reason_code=PolicyReasonCode.ALLOWED,
            required_permission=entry.required_permission,
            required_assurance=entry.required_assurance,
            hashed=hashed,
        )

    return _decision(
        effect=PolicyEffect.APPROVAL_REQUIRED,
        risk=entry.risk,
        reason_code=PolicyReasonCode.APPROVAL_REQUIRED,
        required_permission=entry.required_permission,
        required_assurance=entry.required_assurance,
        hashed=hashed,
        approval_path_ids=_open_path_ids(actor, entry, descriptor),
    )


def _open_path_ids(
    actor: ActorContext, entry: CatalogueEntry, descriptor: ActionDescriptor
) -> tuple[int, ...]:
    from app.approvals.composition import (
        is_at_or_above_threshold,
        open_paths,
        parse_roles,
        requester_kind,
    )

    return tuple(
        path.path_id
        for path in open_paths(
            risk=entry.risk,
            requester=requester_kind(parse_roles(actor.roles)),
            at_or_above_threshold=is_at_or_above_threshold(entry, descriptor.normalized_arguments),
        )
    )
