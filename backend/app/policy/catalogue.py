"""The versioned action risk catalogue — `ADR-004` §1, §3 and §5.

This module is data plus a lookup. Nothing here consults a model, a prompt, a
request body or retrieved content: `ARCH-008` requires the risk classification to
be code and data, so an action's risk level is a property of the deployed
catalogue version and of nothing else.

The catalogue is versioned because `ADR-004` §Rollback makes reclassification a
migration rather than a code edit. Migration `0003` seeds `policy_action_catalogue`
from `CATALOGUE`, and `P03-UAT-01` has Nikola sign the exported matrix.

Business permissions named here (`client.*`, `offer.*`, `invoice.*`, `payment.*`,
`email.*`, `contact.*`) are created by Phase 04 and Phase 05, which own those
actions. Phase 03 references them by name only and creates no business table or
tool, per `ADR-004` §2.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Final

from app.policy.contracts import Assurance, RiskLevel

CATALOGUE_VERSION: Final = 1

# `ADR-004` §2. What this figure measures — net or gross, which currency, and the
# conversion rule for non-EUR documents — is deferred to HD-004 and is NOT decided
# here. Phase 03 implements the comparison and tests both sides of it.
AMOUNT_THRESHOLD: Final = Decimal("10000")

# `ADR-004` §5, keyed tenant + actor + operation, enforced before any model call.
RATE_LIMIT_PER_MINUTE: Final[Mapping[RiskLevel, int]] = {
    RiskLevel.R1: 120,
    RiskLevel.R2: 30,
    RiskLevel.R3: 10,
}


@dataclass(frozen=True, slots=True)
class CatalogueEntry:
    """One action's immutable classification."""

    action_key: str
    risk: RiskLevel
    required_permission: str
    required_assurance: Assurance
    # Names the normalized argument carrying the transaction amount, for the R3
    # composition rule only. Phase 03 reads the declared field; it does not decide
    # what the field means (HD-004).
    amount_field: str | None = None
    currency_field: str | None = None


def _r1(action_key: str, permission: str) -> CatalogueEntry:
    return CatalogueEntry(
        action_key=action_key,
        risk=RiskLevel.R1,
        required_permission=permission,
        required_assurance=Assurance.STANDARD,
    )


def _r2(action_key: str, permission: str) -> CatalogueEntry:
    return CatalogueEntry(
        action_key=action_key,
        risk=RiskLevel.R2,
        required_permission=permission,
        required_assurance=Assurance.STANDARD,
    )


def _r3(action_key: str, permission: str) -> CatalogueEntry:
    return CatalogueEntry(
        action_key=action_key,
        risk=RiskLevel.R3,
        required_permission=permission,
        # `ADR-004` §4: every R3 approver needs step-up, in every slot.
        required_assurance=Assurance.STEP_UP,
        amount_field="amount",
        currency_field="currency",
    )


_ENTRIES: Final[tuple[CatalogueEntry, ...]] = (
    # -- R1: authorization only, no approval -----------------------------
    # Reversible, purely internal, and they emit nothing. The protected doors
    # behind them are `invoice_issue` and `email_send`.
    _r1("client_get", "client.read"),
    _r1("offer_get", "offer.read"),
    _r1("offer_items", "offer.read"),
    _r1("invoice_get", "invoice.read"),
    _r1("invoice_items", "invoice.read"),
    _r1("invoice_list_unpaid", "invoice.read"),
    _r1("offer_validate", "offer.write"),
    _r1("invoice_validate", "invoice.write"),
    _r1("email_account_list", "email.read"),
    _r1("email_draft_get", "email.read"),
    _r1("email_thread_recent", "email.read"),
    # -- R2: exactly one approval ----------------------------------------
    _r2("client_create", "client.write"),
    _r2("client_update", "client.write"),
    _r2("offer_draft_create", "offer.write"),
    _r2("invoice_draft_create", "invoice.write"),
    _r2("email_draft_create", "email.draft"),
    _r2("email_draft_update", "email.draft"),
    # R2 despite being a read: it selects who receives an offer or invoice, and a
    # wrong resolution is discovered only once the document is at a competitor.
    _r2("contact_resolve", "contact.read"),
    # Always R2 regardless of recipient. A message may be composed by a person or
    # by the agent, but there is no autonomous send path.
    _r2("email_send", "email.send"),
    # -- R3: approval composition plus step-up ---------------------------
    # The amount does not change the risk level; it changes how many people must
    # agree. See `app.approvals.composition`.
    _r3("invoice_issue", "invoice.issue"),
    _r3("payment_record", "payment.record"),
)

CATALOGUE: Final[Mapping[str, CatalogueEntry]] = {entry.action_key: entry for entry in _ENTRIES}

# `ADR-004` §3. TTL scales with the number of decisions the *open* paths require.
# It is fixed when the request is created, so it is derived from the requester's
# authority and the amount rather than from the path eventually used.
TTL_R2: Final = timedelta(hours=1)
TTL_R3_SELF_APPROVABLE: Final = timedelta(minutes=10)
TTL_R3_SINGLE_OR_PAIR: Final = timedelta(hours=1)
TTL_R3_THREE_PARTY: Final = timedelta(hours=2)


def lookup(action_key: str) -> CatalogueEntry | None:
    """Return the entry, or `None` for an unclassified action.

    An unknown action is never allowed by default. `app.policy.evaluator` turns
    `None` into a denial, because `ARCH-015` makes an unclassified action a stop
    condition rather than something to guess at.
    """
    return CATALOGUE.get(action_key)


def rate_limit_for(risk: RiskLevel) -> int:
    return RATE_LIMIT_PER_MINUTE[risk]
