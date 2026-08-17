from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    FIXED_NOW,
    TENANT_A,
    migration_engine,
    owner_actor,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import set_request_context
from app.events import FoundationMutationService
from app.events.outbox import (
    claim_next,
    log_backlog_snapshot,
    mark_failed,
    mark_published,
    recover_failed,
)


@pytest.mark.integration
def test_expired_outbox_claim_recovers_and_publishes_once() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    FoundationMutationService(sessions).execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="outbox-key-001",
        arguments={"value": "fixed"},
        now=FIXED_NOW,
    )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        snapshot = log_backlog_snapshot(session, now=FIXED_NOW + timedelta(seconds=10))
        assert snapshot.pending_count == 1
        assert snapshot.oldest_age_seconds == 10.0
        first = claim_next(session, now=FIXED_NOW, lease=timedelta(seconds=30))
        assert first is not None
        assert first.attempt_count == 1
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        recovered = claim_next(
            session, now=FIXED_NOW + timedelta(seconds=31), lease=timedelta(seconds=30)
        )
        assert recovered is not None
        assert recovered.id == first.id
        assert recovered.attempt_count == 2
        assert mark_published(session, event_id=recovered.id, now=FIXED_NOW + timedelta(seconds=32))
        assert not mark_published(
            session, event_id=recovered.id, now=FIXED_NOW + timedelta(seconds=33)
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        row = session.execute(
            text("SELECT state, attempt_count, published_at FROM outbox_events")
        ).one()
        assert row.state == "PUBLISHED"
        assert row.attempt_count == 2
        assert row.published_at == FIXED_NOW + timedelta(seconds=32)


@pytest.mark.integration
def test_terminal_outbox_failure_requires_audited_operator_recovery() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    FoundationMutationService(sessions).execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="outbox-failed-001",
        arguments={"value": "fixed"},
        now=FIXED_NOW,
    )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        claimed = claim_next(session, now=FIXED_NOW, lease=timedelta(seconds=30))
        assert claimed is not None
        assert mark_failed(session, event_id=claimed.id, error_code="DELIVERY_REJECTED")
        assert (
            claim_next(
                session,
                now=FIXED_NOW + timedelta(hours=1),
                lease=timedelta(seconds=30),
            )
            is None
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert recover_failed(
            session,
            event_id=claimed.id,
            actor=owner_actor(),
            now=FIXED_NOW + timedelta(hours=1),
        )
        assert (
            session.execute(
                text("SELECT count(*) FROM audit_events WHERE action = 'outbox.recover'")
            ).scalar_one()
            == 1
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        second_claim = claim_next(
            session,
            now=FIXED_NOW + timedelta(hours=1, seconds=1),
            lease=timedelta(seconds=30),
        )
        assert second_claim is not None
    with pytest.raises(DBAPIError, match="invalid outbox transition"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text("UPDATE outbox_events SET attempt_count = attempt_count - 1 WHERE id = :id"),
                {"id": second_claim.id},
            )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert mark_failed(session, event_id=second_claim.id, error_code="DELIVERY_REJECTED")
    with pytest.raises(DBAPIError, match="authorized audit"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """UPDATE outbox_events SET state = 'PENDING', available_at = :now,
                    claimed_at = NULL, lease_expires_at = NULL, last_error_code = NULL
                    WHERE id = :id"""
                ),
                {"now": FIXED_NOW + timedelta(hours=2), "id": second_claim.id},
            )


@pytest.mark.integration
def test_two_workers_cannot_claim_the_same_outbox_event() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    FoundationMutationService(sessions).execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="outbox-two-workers-001",
        arguments={"value": "fixed"},
        now=FIXED_NOW,
    )

    def claim() -> str | None:
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            event = claim_next(session, now=FIXED_NOW, lease=timedelta(seconds=30))
            return None if event is None else str(event.id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _: claim(), range(2)))
    assert sum(item is not None for item in claims) == 1
