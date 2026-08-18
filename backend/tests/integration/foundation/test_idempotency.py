import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

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

from app.db import set_request_context
from app.errors import IdempotencyConflict, IdempotencyFinalFailure, IdempotencyInProgress
from app.events import FoundationMutationService, MutationResult
from app.events.service import request_hash, stable_id


@pytest.mark.integration
def test_ten_concurrent_duplicates_commit_once() -> None:
    fixture = json.loads(
        Path("backend/tests/fixtures/foundation/idempotent-write.json").read_text()
    )
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    service = FoundationMutationService(sessions)

    def execute_once() -> MutationResult:
        return service.execute(
            actor=owner_actor(),
            operation=fixture["operation"],
            idempotency_key=fixture["idempotency_key"],
            arguments=fixture["arguments"],
            now=FIXED_NOW,
        )

    with ThreadPoolExecutor(max_workers=fixture["workers"]) as executor:
        results = list(executor.map(lambda _: execute_once(), range(fixture["workers"])))
    identities = {(item.operation_id, item.event_id) for item in results}
    payloads = [item.result for item in results]
    assert len(identities) == 1
    assert payloads == [payloads[0]] * 10
    assert [item.replayed for item in results].count(False) == 1
    assert [item.replayed for item in results].count(True) == 9

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in (
            "foundation_mutations",
            "domain_events",
            "outbox_events",
            "idempotency_records",
            "audit_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
        durable = session.execute(
            text("SELECT stored_result FROM idempotency_records")
        ).scalar_one()
        assert durable["result"] == payloads[0]
        before_counts = {
            table: session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            for table in (
                "foundation_mutations",
                "domain_events",
                "outbox_events",
                "idempotency_records",
                "audit_events",
            )
        }

    with pytest.raises(IdempotencyConflict):
        service.execute(
            actor=owner_actor(),
            operation="foundation.test_mutation",
            idempotency_key="concurrent-key-001",
            arguments={"amount": "999.00", "currency": "EUR"},
            now=FIXED_NOW,
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        after_counts = {
            table: session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            for table in before_counts
        }
        assert after_counts == before_counts
        assert (
            session.execute(text("SELECT stored_result FROM idempotency_records")).scalar_one()
            == durable
        )


@pytest.mark.integration
def test_idempotency_lease_takeover_and_terminal_states_are_deterministic() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    actor = owner_actor()
    service = FoundationMutationService(sessions)
    arguments = {"amount": "125.00", "currency": "EUR"}

    def seed_record(key: str, state: str, lease_delta: timedelta) -> None:
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """INSERT INTO idempotency_records (
                    id, tenant_id, actor_id, operation, idempotency_key, request_hash,
                    contract_version, state, stored_result, stored_error, lease_expires_at,
                    expires_at, created_at, updated_at)
                    VALUES (:id, :tenant, :actor, 'foundation.test_mutation', :key, :hash,
                        1, CAST(:state AS varchar), NULL,
                        CASE WHEN CAST(:state AS varchar) = 'FAILED_FINAL'
                             THEN '{"code":"FINAL"}'::jsonb ELSE NULL END,
                        CASE WHEN CAST(:state AS varchar) = 'IN_PROGRESS' THEN :lease ELSE NULL END,
                    :expires, :now, :now)"""
                ),
                {
                    "id": stable_id("idempotency", actor, "foundation.test_mutation", key),
                    "tenant": TENANT_A,
                    "actor": ACTOR_A,
                    "key": key,
                    "hash": request_hash("1", arguments),
                    "state": state,
                    "lease": FIXED_NOW + lease_delta,
                    "expires": FIXED_NOW + timedelta(days=7),
                    "now": FIXED_NOW - timedelta(minutes=10),
                },
            )

    seed_record("expired", "IN_PROGRESS", timedelta(minutes=-1))
    takeover = service.execute(
        actor=actor,
        operation="foundation.test_mutation",
        idempotency_key="expired",
        arguments=arguments,
        now=FIXED_NOW,
    )
    assert takeover.replayed is False

    seed_record("active", "IN_PROGRESS", timedelta(minutes=1))
    with pytest.raises(IdempotencyInProgress):
        service.execute(
            actor=actor,
            operation="foundation.test_mutation",
            idempotency_key="active",
            arguments=arguments,
            now=FIXED_NOW,
        )

    seed_record("terminal", "FAILED_FINAL", timedelta(minutes=-1))
    with pytest.raises(IdempotencyFinalFailure):
        service.execute(
            actor=actor,
            operation="foundation.test_mutation",
            idempotency_key="terminal",
            arguments=arguments,
            now=FIXED_NOW,
        )
