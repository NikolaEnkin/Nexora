"""Composition root for the approval boundary.

Kept separate from `app.agent.wiring` so a rollback can disable protected
execution without touching the runtime, which is what packet §17 asks for.
"""

from collections.abc import Callable
from datetime import UTC, datetime

from redis import Redis
from sqlalchemy.orm import Session, sessionmaker

from app.approvals.audit import ApprovalAuditLog
from app.approvals.gate import ProtectedActionGate
from app.approvals.repository import ApprovalRepository
from app.approvals.runtime import ApprovalRuntimeSignal
from app.approvals.service import ApprovalService
from app.config import Settings
from app.rate_limit import RateLimitPort, RedisRateLimiter


def _utc_now() -> datetime:
    return datetime.now(UTC)


def build_approval_service(
    sessions: sessionmaker[Session],
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> ApprovalService:
    repository = ApprovalRepository(sessions=sessions)
    return ApprovalService(
        repository=repository,
        audit=ApprovalAuditLog(sessions=sessions),
        clock=clock,
    )


def build_rate_limiter(
    settings: Settings, *, clock: Callable[[], datetime] = _utc_now
) -> RateLimitPort:
    return RedisRateLimiter(
        redis=Redis.from_url(settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5),
        clock=clock,
    )


def build_gate(
    sessions: sessionmaker[Session],
    settings: Settings,
    *,
    signal: ApprovalRuntimeSignal | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> ProtectedActionGate:
    service = build_approval_service(sessions, clock=clock)
    return ProtectedActionGate(
        approvals=service,
        repository=service.repository,
        limiter=build_rate_limiter(settings, clock=clock),
        audit=service.audit,
        clock=clock,
        signal=signal,
    )
