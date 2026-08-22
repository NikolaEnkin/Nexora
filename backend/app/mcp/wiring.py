"""Composition root for the MCP boundary.

Separate from `app.approvals.wiring` so a rollback can disable the tool surface
without touching policy or approvals — packet §17 asks for write tools to be
disabled first.
"""

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from app.approvals.wiring import build_gate
from app.business.clients.service import ClientService
from app.config import Settings
from app.mcp.gateway import McpGateway


def _utc_now() -> datetime:
    return datetime.now(UTC)


def build_gateway(
    sessions: sessionmaker[Session],
    settings: Settings,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> McpGateway:
    gate = build_gate(sessions, settings, clock=clock)
    return McpGateway(
        clients=ClientService(sessions=sessions),
        policy_gate=gate,
        clock=clock,
        # The gate's own limiter, not a second one: two limiter instances would
        # be two independent budgets for the same actor.
        limiter=gate.limiter,
    )
