"""Per-actor action rate limiting — `ADR-004` §5.

Keyed `tenant + actor + operation` and enforced *before* any model or action call,
so a burst is refused without having paid for inference or touched an approval.

Redis state here is disposable: losing it loses rate history, never an approval or
an audit record. But "disposable" is not "ignorable". When the store cannot answer,
a protected action fails closed — refusing an R2 or R3 action is recoverable, while
allowing an unbounded burst of them is not. R1 reads degrade open, because a read
carries no side effect and blocking every read on a cache outage converts a
degraded dependency into a total outage.

The limiter never logs a key, an argument or a payload. The Redis key contains
identifiers only.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from redis import Redis
from redis.exceptions import RedisError

from app.policy.catalogue import rate_limit_for
from app.policy.contracts import RiskLevel

WINDOW_SECONDS = 60


@dataclass(frozen=True, slots=True)
class RateVerdict:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    degraded: bool = False


class RateLimitPort:
    """The seam a deterministic test replaces. No test needs a real Redis."""

    def check(
        self, *, tenant_id: UUID, actor_id: UUID, operation: str, risk: RiskLevel, now: datetime
    ) -> RateVerdict:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(slots=True)
class RedisRateLimiter(RateLimitPort):
    """Fixed-window counter.

    A fixed window is chosen over a sliding log deliberately: it needs one
    `INCR` plus one `EXPIRE`, has no unbounded memory growth per actor, and its
    worst case — twice the limit across a window boundary — is acceptable at
    these magnitudes. A sliding window would be more precise and would also give
    an attacker a way to grow memory per key.
    """

    redis: Redis
    clock: Callable[[], datetime]

    def check(
        self, *, tenant_id: UUID, actor_id: UUID, operation: str, risk: RiskLevel, now: datetime
    ) -> RateVerdict:
        limit = rate_limit_for(risk)
        window = int(now.timestamp()) // WINDOW_SECONDS
        key = f"nexora:rate:{tenant_id}:{actor_id}:{operation}:{window}"
        try:
            pipeline = self.redis.pipeline()
            pipeline.incr(key)
            pipeline.expire(key, WINDOW_SECONDS * 2)
            used = int(pipeline.execute()[0])
        except (RedisError, OSError, ValueError):
            return self._degraded(risk, limit)
        remaining = max(0, limit - used)
        return RateVerdict(
            allowed=used <= limit,
            limit=limit,
            remaining=remaining,
            retry_after_seconds=WINDOW_SECONDS,
        )

    @staticmethod
    def _degraded(risk: RiskLevel, limit: int) -> RateVerdict:
        """Store ambiguity: protected actions fail closed, reads degrade open."""
        protected = risk in (RiskLevel.R2, RiskLevel.R3)
        return RateVerdict(
            allowed=not protected,
            limit=limit,
            remaining=0,
            retry_after_seconds=WINDOW_SECONDS,
            degraded=True,
        )


@dataclass(slots=True)
class InMemoryRateLimiter(RateLimitPort):
    """Deterministic double for tests. Same window arithmetic, no network."""

    clock: Callable[[], datetime]
    _counts: dict[tuple[str, int], int] | None = None

    def check(
        self, *, tenant_id: UUID, actor_id: UUID, operation: str, risk: RiskLevel, now: datetime
    ) -> RateVerdict:
        if self._counts is None:
            self._counts = {}
        limit = rate_limit_for(risk)
        window = int(now.timestamp()) // WINDOW_SECONDS
        key = (f"{tenant_id}:{actor_id}:{operation}", window)
        used = self._counts.get(key, 0) + 1
        self._counts[key] = used
        return RateVerdict(
            allowed=used <= limit,
            limit=limit,
            remaining=max(0, limit - used),
            retry_after_seconds=WINDOW_SECONDS,
        )


@dataclass(slots=True)
class UnavailableRateLimiter(RateLimitPort):
    """Simulates an unreachable store, so fail-closed behaviour is asserted directly."""

    def check(
        self, *, tenant_id: UUID, actor_id: UUID, operation: str, risk: RiskLevel, now: datetime
    ) -> RateVerdict:
        return RedisRateLimiter._degraded(risk, rate_limit_for(risk))
