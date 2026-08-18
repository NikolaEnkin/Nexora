from dataclasses import dataclass
from time import monotonic

import structlog
from redis import Redis
from sqlalchemy import Engine, text

from app.config import Settings
from app.db.engine import build_engine


@dataclass(slots=True)
class DependencyReadiness:
    engine: Engine
    redis: Redis

    @classmethod
    def from_settings(cls, settings: Settings) -> "DependencyReadiness":
        return cls(
            engine=build_engine(settings.database_url),
            redis=Redis.from_url(
                settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5
            ),
        )

    def is_ready(self) -> bool:
        logger = structlog.get_logger("dependency-readiness")
        started = monotonic()
        try:
            db_started = monotonic()
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            db_latency_ms = round((monotonic() - db_started) * 1000, 3)
            redis_started = monotonic()
            redis_ready = bool(self.redis.ping())
            redis_latency_ms = round((monotonic() - redis_started) * 1000, 3)
            logger.info(
                "dependency_readiness",
                outcome="READY" if redis_ready else "NOT_READY",
                db_latency_ms=db_latency_ms,
                redis_latency_ms=redis_latency_ms,
                total_latency_ms=round((monotonic() - started) * 1000, 3),
            )
            return redis_ready
        except Exception:
            logger.warning(
                "dependency_readiness",
                outcome="NOT_READY",
                total_latency_ms=round((monotonic() - started) * 1000, 3),
            )
            return False
