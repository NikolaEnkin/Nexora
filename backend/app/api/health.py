from typing import Protocol

from fastapi import APIRouter, Request

from app.errors import DependencyUnavailable


class ReadinessPort(Protocol):
    def is_ready(self) -> bool: ...


router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> dict[str, str]:
    readiness: ReadinessPort = request.app.state.readiness
    if not readiness.is_ready():
        raise DependencyUnavailable
    return {"status": "ready"}
