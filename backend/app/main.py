from uuid import UUID, uuid4

from fastapi import FastAPI, Request

from app.api.health import ReadinessPort
from app.api.health import router as health_router
from app.config import Settings, get_settings
from app.db.health import DependencyReadiness
from app.errors import install_error_handlers
from app.logging import configure_logging


class AlwaysReady:
    def is_ready(self) -> bool:
        return True


def _correlation_id(request: Request) -> str:
    supplied = request.headers.get("X-Correlation-ID")
    if supplied:
        try:
            return str(UUID(supplied))
        except ValueError:
            pass
    return str(uuid4())


def create_app(
    settings: Settings | None = None,
    readiness: ReadinessPort | None = None,
) -> FastAPI:
    active_settings = settings or get_settings()
    configure_logging(
        active_settings.log_level,
        secret_values=(
            active_settings.session_hash_pepper.get_secret_value(),
            active_settings.rls_context_secret.get_secret_value(),
            active_settings.database_url,
            active_settings.redis_url,
        ),
    )
    app = FastAPI(title="Nexora Business Ops", version="0.1.0")
    app.state.settings = active_settings
    app.state.readiness = readiness or DependencyReadiness.from_settings(active_settings)

    @app.middleware("http")
    async def correlation_middleware(request: Request, call_next: object) -> object:
        request.state.correlation_id = _correlation_id(request)
        response = await call_next(request)  # type: ignore[operator]
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        return response

    install_error_handlers(app)
    app.include_router(health_router)
    return app


app = create_app()
