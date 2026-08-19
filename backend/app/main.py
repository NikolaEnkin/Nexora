from uuid import UUID, uuid4

from fastapi import FastAPI, Request

from app.agent.wiring import AgentComposition, build_agent_composition
from app.api.approvals import ApprovalApiDependencies
from app.api.approvals import router as approvals_router
from app.api.chat import router as chat_router
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
    *,
    agent: AgentComposition | None = None,
    enable_chat: bool = True,
    approvals: ApprovalApiDependencies | None = None,
    enable_approvals: bool = True,
) -> FastAPI:
    active_settings = settings or get_settings()
    configure_logging(
        active_settings.log_level,
        secret_values=(
            active_settings.session_hash_pepper.get_secret_value(),
            active_settings.rls_context_secret.get_secret_value(),
            active_settings.checkpoint_encryption_key.get_secret_value(),
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

    # `/chat` is feature-disabled independently of health. Rollback can drop the
    # runtime while liveness and readiness keep serving (packet §17).
    if enable_chat:
        composition = agent or build_agent_composition(active_settings)
        app.state.agent = composition
        app.state.chat = composition.dependencies
        app.include_router(chat_router)

    # `/approvals` is feature-disabled independently of `/chat`, so the packet §17
    # rollback ("disable protected execution") is a flag rather than a deploy.
    if enable_approvals:
        composed = approvals or _default_approvals(active_settings)
        app.state.approvals = composed
        app.include_router(approvals_router)

    return app


def _default_approvals(settings: Settings) -> ApprovalApiDependencies:
    from app.approvals.wiring import build_approval_service
    from app.db import build_engine, build_session_factory

    sessions = build_session_factory(build_engine(settings.database_url))
    return ApprovalApiDependencies(service=build_approval_service(sessions))


app = create_app()
