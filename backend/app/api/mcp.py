"""`GET /mcp/tools` and `POST /mcp/call` — the tool boundary over HTTP.

**The audience is not a request field.** A caller arriving with a browser session
is, by definition, `operator_ui`; the `agent` audience belongs to the LangGraph
runtime, which reaches the gateway in-process and never through this endpoint.
Deriving it server-side rather than reading it from the body is what makes a
forged audience impossible here — there is nothing to forge.

The actor is the trusted `ActorContext` the session middleware resolved. This
module never assembles one, and `ToolCallRequest` has no field it could come from.

`POST /mcp/call` is a state-changing method, so the session middleware has already
required a CSRF token and a same-origin `Origin` before this handler runs.
"""

from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError

from app.contracts import ActorContext
from app.contracts.foundation import FrozenContract
from app.errors import ApplicationError, AuthenticationRequired
from app.mcp.contracts import ToolAudience, ToolCallEnvelope
from app.mcp.gateway import McpGateway

router = APIRouter(prefix="/mcp", tags=["mcp"])

# Every caller of this endpoint is a human operator. See the module docstring.
HTTP_AUDIENCE = ToolAudience.OPERATOR_UI


class ToolCallRequest(FrozenContract):
    """`extra="forbid"`. There is no `audience`, no `actor_id`, no `tenant_id`."""

    version: Literal["1"] = "1"
    tool_name: str = Field(min_length=1, max_length=64)
    tool_version: int = Field(default=1, ge=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=255)
    operation_id: UUID | None = None
    request_id: UUID | None = None


class ToolSummary(FrozenContract):
    """What discovery exposes. Enough to call a tool, nothing about others."""

    version: Literal["1"] = "1"
    name: str
    purpose: str
    risk: str
    required_permission: str
    writes: bool
    requires_idempotency_key: bool
    input_schema: dict[str, Any]


@dataclass(slots=True)
class McpApiDependencies:
    gateway: McpGateway


def _actor(request: Request) -> ActorContext:
    actor = getattr(request.state, "actor", None)
    if not isinstance(actor, ActorContext):
        raise AuthenticationRequired
    return actor


def _dependencies(request: Request) -> McpApiDependencies:
    dependencies = getattr(request.app.state, "mcp", None)
    if not isinstance(dependencies, McpApiDependencies):
        raise AuthenticationRequired
    return dependencies


@router.get("/tools")
async def list_tools(request: Request) -> Response:
    """Audience-scoped discovery.

    A tool outside this audience is *absent*, not refused, so its name and schema
    disclose nothing (packet §12). The risk and permission come from the accepted
    `ADR-004` catalogue, so an operator can see what a tool will cost them before
    calling it.
    """
    _actor(request)
    dependencies = _dependencies(request)
    tools = [
        ToolSummary(
            name=tool.name,
            purpose=tool.purpose,
            risk=tool.risk.value,
            required_permission=tool.required_permission,
            writes=tool.writes,
            requires_idempotency_key=tool.requires_idempotency_key,
            input_schema=dict(tool.input_schema),
        ).model_dump(mode="json")
        for tool in dependencies.gateway.list_tools(audience=HTTP_AUDIENCE)
    ]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"version": "1", "audience": HTTP_AUDIENCE.value, "tools": tools},
    )


@router.post("/call")
async def call_tool(request: Request) -> Response:
    """Invoke one tool.

    The handler returns `200` with a `ToolResult` for every outcome the gateway
    reports, including `DENIED` and `APPROVAL_REQUIRED`. Those are *results*, not
    transport failures: a caller must be able to read the approval id out of the
    body and act on it. Only a malformed request or an unavailable tool is an
    error status.
    """
    actor = _actor(request)
    dependencies = _dependencies(request)

    try:
        body = ToolCallRequest.model_validate(await request.json())
    except (ValidationError, ValueError) as error:
        raise ApplicationError(
            code="VALIDATION_FAILED",
            message="The tool call request is not valid.",
            status_code=422,
        ) from error

    envelope = ToolCallEnvelope(
        request_id=body.request_id or uuid4(),
        tool_name=body.tool_name,
        tool_version=body.tool_version,
        audience=HTTP_AUDIENCE,
        typed_arguments=body.arguments,
        idempotency_key=body.idempotency_key,
        operation_id=body.operation_id,
    )
    result = dependencies.gateway.call(
        actor=actor, envelope=envelope, authenticated_audience=HTTP_AUDIENCE
    )
    return JSONResponse(status_code=status.HTTP_200_OK, content=result.model_dump(mode="json"))
