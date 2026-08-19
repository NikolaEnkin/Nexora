"""The model boundary: a port, and a deterministic adapter behind it.

Phase 02 selects no production provider and holds no provider credential. The
adapter here produces fixed output for fixed input so every downstream assertion
can be exact rather than "plausible prose".

The important property is what the response *cannot* do. `ModelResponse.route_hint`
is a free-form string that the model fills in and the runtime ignores; it exists
precisely so a security test can prove that a model demanding a different route,
a permission, or a tool changes nothing. Routing comes from `app.agent.routing`,
lifecycle comes from the runtime service, and tools come from a registry that is
empty and cannot be added to.
"""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.agent.routing import normalize
from app.agent.state import AgentMessage, AgentRoute, MessageRole
from app.config import Settings

ECHO_PREFIX = "echo:"
CLARIFICATION_TEXT = "Could you add more detail?"
DELTA_COUNT = 3
ROUTE_HINT_LENGTH = 64


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """What the runtime asks for. The route is already decided."""

    operation_id: UUID
    route: AgentRoute
    messages: tuple[AgentMessage, ...]


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """What the model returns. All of it is untrusted data.

    `deltas` always concatenate to exactly `text`, so a stream consumer that joins
    the deltas and a consumer that reads the completion agree byte for byte.
    """

    route_hint: str
    deltas: tuple[str, ...]
    text: str

    def __post_init__(self) -> None:
        if "".join(self.deltas) != self.text:
            raise ValueError("model deltas must concatenate to the completed text")


class ModelPort(Protocol):
    def respond(self, request: ModelRequest) -> ModelResponse: ...


def _latest_user_content(messages: tuple[AgentMessage, ...]) -> str:
    for message in reversed(messages):
        if message.role is MessageRole.USER:
            return message.content
    return ""


@dataclass(frozen=True, slots=True)
class DeterministicModelAdapter:
    """Fixed input produces fixed route-appropriate deltas and a fixed completion.

    Refuses to exist outside development/test, mirroring `FakeIdentityAdapter`, so
    it cannot become an accidental production model.
    """

    settings: Settings

    def __post_init__(self) -> None:
        if self.settings.environment not in {"development", "test"}:
            raise RuntimeError("deterministic model adapter is forbidden outside development/test")

    def respond(self, request: ModelRequest) -> ModelResponse:
        content = _latest_user_content(request.messages)
        # Echoed back verbatim so a test can show that even a hint literally
        # spelling out "CONTROLLED_FAILURE" or "send_email" is inert.
        route_hint = normalize(content)[:ROUTE_HINT_LENGTH]

        if request.route is AgentRoute.ECHO:
            deltas = (ECHO_PREFIX, " ", content)
        elif request.route is AgentRoute.CLARIFY:
            deltas = ("Could you", " add more", " detail?")
        else:
            deltas = ("The runtime", " could not", " complete this request.")

        if len(deltas) != DELTA_COUNT:
            raise ValueError("deterministic adapter must emit exactly three deltas")
        return ModelResponse(route_hint=route_hint, deltas=deltas, text="".join(deltas))
