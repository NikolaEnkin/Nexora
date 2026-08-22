"""The MCP gateway — the only path from a tool call to a business service.

Order, again, is the security property, and it is the same order as the Phase-03
gate because it is the same architecture:

    audience → schema → authorization → policy → execution

Each stage can only refuse. None can re-open what an earlier one closed, and the
business service is never reached until all four have passed.

Two things this gateway deliberately does **not** do:

* It does not accept an actor. `ToolCallEnvelope` has no identity field; the actor
  arrives from the session boundary and is passed in as a separate argument. A
  caller cannot supply one because the contract has nowhere to put it.
* It does not decide risk. `ProtectedActionGate` from Phase 03 does, reading the
  `ADR-004` catalogue. This module would be the obvious place to "simplify" by
  inlining a risk check; that would create a second classification that could
  drift from the accepted one.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

import jsonschema

from app.approvals.errors import ApprovalReplayed, ApprovalRequired
from app.approvals.gate import ProtectedActionGate
from app.business.clients.service import ClientService
from app.contracts import ActorContext
from app.errors import SAFE_DETAIL_KEYS, ApplicationError, AuthorizationDenied
from app.mcp.contracts import (
    ToolAudience,
    ToolCallEnvelope,
    ToolError,
    ToolOutcome,
    ToolResult,
)
from app.mcp.registry import ToolDefinition, lookup, visible_to
from app.policy.catalogue import lookup as catalogue_lookup
from app.policy.contracts import ActionDescriptor
from app.policy.errors import RateLimited
from app.rate_limit import RateLimitPort

IDEMPOTENCY_NAMESPACE = UUID("70000000-0000-0000-0000-000000000005")


class ToolNotAllowed(ApplicationError):
    """A tool that is unknown, or not exposed to this audience.

    The two cases are deliberately indistinguishable: telling a caller that a tool
    exists but is not theirs is a catalogue disclosure.
    """

    def __init__(self) -> None:
        super().__init__(
            code="TOOL_NOT_ALLOWED", message="The tool is not available.", status_code=403
        )


class ToolSchemaInvalid(ApplicationError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            code="TOOL_SCHEMA_INVALID",
            message="The tool arguments are not valid.",
            status_code=422,
            details={"reason": reason},
        )


@dataclass(slots=True)
class McpGateway:
    clients: ClientService
    policy_gate: ProtectedActionGate
    clock: Callable[[], datetime]
    # Required, not optional. An optional limiter would mean a wiring mistake
    # silently removes a control instead of failing to construct.
    limiter: RateLimitPort

    def list_tools(self, *, audience: ToolAudience) -> tuple[ToolDefinition, ...]:
        """Discovery is audience-scoped. A forbidden tool is absent, not refused."""
        return visible_to(audience)

    def call(
        self,
        *,
        actor: ActorContext,
        envelope: ToolCallEnvelope,
        authenticated_audience: ToolAudience,
    ) -> ToolResult:
        # 1. Audience. The audience the caller *claims* must match the one they
        #    were authenticated for, or the claim is worthless.
        if envelope.audience is not authenticated_audience:
            raise ToolNotAllowed
        tool = lookup(envelope.tool_name, authenticated_audience)
        if tool is None:
            raise ToolNotAllowed
        if envelope.tool_version != 1:
            raise ToolNotAllowed

        # 2. Schema. Closed, so an undeclared argument is an error.
        self._validate(tool, envelope.typed_arguments)
        if tool.requires_idempotency_key and not envelope.idempotency_key:
            raise ToolSchemaInvalid("idempotency_key is required for a write tool")

        # 3 and 4. Authorization then policy, inside the Phase-03 gate.
        try:
            return self._dispatch(actor, envelope, tool)
        except ApprovalRequired as required:
            return ToolResult(
                request_id=envelope.request_id,
                tool_name=tool.name,
                tool_version=envelope.tool_version,
                outcome=ToolOutcome.APPROVAL_REQUIRED,
                error=ToolError(
                    code="APPROVAL_REQUIRED",
                    message="A human decision is required before this action runs.",
                    details={"approval_id": required.details["approval_id"]},
                ),
            )
        except AuthorizationDenied:
            return ToolResult(
                request_id=envelope.request_id,
                tool_name=tool.name,
                tool_version=envelope.tool_version,
                outcome=ToolOutcome.DENIED,
                error=ToolError(code="AUTHORIZATION_DENIED", message="Not permitted."),
            )
        except ApplicationError as error:
            return ToolResult(
                request_id=envelope.request_id,
                tool_name=tool.name,
                tool_version=envelope.tool_version,
                outcome=ToolOutcome.FAILED,
                error=ToolError(
                    code=error.code,
                    message=error.message,
                    retryable=error.retryable,
                    # `app.errors.SAFE_DETAIL_KEYS`, not a second copy of it. A
                    # local set was narrower and therefore harmless today, but
                    # two allowlists for the same question drift, and only one of
                    # them gets reviewed when a key is added.
                    details={
                        key: value
                        for key, value in error.details.items()
                        if key in SAFE_DETAIL_KEYS
                    },
                ),
            )

    # -- stages ----------------------------------------------------------

    def _validate(self, tool: ToolDefinition, arguments: dict[str, Any]) -> None:
        try:
            jsonschema.validate(arguments, dict(tool.input_schema))
        except jsonschema.ValidationError as error:
            # The message is the schema's, not the payload's: echoing the payload
            # back would put business content into an error channel.
            raise ToolSchemaInvalid(error.message.split("\n")[0][:200]) from error

    def _dispatch(
        self, actor: ActorContext, envelope: ToolCallEnvelope, tool: ToolDefinition
    ) -> ToolResult:
        now = self.clock()
        arguments = envelope.typed_arguments

        if tool.name == "client_get":
            # Packet §12 requires a rate limit per actor and tool for *every*
            # tool. A read never enters the Phase-03 gate, which is where the
            # limiter runs for writes, so it would otherwise be the one unbounded
            # path — and it is now also the path that appends an audit row per
            # call. Writes are deliberately not limited here as well: the gate
            # limits them a moment later, and limiting twice would silently halve
            # the rate the catalogue publishes.
            self._enforce_read_rate_limit(actor, tool, now)
            record = self.clients.get(
                actor=actor,
                now=now,
                client_id=UUID(arguments["client_id"]) if "client_id" in arguments else None,
                legal_name=arguments.get("legal_name"),
            )
            return self._succeeded(
                envelope, tool, record.model_dump(mode="json"), record.row_version
            )

        # Writes pass the Phase-03 protected-action gate first. It runs the rate
        # limit, authorization and policy, and raises ApprovalRequired when a
        # human must decide — which the caller sees as an outcome, not a failure.
        key = envelope.idempotency_key or ""
        descriptor = ActionDescriptor(
            action_type=tool.name,
            target_type="client",
            target_id=self._target_id(actor, tool, arguments, key),
            normalized_arguments=dict(arguments),
            idempotency_key=key,
        )
        try:
            self.policy_gate.execute(
                actor=actor, descriptor=descriptor, operation_id=envelope.operation_id
            )
        except ApprovalReplayed:
            # The grant is single-use and this submission already consumed it, so
            # the action has happened. Packet §11 requires an unknown result to be
            # resolved from durable state before any retry: fall through to the
            # service, whose own idempotency record returns the stored result and
            # marks it replayed. No second effect is possible — the business
            # idempotency key is the same one that produced the first.
            pass

        if tool.name == "client_create":
            record, replayed = self.clients.create(
                actor=actor,
                legal_name=arguments["legal_name"],
                display_name=arguments["display_name"],
                contact_ref=arguments.get("contact_ref"),
                idempotency_key=key,
                now=now,
            )
        elif tool.name == "client_update":
            record, replayed = self.clients.update(
                actor=actor,
                client_id=UUID(arguments["client_id"]),
                expected_version=arguments["expected_version"],
                legal_name=arguments.get("legal_name"),
                display_name=arguments.get("display_name"),
                status=arguments.get("status"),
                idempotency_key=key,
                now=now,
            )
        else:  # pragma: no cover - the registry admits no other name
            raise ToolNotAllowed

        return self._succeeded(
            envelope, tool, record.model_dump(mode="json"), record.row_version, replayed=replayed
        )

    def _enforce_read_rate_limit(
        self, actor: ActorContext, tool: ToolDefinition, now: datetime
    ) -> None:
        """The same limiter, the same catalogue risk, as a write would get.

        The risk is read from `app.policy.catalogue` rather than from a number
        chosen here, for the reason the registry gives: a second classification
        is a classification that can drift from the accepted one.
        """
        entry = catalogue_lookup(tool.name)
        risk = entry.risk if entry is not None else tool.risk
        verdict = self.limiter.check(
            tenant_id=actor.tenant_id,
            actor_id=actor.actor_id,
            operation=tool.name,
            risk=risk,
            now=now,
        )
        if not verdict.allowed:
            raise RateLimited(verdict.retry_after_seconds)

    @staticmethod
    def _target_id(
        actor: ActorContext, tool: ToolDefinition, arguments: dict[str, Any], key: str
    ) -> UUID:
        """The canonical target the approval binds to.

        For an update it is the client being changed. For a create there is no
        client yet, so it is derived from the submission identity — stable across
        retries, so a retry binds to the same approval rather than opening a new one.
        """
        if "client_id" in arguments:
            return UUID(arguments["client_id"])
        return uuid5(IDEMPOTENCY_NAMESPACE, f"{actor.tenant_id}:{tool.name}:{key}")

    @staticmethod
    def _succeeded(
        envelope: ToolCallEnvelope,
        tool: ToolDefinition,
        resource: dict[str, Any],
        resource_version: int,
        *,
        replayed: bool = False,
    ) -> ToolResult:
        return ToolResult(
            request_id=envelope.request_id,
            tool_name=tool.name,
            tool_version=envelope.tool_version,
            outcome=ToolOutcome.SUCCEEDED,
            resource=resource,
            resource_version=resource_version,
            replayed=replayed,
        )
