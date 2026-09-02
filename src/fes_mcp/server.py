"""FastMCP server assembly: registry-driven tool factory.

Each allowlisted registry entry becomes one MCP tool, registered schema-first
(name + description + raw JSON Schema) rather than via decorated Python
functions, so the tool surface always mirrors the generated registry.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Optional

import hashlib

import mcp.types as mt
import mcp_types
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.elicitation import AcceptedElicitation
from fastmcp.tools import InputRequiredToolResult, Tool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import ConfigDict

from .credentials import SisenseCredential
from .descriptions import compose_description
from .dispatcher import DispatchError, SisenseDispatcher, _scrub
from .registry import load_registry, select_tools
from .settings import Settings

# Resolves the current request's Sisense credential (None → env/dev default).
# Upstream mode supplies one that reads the credential injected per request.
CredentialResolver = Callable[[], Optional[SisenseCredential]]


def _no_credential() -> SisenseCredential | None:
    return None

logger = logging.getLogger("fes_mcp.server")

SERVER_INSTRUCTIONS = """\
Sisense management tools backed by the PySisense SDK, for any Sisense user:
every call runs with the calling user's own Sisense credential, so results and
permissions are exactly what that user can see and do in Sisense itself. Tool
names mirror PySisense: <module>_<method> (e.g. dashboard_get_all_dashboards).
Tools marked as destructive modify the Sisense instance — confirm with the
user before calling them. On clients that support MCP elicitation, destructive
tools also ask the user to approve directly before executing.
"""


def _current_context():
    """The active request Context, or None outside a request (e.g. tests
    calling run() directly)."""
    try:
        from fastmcp.server.dependencies import get_context

        return get_context()
    except RuntimeError:
        return None


# Keep the confirmation dialog readable even for huge payloads.
_ELICIT_ARGS_LIMIT = 800

# Key for the mutation-confirmation ask in an InputRequiredResult's
# input_requests map (and the matching entry in ctx.input_responses).
_CONFIRM_KEY = "confirm_mutation"


def _is_modern(ctx: Any) -> bool:
    """Whether this connection negotiated the stateless (2026-07-28) era.

    fastmcp exposes this only as the private method Context._is_modern_protocol
    (no public equivalent yet — re-check on every fastmcp upgrade; a drift
    guard in tests/unit/test_safety.py fails if it disappears). It is a
    method, not a property: it must be called, never truth-tested.
    """
    probe = getattr(ctx, "_is_modern_protocol", None)
    try:
        return probe() if callable(probe) else bool(probe)
    except Exception:  # noqa: BLE001 — unknown era: use the legacy wire path
        return False


def _supports_form_elicitation(ctx: Any) -> bool:
    try:
        return bool(
            ctx.session.check_client_capability(
                mt.ClientCapabilities(elicitation=mt.ElicitationCapability())
            )
        )
    except Exception:  # noqa: BLE001 — treat any probe failure as "no"
        return False


def _answer_value(answer: Any) -> Any:
    """The "value" field of an elicitation answer's content, which may arrive
    as a plain dict or as a model object depending on the client/SDK."""
    content = getattr(answer, "content", None)
    if isinstance(content, dict):
        return content.get("value")
    return getattr(content, "value", None)


def _args_fingerprint(arguments: dict[str, Any]) -> str:
    """Binds a confirmation to the exact arguments the human saw: carried in
    request_state across the MRTR round trip and re-checked on the retry, so
    an approval can never be replayed onto different arguments."""
    canon = json.dumps(arguments, sort_keys=True, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


class SisenseTool(Tool):
    """Schema-first MCP tool bound to one registry entry."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_id: str
    dispatcher: SisenseDispatcher
    credential_resolver: CredentialResolver = _no_credential
    mutates: bool = False

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        if self.mutates:
            decision = await self._user_approved(arguments)
            if isinstance(decision, ToolResult):
                return decision  # the MRTR ask, or the aborted result
            if decision is False:
                return self._aborted()

        credential = self.credential_resolver()
        try:
            result = await asyncio.to_thread(
                self.dispatcher.invoke, self.tool_id, arguments, credential
            )
        except DispatchError as exc:
            raise ToolError(str(exc)) from exc

        structured = result if isinstance(result, dict) else {"result": result}
        return ToolResult(
            content=json.dumps(result, indent=2, default=str),
            structured_content=structured,
        )

    def _aborted(self) -> ToolResult:
        aborted = {
            "aborted": True,
            "mutated": False,
            "message": "User declined the confirmation; nothing was changed.",
        }
        return ToolResult(
            content=json.dumps(aborted, indent=2), structured_content=aborted
        )

    def _confirm_message(self, arguments: dict[str, Any]) -> str:
        args_shown = _scrub(arguments) if arguments else "(no arguments)"
        if len(args_shown) > _ELICIT_ARGS_LIMIT:
            args_shown = args_shown[:_ELICIT_ARGS_LIMIT] + "… (truncated)"
        return (
            f"'{self.name}' will modify the Sisense instance with "
            f"arguments: {args_shown} Proceed?"
        )

    async def _user_approved(self, arguments: dict[str, Any]) -> bool | ToolResult:
        """Ask the human before a mutating tool runs, disclosing the exact
        arguments (secrets masked) so they confirm an operation, not a name.

        Two wire mechanisms, one behavior:
        - 2026-07-28 connections (stateless): the MRTR guard pattern — return
          an input_required result carrying the confirmation ask; the client
          answers and retries, and the answer arrives in ctx.input_responses.
          request_state carries a fingerprint of the arguments so an approval
          can never be replayed onto different arguments.
        - Legacy connections: imperative ctx.elicit, as before.

        Fail-open by design in both eras: a client that cannot render the
        confirmation proceeds under its own tool-approval flow plus
        destructiveHint, like any standard MCP server. Returns True to
        proceed, False to abort, or a ToolResult to send instead (the ask).
        """
        ctx = _current_context()
        if ctx is None:
            return True

        # MRTR round 2: the client retried with an answer attached.
        responses = getattr(ctx, "input_responses", None)
        if responses and _CONFIRM_KEY in responses:
            if getattr(ctx, "request_state", None) != _args_fingerprint(arguments):
                return self._mrtr_ask(arguments)  # args changed since the ask
            answer = responses[_CONFIRM_KEY]
            return (
                getattr(answer, "action", None) == "accept"
                and _answer_value(answer) == "proceed"
            )

        if not _supports_form_elicitation(ctx):
            return True  # fail-open: the client's own approval UI is the safeguard

        if _is_modern(ctx):
            return self._mrtr_ask(arguments)  # MRTR round 1: send the ask

        # Legacy connection: imperative elicitation.
        try:
            answer = await ctx.elicit(
                self._confirm_message(arguments), response_type=["proceed", "abort"]
            )
        except Exception as exc:  # noqa: BLE001
            raise ToolError(
                f"Confirmation dialog failed ({exc}); nothing was changed. "
                "Retry the call to be asked again."
            ) from exc
        return isinstance(answer, AcceptedElicitation) and answer.data == "proceed"

    def _mrtr_ask(self, arguments: dict[str, Any]) -> ToolResult:
        ask = mcp_types.ElicitRequest(
            params=mcp_types.ElicitRequestFormParams(
                message=self._confirm_message(arguments),
                requested_schema={
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "enum": ["proceed", "abort"],
                            "title": "Confirm",
                        }
                    },
                    "required": ["value"],
                },
            )
        )
        return InputRequiredToolResult(
            mcp_types.InputRequiredResult(
                input_requests={_CONFIRM_KEY: ask},
                request_state=_args_fingerprint(arguments),
            )
        )


def _mcp_tool_name(tool_id: str) -> str:
    # MCP tool names must match [a-zA-Z0-9_-]; registry ids use dots.
    return tool_id.replace(".", "_")


def build_tool(
    entry: dict[str, Any],
    dispatcher: SisenseDispatcher,
    credential_resolver: CredentialResolver = _no_credential,
) -> SisenseTool:
    mutates = bool(entry["mutates"])
    return SisenseTool(
        tool_id=entry["tool_id"],
        dispatcher=dispatcher,
        credential_resolver=credential_resolver,
        mutates=mutates,
        name=_mcp_tool_name(entry["tool_id"]),
        description=compose_description(entry) or f"PySisense {entry['tool_id']}",
        parameters=entry["parameters"],
        output_schema=entry.get("output_schema"),
        annotations=ToolAnnotations(
            title=entry["tool_id"],
            read_only_hint=not mutates,
            destructive_hint=mutates,
            open_world_hint=True,
        ),
        tags={entry["module"]},
        meta={
            "tool_id": entry["tool_id"],
            "module": entry["module"],
            "mutates": mutates,
            "sdk_version": entry.get("sdk_version"),
        },
    )


def build_server(
    settings: Settings,
    credential_resolver: CredentialResolver = _no_credential,
    auth: Any = None,
) -> FastMCP:
    registry = load_registry(settings.registry_path)
    selected = select_tools(registry, settings.allowlist, settings.allow_mutations)
    if not selected:
        raise RuntimeError(
            "No tools selected. Check FES_MCP_TOOLS / config/allowlist.txt against the registry."
        )

    dispatcher = SisenseDispatcher(settings, selected)

    if settings.auth_mode == "env" and (
        not settings.sisense_domain or not settings.sisense_token
    ):
        logger.warning(
            "SISENSE_DOMAIN/SISENSE_TOKEN not set — tools will list but every call will fail."
        )

    mcp: FastMCP = FastMCP(name="sisense", instructions=SERVER_INSTRUCTIONS, auth=auth)
    for entry in selected.values():
        mcp.add_tool(build_tool(entry, dispatcher, credential_resolver))

    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse

    @mcp.custom_route("/", methods=["GET"])
    async def root(request: Request) -> PlainTextResponse:
        return PlainTextResponse(
            "Sisense Meta-Management MCP server (resource server) is running.\n"
            f"Tools: {len(selected)} | auth: {settings.auth_mode}\n"
            "Add the /mcp path of this URL as a connector in your MCP client "
            "(Claude Desktop / Claude Code / claude.ai). Do not browse here directly.\n"
        )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "tools": len(selected), "auth": settings.auth_mode})

    logger.info("Registered %d MCP tools", len(selected))
    return mcp
