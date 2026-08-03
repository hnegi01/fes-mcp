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

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools.tool import Tool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import ConfigDict

from .credentials import SisenseCredential
from .dispatcher import DispatchError, SisenseDispatcher
from .registry import load_registry, select_tools
from .settings import Settings

# Resolves the current request's Sisense credential (None → env/dev default).
# The oauth mode supplies one that maps the caller's access token to the
# credential captured at login.
CredentialResolver = Callable[[], Optional[SisenseCredential]]


def _no_credential() -> SisenseCredential | None:
    return None

logger = logging.getLogger("fes_mcp.server")

SERVER_INSTRUCTIONS = """\
Sisense administration tools backed by the PySisense SDK. All tools operate on
the single Sisense instance this server is connected to. Tool names mirror
PySisense: <module>_<method> (e.g. dashboard_get_all_dashboards). Tools marked
as destructive modify the Sisense instance — confirm with the user before
calling them.
"""


class SisenseTool(Tool):
    """Schema-first MCP tool bound to one registry entry."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_id: str
    dispatcher: SisenseDispatcher
    credential_resolver: CredentialResolver = _no_credential

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
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
        name=_mcp_tool_name(entry["tool_id"]),
        description=entry.get("description") or f"PySisense {entry['tool_id']}",
        parameters=entry["parameters"],
        annotations=ToolAnnotations(
            title=entry["tool_id"],
            readOnlyHint=not mutates,
            destructiveHint=mutates,
            openWorldHint=True,
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

    if settings.auth_mode == "none" and (
        not settings.sisense_domain or not settings.sisense_token
    ):
        logger.warning(
            "SISENSE_DOMAIN/SISENSE_TOKEN not set — tools will list but every call will fail."
        )

    mcp: FastMCP = FastMCP(name="sisense-admin", instructions=SERVER_INSTRUCTIONS, auth=auth)
    for entry in selected.values():
        mcp.add_tool(build_tool(entry, dispatcher, credential_resolver))

    logger.info("Registered %d MCP tools", len(selected))
    return mcp
