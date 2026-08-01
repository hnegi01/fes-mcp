"""Single-tenant dispatcher: tool_id + arguments → PySisense SDK method call.

Slimmed down from the fes-assistant dispatcher: the Sisense connection comes
from env-configured settings (never from tool arguments), and there is no
multi-tenant credential injection, cancellation, or progress-emit plumbing.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

import jsonschema
import urllib3

from .settings import Settings

logger = logging.getLogger("fes_mcp.dispatcher")
audit_logger = logging.getLogger("fes_mcp.mutations")


class DispatchError(Exception):
    """A tool call failed: bad arguments, unknown tool, or SDK-reported error."""


class SisenseDispatcher:
    """Routes tool calls to PySisense facade methods over one cached client."""

    def __init__(self, settings: Settings, tools: dict[str, dict[str, Any]]):
        self._settings = settings
        self._tools = tools
        self._client: Any = None
        self._modules: dict[str, Any] = {}
        # RLock: _get_module_instance holds it while calling _get_client.
        self._lock = threading.RLock()

    @property
    def tools(self) -> dict[str, dict[str, Any]]:
        return self._tools

    def _get_client(self) -> Any:
        """Build the SisenseClient lazily so the server can start (and list
        tools) before credentials are configured."""
        if self._client is None:
            with self._lock:
                if self._client is None:
                    s = self._settings
                    if not s.sisense_domain or not s.sisense_token:
                        raise DispatchError(
                            "Sisense credentials are not configured. "
                            "Set SISENSE_DOMAIN and SISENSE_TOKEN in the server environment."
                        )
                    if not s.sisense_ssl_verify:
                        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    from pysisense import SisenseClient

                    self._client = SisenseClient.from_connection(
                        domain=s.sisense_domain,
                        token=s.sisense_token,
                        is_ssl=s.sisense_ssl_verify,
                    )
                    logger.info("SisenseClient created for domain=%s", s.sisense_domain)
        return self._client

    def _get_module_instance(self, class_name: str) -> Any:
        if class_name not in self._modules:
            with self._lock:
                if class_name not in self._modules:
                    import pysisense

                    klass = getattr(pysisense, class_name, None)
                    if klass is None:
                        raise DispatchError(f"SDK class '{class_name}' not found in pysisense.")
                    self._modules[class_name] = klass(api_client=self._get_client())
        return self._modules[class_name]

    def invoke(self, tool_id: str, arguments: dict[str, Any] | None) -> Any:
        """Validate arguments against the registry schema and call the SDK.

        Returns the raw SDK result. Raises DispatchError on any failure.
        Blocking — callers on an event loop should offload to a thread.
        """
        meta = self._tools.get(tool_id)
        if meta is None:
            raise DispatchError(f"Unknown tool_id: {tool_id}")

        if meta["mutates"] and not self._settings.allow_mutations:
            raise DispatchError(
                f"Tool '{tool_id}' mutates the Sisense instance and mutations are disabled "
                "(FES_MCP_ALLOW_MUTATIONS=false)."
            )

        args = _coerce_json_strings(arguments or {})
        _validate_arguments(tool_id, args, meta["parameters"])

        instance = self._get_module_instance(meta["class"])
        method = getattr(instance, meta["method"], None)
        if method is None:
            raise DispatchError(f"Method '{meta['class']}.{meta['method']}' not found in SDK.")

        if meta["mutates"]:
            audit_logger.info("EXECUTING mutation tool=%s args=%s", tool_id, _scrub(args))

        logger.info("Dispatching %s", tool_id)
        try:
            result = method(**args)
        except TypeError as exc:
            raise DispatchError(f"Argument error calling {tool_id}: {exc}") from exc
        except Exception as exc:
            raise DispatchError(f"{type(exc).__name__} calling {tool_id}: {exc}") from exc

        sdk_error = _sdk_error_message(result)
        if sdk_error is not None:
            raise DispatchError(f"Sisense SDK error from {tool_id}: {sdk_error}")
        return result


def _validate_arguments(tool_id: str, args: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        jsonschema.validate(instance=args, schema=schema)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(p) for p in exc.absolute_path) or "(top level)"
        raise DispatchError(f"Invalid arguments for {tool_id} at {path}: {exc.message}") from exc
    except jsonschema.SchemaError:
        # The registry is auto-generated; a malformed schema should not block
        # the call itself.
        logger.warning("Registry schema for %s is invalid; skipping validation", tool_id)


def _coerce_json_strings(arguments: dict[str, Any]) -> dict[str, Any]:
    """Parse JSON-looking string values ('{...}' / '[...]') into objects —
    MCP clients sometimes stringify nested arguments."""
    coerced: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            stripped = value.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (
                stripped.startswith("[") and stripped.endswith("]")
            ):
                try:
                    coerced[key] = json.loads(stripped)
                    continue
                except json.JSONDecodeError:
                    pass
        coerced[key] = value
    return coerced


def _sdk_error_message(result: Any) -> str | None:
    """PySisense methods report failures as {'error': '...'} (sometimes inside
    a single-item list) instead of raising."""
    candidate = result
    if isinstance(result, list) and len(result) == 1:
        candidate = result[0]
    if isinstance(candidate, dict) and list(candidate.keys()) == ["error"]:
        return str(candidate["error"])
    return None


def _scrub(obj: Any) -> str:
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: "***" if any(s in str(k).lower() for s in ("token", "password", "secret", "authorization")) else clean(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    return json.dumps(clean(obj), default=str)
