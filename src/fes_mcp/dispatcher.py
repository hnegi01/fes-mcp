"""Dispatcher: (credential, tool_id, arguments) → PySisense SDK method call.

Clients are cached per credential, so the server can serve many users (each
with their own Sisense identity, possibly on different Sisense instances)
from one process. When no per-session credential is supplied, the env-derived
default credential is used — that's local dev mode.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict
from typing import Any

import jsonschema
import urllib3

from .credentials import SisenseCredential, credential_from_settings
from .settings import Settings

logger = logging.getLogger("fes_mcp.dispatcher")
audit_logger = logging.getLogger("fes_mcp.mutations")

# Cap on distinct cached (domain, token) clients; oldest evicted first.
MAX_CACHED_CLIENTS = 200


class DispatchError(Exception):
    """A tool call failed: bad arguments, unknown tool, or SDK-reported error."""


class _ClientBundle:
    """A SisenseClient plus its lazily-built module facade instances."""

    def __init__(self, credential: SisenseCredential):
        if not credential.ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        from pysisense import SisenseClient

        self.client = SisenseClient.from_connection(
            domain=credential.domain,
            token=credential.token,
            is_ssl=credential.ssl_verify,
        )
        self.modules: dict[str, Any] = {}

    def module(self, class_name: str) -> Any:
        if class_name not in self.modules:
            import pysisense

            klass = getattr(pysisense, class_name, None)
            if klass is None:
                raise DispatchError(f"SDK class '{class_name}' not found in pysisense.")
            self.modules[class_name] = klass(api_client=self.client)
        return self.modules[class_name]


class SisenseDispatcher:
    """Routes tool calls to PySisense facade methods, one client per credential."""

    def __init__(self, settings: Settings, tools: dict[str, dict[str, Any]]):
        self._settings = settings
        self._tools = tools
        self._default_credential = credential_from_settings(settings)
        self._bundles: OrderedDict[tuple, _ClientBundle] = OrderedDict()
        self._lock = threading.RLock()

    @property
    def tools(self) -> dict[str, dict[str, Any]]:
        return self._tools

    def _get_bundle(self, credential: SisenseCredential) -> _ClientBundle:
        key = credential.cache_key()
        with self._lock:
            bundle = self._bundles.get(key)
            if bundle is None:
                bundle = _ClientBundle(credential)
                self._bundles[key] = bundle
                logger.info("SisenseClient created for domain=%s", credential.domain)
                while len(self._bundles) > MAX_CACHED_CLIENTS:
                    self._bundles.popitem(last=False)
            else:
                self._bundles.move_to_end(key)
            return bundle

    def evict(self, credential: SisenseCredential) -> None:
        """Drop the cached client for a credential (e.g. on session logout)."""
        with self._lock:
            self._bundles.pop(credential.cache_key(), None)

    def invoke(
        self,
        tool_id: str,
        arguments: dict[str, Any] | None,
        credential: SisenseCredential | None = None,
    ) -> Any:
        """Validate arguments against the registry schema and call the SDK.

        `credential` is the per-session Sisense identity; falls back to the
        env-derived default when omitted (local dev mode). Returns the raw SDK
        result; raises DispatchError on any failure. Blocking — callers on an
        event loop should offload to a thread.
        """
        meta = self._tools.get(tool_id)
        if meta is None:
            raise DispatchError(f"Unknown tool_id: {tool_id}")

        if meta["mutates"] and not self._settings.allow_mutations:
            raise DispatchError(
                f"Tool '{tool_id}' mutates the Sisense instance and mutations are disabled "
                "(FES_MCP_ALLOW_MUTATIONS=false)."
            )

        cred = credential or self._default_credential
        if cred is None:
            raise DispatchError(
                "No Sisense credential for this session. Authenticate via the connector, "
                "or set SISENSE_DOMAIN and SISENSE_TOKEN in the server environment for dev mode."
            )

        args = _coerce_json_strings(arguments or {})
        _validate_arguments(tool_id, args, meta["parameters"])

        instance = self._get_bundle(cred).module(meta["class"])
        method = getattr(instance, meta["method"], None)
        if method is None:
            raise DispatchError(f"Method '{meta['class']}.{meta['method']}' not found in SDK.")

        if meta["mutates"]:
            audit_logger.info(
                "EXECUTING mutation tool=%s domain=%s args=%s", tool_id, cred.domain, _scrub(args)
            )

        start = time.perf_counter()
        outcome = "error"
        try:
            result = method(**args)
            outcome = "ok"
        except TypeError as exc:
            raise DispatchError(f"Argument error calling {tool_id}: {exc}") from exc
        except Exception as exc:
            raise DispatchError(f"{type(exc).__name__} calling {tool_id}: {exc}") from exc
        finally:
            logger.info(
                "tool=%s domain=%s outcome=%s duration_ms=%.0f",
                tool_id,
                cred.domain,
                outcome,
                (time.perf_counter() - start) * 1000,
            )

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
