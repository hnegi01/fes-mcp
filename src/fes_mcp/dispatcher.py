"""Dispatcher: (credential, tool_id, arguments) → PySisense SDK method call.

Clients are cached per credential, so the server can serve many users (each
with their own Sisense identity, possibly on different Sisense instances)
from one process. When no per-session credential is supplied, the env-derived
default credential is used — that's local dev mode.
"""

from __future__ import annotations

import json
import logging
import re
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

# Dashboard OIDs are 24 hex chars; DataModel (v2) ids are GUIDs.
_HEX24 = re.compile(r"^[0-9a-fA-F]{24}$")
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class DispatchError(Exception):
    """A tool call failed: bad arguments, unknown tool, or SDK-reported error."""


class _ClientBundle:
    """A SisenseClient plus its lazily-built module facade instances."""

    def __init__(self, credential: SisenseCredential):
        if not credential.ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        from pysisense import SisenseClient

        from .auth import domain_uses_ssl

        self.client = SisenseClient.from_connection(
            domain=credential.domain,
            token=credential.token,
            # is_ssl is the URL scheme (it also selects http:30845 for non-SSL
            # instances); the credential's ssl_verify is certificate
            # verification. Confusing the two sends HTTPS traffic to
            # http://host:30845 — token in cleartext.
            is_ssl=domain_uses_ssl(credential.domain),
            verify_ssl=credential.ssl_verify,
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

        args = _coerce_json_strings(arguments or {}, meta["parameters"])
        _validate_arguments(tool_id, args, meta["parameters"])

        bundle = self._get_bundle(cred)
        args = _resolve_references(bundle, tool_id, meta, args)
        instance = bundle.module(meta["class"])
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


def _resolve_references(
    bundle: _ClientBundle, tool_id: str, meta: dict[str, Any], args: dict[str, Any]
) -> dict[str, Any]:
    """Let every tool accept an ID or a title, whichever the user has.

    The SDK is inconsistent: dashboard methods take a `dashboard_id` (24-hex
    OID) while datamodel methods take a `datamodel_name` (title). Rather than
    exposing the SDK's resolve_* helpers as separate tools, convert here:
    a title passed as dashboard_id resolves to the OID, and an ID passed as
    datamodel_name resolves to the title. Unresolvable references fail with
    a clear error instead of a confusing SDK payload.
    """
    if meta["method"].startswith("resolve_"):
        return args

    out = dict(args)

    ref = out.get("dashboard_id")
    if isinstance(ref, str) and ref and not _HEX24.match(ref):
        resolved = _call_resolver(
            bundle, "Dashboard", "resolve_dashboard_reference", ref, tool_id
        )
        out["dashboard_id"] = resolved["dashboard_id"]
        logger.info(
            "tool=%s resolved dashboard %r -> %s", tool_id, ref, resolved["dashboard_id"]
        )

    ref = out.get("datamodel_name")
    if isinstance(ref, str) and (_GUID.match(ref) or _HEX24.match(ref)):
        resolved = _call_resolver(
            bundle, "DataModel", "resolve_datamodel_reference", ref, tool_id
        )
        out["datamodel_name"] = resolved["datamodel_title"]
        logger.info(
            "tool=%s resolved datamodel %r -> %r", tool_id, ref, resolved["datamodel_title"]
        )

    return out


def _call_resolver(
    bundle: _ClientBundle, class_name: str, method: str, ref: str, tool_id: str
) -> dict[str, Any]:
    kind = "dashboard" if class_name == "Dashboard" else "data model"
    try:
        result = getattr(bundle.module(class_name), method)(ref)
    except Exception as exc:
        raise DispatchError(f"Could not resolve {kind} {ref!r} for {tool_id}: {exc}") from exc
    if not (isinstance(result, dict) and result.get("success")):
        detail = result.get("error") if isinstance(result, dict) else result
        raise DispatchError(
            f"Could not resolve {kind} {ref!r} for {tool_id}: {detail or 'not found'}"
        )
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


def _wants_structure(prop_schema: Any) -> bool:
    """Whether a parameter's declared schema expects an object/array (or is
    free-form), i.e. a stringified JSON value should be parsed for it."""
    if not isinstance(prop_schema, dict):
        return False
    declared = prop_schema.get("type")
    if declared is None:
        # Free-form param (bare {} or anyOf without a top-level type): keep
        # coercing — these are exactly the payloads clients stringify.
        return True
    types = declared if isinstance(declared, list) else [declared]
    return "object" in types or "array" in types


def _coerce_json_strings(
    arguments: dict[str, Any], schema: dict[str, Any]
) -> dict[str, Any]:
    """Parse JSON-looking string values ('{...}' / '[...]') into objects —
    MCP clients sometimes stringify nested arguments. Only parameters whose
    schema expects structure are coerced: a genuine string value that happens
    to look like JSON (a title such as "[1,2]") must pass through untouched."""
    properties = schema.get("properties") or {}
    coerced: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str) and _wants_structure(properties.get(key)):
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
    """Normalize the SDK's failure returns to one error path.

    pysisense >= 2.0 marks every failure dict with "ok": False (success
    returns never carry "ok"), so detection is marker-based, NEVER an
    exact-key-set match — an exact-shape matcher is what silently turned
    401s into successes when the contract gained a field. Legacy shapes
    (bare {"error": ...} dicts, "Error: ..." strings, single-item list
    wrapping) are kept for defense in depth.
    """
    candidate = result
    if isinstance(result, list) and len(result) == 1:
        candidate = result[0]
    if isinstance(candidate, dict):
        # Primary: the 2.0 marker. Legacy backup: the exact pre-2.0 error
        # shapes (exact, so a data payload that merely CONTAINS an "error"
        # field is never misread as a failure).
        is_failure = candidate.get("ok") is False or set(candidate.keys()) in (
            {"error"},
            {"error", "status_code"},
        )
        if is_failure:
            message = str(candidate.get("error") or "SDK call failed")
            status = candidate.get("status_code")
            if status is not None:
                message = f"{message} (HTTP {status})"
            raw = candidate.get("raw_body")
            if raw:
                message = f"{message} — {raw}"
            return message
    if isinstance(candidate, str) and candidate.startswith("Error:"):
        return candidate
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
