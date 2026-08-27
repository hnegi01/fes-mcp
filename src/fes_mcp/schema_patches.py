"""Inner schemas for dict-typed SDK parameters (the dict-param blind spot).

The registry generator introspects PySisense signatures, so a parameter typed
``dict[str, Any]`` becomes a bare ``{"type": "object"}`` schema. MCP clients
then can't see which fields the SDK actually needs: a call like
``create_user(user_data={"firstName": "x"})`` validates, gets past every gate,
and only fails inside the SDK ("Role 'None' not found"). These patches merge
the field contract the installed SDK documents into the advertised tool
schema, so any MCP client's agent knows the real fields — and asks its user
for missing required ones — before calling. Entirely standard MCP: the fix is
a richer inputSchema, nothing else.

Rules:
- Encode ONLY the installed PyPI version's contract (pysisense==1.0.2);
  every entry cites the SDK source it was read from, and
  tests/test_schema_patches.py drift-guards each entry against the installed
  SDK, so a version bump that changes the contract fails tests instead of
  advertising a stale schema.
- Only provable knowledge: ``required`` only where the SDK demonstrably fails
  without the field; ``additionalProperties`` stays True everywhere; params
  whose fields the SDK does not enumerate stay honestly bare.
- Free-form payloads (JAQL, metadata queries, Blox JSON, scripts, encryption)
  are deliberately NOT patched — their "schema" is a language; the registry's
  curated examples are the right guidance there.
- Self-retiring: registry.load_registry applies a patch only while the
  generated schema is still a bare object. When the SDK ships typed payloads
  and regeneration produces real properties, the patch logs a stale warning —
  delete it (and this module, once empty).
"""

from __future__ import annotations

from typing import Any

# {tool_id: {parameter_name: inner JSON Schema}}
SCHEMA_PATCHES: dict[str, dict[str, dict[str, Any]]] = {
    # pysisense access_management/users.py::create_user — fields from the
    # docstring bullet list; `role` is required in code (users.py:509: a
    # missing role becomes "" and the roles_mapping lookup fails), `email`
    # is required by POST /api/v1/users.
    "access_management.create_user": {
        "user_data": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "The user's email address."},
                "firstName": {"type": "string", "description": "The user's first name."},
                "lastName": {"type": "string", "description": "The user's last name."},
                "role": {
                    "type": "string",
                    "description": "Role name to assign (resolved to roleId; "
                    "VIEWER and DESIGNER map to CONSUMER and CONTRIBUTOR).",
                },
                "groups": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Group names to assign (resolved to IDs).",
                },
                "preferences": {"type": "object", "description": "User preference settings."},
            },
            "required": ["email", "role"],
            "additionalProperties": True,
        }
    },
    # pysisense access_management/users.py::update_user — docstring:
    # "Only include fields you want to change" → rich properties, NO required.
    "access_management.update_user": {
        "user_data": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "description": "New email address."},
                "userName": {"type": "string", "description": "New username/login name."},
                "firstName": {"type": "string", "description": "New first name."},
                "lastName": {"type": "string", "description": "New last name."},
                "role": {"type": "string", "description": "New role name (resolved to roleId)."},
                "groups": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Replacement list of group names (resolved to IDs).",
                },
            },
            "required": [],
            "additionalProperties": True,
        }
    },
    # pysisense plugins::restore_snapshot — docstring: "containing at minimum
    # a 'plugins' key with a list of folderName values".
    "plugins.restore_snapshot": {
        "snapshot": {
            "type": "object",
            "properties": {
                "plugins": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "folderName values of the plugins to enable; "
                    "all other plugins will be disabled.",
                },
            },
            "required": ["plugins"],
            "additionalProperties": True,
        }
    },
    # pysisense datamodel::create_connections — docstring names the canonical
    # fields; which are mandatory depends on the connector, so no inner
    # required.
    "datamodel.create_connections": {
        "connection_payload": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Connector provider name."},
                "name": {"type": "string", "description": "Connection display name."},
                "description": {"type": "string"},
                "parameters": {
                    "type": "object",
                    "description": "Provider-specific connection parameters.",
                },
                "enabled": {"type": "boolean"},
                "createdByUser": {"type": "string"},
                "supportedModelTypes": {"type": "array", "items": {"type": "string"}},
            },
            "required": [],
            "additionalProperties": True,
        }
    },
    # pysisense datamodel::update_connection — docstring: "Fields to update
    # (for example name, parameters, provider); supported keys depend on the
    # connection type" → properties as hints, no required.
    "datamodel.update_connection": {
        "connection_data": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "New connection name."},
                "provider": {"type": "string", "description": "Connector provider name."},
                "parameters": {
                    "type": "object",
                    "description": "Provider-specific connection parameters.",
                },
            },
            "required": [],
            "additionalProperties": True,
        }
    },
}
