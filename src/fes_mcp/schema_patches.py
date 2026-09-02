"""Per-field descriptions overlaid on SDK payload schemas.

Since pysisense 1.1.0 the dict-typed payload parameters carry machine-readable
TypedDict contracts, so the registry generator produces the nested object
schemas (properties + required) directly from the SDK — the hand-maintained
inner schemas that used to live here were deleted the day the SDK shipped its
own (delete-and-compare confirmed the SDK's are richer: e.g. create_user grew
from our 6 documented fields to the SDK's 8).

What the TypedDicts do NOT carry is per-field descriptions — a schema field
shows up as a bare name ("email") in any client UI. This overlay keeps our
human-written field descriptions until the SDK ships annotated contracts
(Annotated[...] has been requested upstream); then this module dies too.

Rules:
- Descriptions ONLY. This module must never define properties, types, or
  required-ness — the SDK contract is the single source of structural truth.
- registry.load_registry applies a description only to a field that exists in
  the generated schema and lacks one; a field named here that the SDK no
  longer has logs a drift warning (tests/test_schema_patches.py enforces the
  same against the installed SDK).
"""

from __future__ import annotations

# {tool_id: {parameter_name: {field_name: description}}}
FIELD_DESCRIPTIONS: dict[str, dict[str, dict[str, str]]] = {
    "access_management.create_user": {
        "user_data": {
            "email": "The user's email address.",
            "firstName": "The user's first name.",
            "lastName": "The user's last name.",
            "role": "Role name to assign (resolved to roleId; VIEWER and "
            "DESIGNER map to CONSUMER and CONTRIBUTOR).",
            "groups": "Group names to assign (resolved to IDs).",
            "preferences": "User preference settings.",
        }
    },
    "access_management.update_user": {
        "user_data": {
            "email": "New email address.",
            "userName": "New username/login name.",
            "firstName": "New first name.",
            "lastName": "New last name.",
            "role": "New role name (resolved to roleId).",
            "groups": "Replacement list of group names (resolved to IDs).",
        }
    },
    "plugins.restore_snapshot": {
        "snapshot": {
            "plugins": "folderName values of the plugins to enable; all other "
            "plugins will be disabled.",
        }
    },
    "datamodel.create_connections": {
        "connection_payload": {
            "provider": "Connector provider name.",
            "name": "Connection display name.",
            "parameters": "Provider-specific connection parameters.",
        }
    },
    "datamodel.update_connection": {
        "connection_data": {
            "name": "New connection name.",
            "provider": "Connector provider name.",
            "parameters": "Provider-specific connection parameters.",
        }
    },
}
