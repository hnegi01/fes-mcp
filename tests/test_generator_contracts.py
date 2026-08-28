"""Forward-compat generator support for pysisense >= 1.1.0 machine-readable
contracts: TypedDict payloads, Literal enums, deprecated aliases, FACADES
discovery — plus the documented error-return contract in the dispatcher.

All tests run against synthetic constructs so they pass on the currently
pinned SDK; they define the behavior that activates on the 1.1.0 pin bump.
"""

import importlib
from types import SimpleNamespace
from typing import Any, Literal, Optional, TypedDict

from fes_mcp.dispatcher import _sdk_error_message

builder = importlib.import_module("scripts.01_build_registry_from_sdk")
core = importlib.import_module("scripts.registry_core")


# Two-class TypedDict pattern (as pysisense payloads.py uses) so
# __required_keys__ / __optional_keys__ are populated.
class _UserRequired(TypedDict):
    email: str
    role: str


class FakeCreateUserPayload(_UserRequired, total=False):
    firstName: str
    groups: list[str]


# --- annotation → schema ------------------------------------------------------


def test_typeddict_annotation_builds_nested_object_schema():
    schema = builder._schema_from_annotation(FakeCreateUserPayload)
    assert schema["type"] == "object"
    assert schema["required"] == ["email", "role"]
    assert schema["properties"]["groups"] == {"type": "array", "items": {"type": "string"}}
    assert schema["additionalProperties"] is True


def test_literal_annotation_becomes_enum():
    assert builder._schema_from_annotation(Literal["extract", "live"]) == {
        "type": "string",
        "enum": ["extract", "live"],
    }


def test_optional_and_containers():
    assert builder._schema_from_annotation(Optional[str]) == {"type": "string"}
    assert builder._schema_from_annotation(list[str]) == {
        "type": "array",
        "items": {"type": "string"},
    }
    assert builder._schema_from_annotation(dict[str, Any]) == {"type": "object"}


def test_unknown_class_yields_no_knowledge_not_string():
    # The FES trap: an unrecognized payload class must NOT degrade the schema
    # to {"type": "string"} — None lets docstring/default inference decide.
    class SomeUnknownContract:
        pass

    assert builder._schema_from_annotation(SomeUnknownContract) is None
    assert builder._schema_from_annotation(Any) is None


def test_typeddict_wins_inside_signature_schema():
    import inspect

    def create_user(self, user_data: FakeCreateUserPayload):
        """Create a user.

        Parameters
        ----------
        user_data : FakeCreateUserPayload
            The payload.
        """

    schema = builder.json_schema_from_signature(
        inspect.signature(create_user),
        inspect.getdoc(create_user),  # dedented, as build_registry() uses it
        hints={"user_data": FakeCreateUserPayload},
    )
    inner = schema["properties"]["user_data"]
    assert inner["type"] == "object"
    assert inner["required"] == ["email", "role"]
    # docstring description still attached
    assert inner["description"] == "The payload."


# --- deprecated aliases -------------------------------------------------------


def test_deprecated_alias_detected():
    def get_connections():  # the PEP 702 wrapper pysisense keeps for one minor
        pass

    get_connections.__deprecated__ = "use get_connections_all"
    assert builder._is_deprecated_alias(get_connections) is True

    def get_connections_all():
        pass

    assert builder._is_deprecated_alias(get_connections_all) is False


# --- facade discovery ---------------------------------------------------------


class _FakeFacade:
    __module__ = "pysisense.reports"
    __name__ = "ReportManager"


class _FakePayload(TypedDict):
    x: str


def test_discovery_prefers_facades_tuple():
    sdk = SimpleNamespace(
        FACADES=(_FakeFacade,),
        __all__=["ReportManager", "FakePayload", "SisenseClient"],
        ReportManager=_FakeFacade,
        FakePayload=_FakePayload,
    )
    assert core._discover_facade_classes(sdk) == {"reports": _FakeFacade}


def test_discovery_fallback_skips_typeddicts_and_client():
    class _Client:
        __module__ = "pysisense.sisenseclient"

    sdk = SimpleNamespace(
        __all__=["ReportManager", "FakePayload", "SisenseClient"],
        ReportManager=_FakeFacade,
        FakePayload=_FakePayload,
        SisenseClient=_Client,
    )
    modules = core._discover_facade_classes(sdk)
    assert modules == {"reports": _FakeFacade}  # payload + client excluded


def test_discovery_on_installed_sdk_matches_known_modules():
    modules = core._discover_facade_classes()
    assert {"access_management", "dashboard", "datamodel", "queries"} <= modules.keys()


# --- documented error-return contract ------------------------------------------


def test_error_dict_with_status_code_detected():
    msg = _sdk_error_message({"error": "Forbidden", "status_code": 403})
    assert msg == "Forbidden (HTTP 403)"


def test_list_wrapped_contract_error_detected():
    # Point 6a: a list-wrapped error dict must not sail through as a
    # successful one-row result.
    assert _sdk_error_message([{"error": "nope", "status_code": 401}]) is not None


def test_legit_payload_with_error_field_not_flagged():
    assert _sdk_error_message({"error": "x", "data": [1]}) is None
    assert _sdk_error_message([{"error": "x"}, {"error": "y"}]) is None
