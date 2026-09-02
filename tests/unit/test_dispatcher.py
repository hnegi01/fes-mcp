import pytest

from fes_mcp.credentials import SisenseCredential
from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from tests.conftest import make_settings


def _resolver_calls():
    # The class actually patched in (conftest is imported under two module
    # names by pytest, so grab the live one from pysisense).
    import pysisense

    return pysisense.Dashboard.resolver_calls


@pytest.fixture
def dispatcher(settings, sample_tools, fake_sdk):
    return SisenseDispatcher(settings, sample_tools)


def test_happy_path(dispatcher):
    result = dispatcher.invoke("dashboard.get_all_dashboards", {})
    assert result == [{"oid": "d1", "title": "Sales"}]


def test_env_fallback_client_reused(dispatcher, fake_sdk):
    dispatcher.invoke("dashboard.get_all_dashboards", {})
    dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "d1"})
    assert len(dispatcher._bundles) == 1
    bundle = next(iter(dispatcher._bundles.values()))
    assert bundle.client["connection"]["domain"] == "sisense.example.com"
    assert bundle.client["connection"]["is_ssl"] is True


def test_per_credential_clients_are_isolated(dispatcher, fake_sdk):
    alice = SisenseCredential(domain="a.sisense.com", token="tok-a")
    bob = SisenseCredential(domain="b.sisense.com", token="tok-b", ssl_verify=False)
    dispatcher.invoke("dashboard.get_all_dashboards", {}, credential=alice)
    dispatcher.invoke("dashboard.get_all_dashboards", {}, credential=bob)
    dispatcher.invoke("dashboard.get_all_dashboards", {}, credential=alice)  # cache hit
    assert len(dispatcher._bundles) == 2
    domains = {b.client["connection"]["domain"] for b in dispatcher._bundles.values()}
    assert domains == {"a.sisense.com", "b.sisense.com"}


def test_evict_drops_cached_client(dispatcher, fake_sdk):
    alice = SisenseCredential(domain="a.sisense.com", token="tok-a")
    dispatcher.invoke("dashboard.get_all_dashboards", {}, credential=alice)
    assert len(dispatcher._bundles) == 1
    dispatcher.evict(alice)
    assert len(dispatcher._bundles) == 0


def test_unknown_tool(dispatcher):
    with pytest.raises(DispatchError, match="Unknown tool_id"):
        dispatcher.invoke("nope.nothing", {})


def test_no_credential_and_no_env(sample_tools, fake_sdk):
    d = SisenseDispatcher(make_settings(sisense_domain=None, sisense_token=None), sample_tools)
    with pytest.raises(DispatchError, match="No Sisense credential"):
        d.invoke("dashboard.get_all_dashboards", {})


def test_missing_required_arg(dispatcher):
    with pytest.raises(DispatchError, match="dashboard_id.*required|required.*dashboard_id"):
        dispatcher.invoke("dashboard.get_dashboard_by_id", {})


def test_wrong_arg_type(dispatcher):
    with pytest.raises(DispatchError, match="not of type 'string'"):
        dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": 42})


def test_mutation_blocked_by_default(dispatcher):
    with pytest.raises(DispatchError, match="mutations are disabled"):
        dispatcher.invoke("dashboard.delete_dashboard", {"dashboard_id": "d1"})


def test_mutation_allowed_when_enabled(sample_tools, fake_sdk):
    d = SisenseDispatcher(make_settings(allow_mutations=True), sample_tools)
    assert d.invoke("dashboard.delete_dashboard", {"dashboard_id": "d1"}) == "deleted"


def test_sdk_error_payload_becomes_error(dispatcher):
    with pytest.raises(DispatchError, match="Dashboard not found"):
        dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "missing"})


def test_json_string_coercion_is_schema_aware(dispatcher):
    # A free-form param gets stringified JSON parsed back into structure...
    result = dispatcher.invoke(
        "dashboard.get_dashboard_by_id",
        {"dashboard_id": "d1", "payload": '{"a": 1}'},
    )
    assert result["payload"] == {"a": 1}
    # ...but a declared string param passes through even when it looks like
    # JSON — a genuine title such as "[1,2]" must never be mangled.
    from fes_mcp.dispatcher import _coerce_json_strings

    schema = {"properties": {"title": {"type": "string"}, "data": {"type": "object"}}}
    out = _coerce_json_strings({"title": "[1,2]", "data": '{"x": 1}'}, schema)
    assert out == {"title": "[1,2]", "data": {"x": 1}}


def test_error_string_result_becomes_error(dispatcher):
    # A few SDK methods return bare "Error: ..." strings instead of dicts.
    with pytest.raises(DispatchError, match="Error: boom"):
        dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "str-error"})


# --- ID-or-title reference resolution ---------------------------------------


def test_dashboard_title_resolves_to_id(dispatcher):
    result = dispatcher.invoke(
        "dashboard.get_dashboard_by_id", {"dashboard_id": "Sales Overview"}
    )
    assert result["oid"] == "a" * 24
    assert _resolver_calls() == ["Sales Overview"]


def test_hex24_dashboard_id_skips_resolver(dispatcher):
    dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "c" * 24})
    assert _resolver_calls() == []


def test_unresolvable_dashboard_is_clear_error(dispatcher):
    with pytest.raises(DispatchError, match="Could not resolve dashboard"):
        dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "Nonexistent"})


DATAMODEL_TOOL = {
    "datamodel.describe_datamodel": {
        "tool_id": "datamodel.describe_datamodel",
        "module": "datamodel",
        "class": "DataModel",
        "method": "describe_datamodel",
        "description": "Describe a data model.",
        "mutates": False,
        "parameters": {
            "type": "object",
            "properties": {"datamodel_name": {"type": "string"}},
            "required": ["datamodel_name"],
        },
    }
}


class FakeDataModel:
    def __init__(self, api_client):
        self.api_client = api_client

    def resolve_datamodel_reference(self, datamodel_ref):
        return {"success": True, "status_code": 200, "datamodel_id": datamodel_ref,
                "datamodel_title": "Sales Cube", "error": None}

    def describe_datamodel(self, datamodel_name):
        return {"title": datamodel_name}


def test_datamodel_id_resolves_to_title(settings, fake_sdk, monkeypatch):
    import pysisense

    monkeypatch.setattr(pysisense, "DataModel", FakeDataModel, raising=False)
    d = SisenseDispatcher(settings, DATAMODEL_TOOL)
    guid = "12345678-abcd-abcd-abcd-1234567890ab"
    assert d.invoke("datamodel.describe_datamodel", {"datamodel_name": guid}) == {
        "title": "Sales Cube"
    }
    # a plain title passes through untouched
    assert d.invoke("datamodel.describe_datamodel", {"datamodel_name": "My Cube"}) == {
        "title": "My Cube"
    }


def test_client_wiring_scheme_drives_is_ssl_checkbox_drives_verify(fake_sdk):
    # PySisense's is_ssl is scheme/port selection (https:443 vs http:30845);
    # verify_ssl is certificate verification. The credential's ssl_verify flag
    # (the "self-signed certificate" checkbox) must land on verify_ssl only.
    from fes_mcp.credentials import SisenseCredential
    from fes_mcp.dispatcher import _ClientBundle

    self_signed = _ClientBundle(
        SisenseCredential(domain="https://acme.sisense.com", token="t", ssl_verify=False)
    )
    conn = self_signed.client["connection"]
    assert conn["is_ssl"] is True
    assert conn["verify_ssl"] is False

    http_box = _ClientBundle(
        SisenseCredential(domain="http://10.0.0.5", token="t", ssl_verify=True)
    )
    conn = http_box.client["connection"]
    assert conn["is_ssl"] is False
    assert conn["verify_ssl"] is True
