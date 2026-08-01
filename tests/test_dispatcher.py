import pytest

from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from tests.conftest import make_settings


@pytest.fixture
def dispatcher(settings, sample_tools, fake_sdk):
    return SisenseDispatcher(settings, sample_tools)


def test_happy_path(dispatcher):
    result = dispatcher.invoke("dashboard.get_all_dashboards", {})
    assert result == [{"oid": "d1", "title": "Sales"}]


def test_client_built_once_from_settings(dispatcher, fake_sdk):
    dispatcher.invoke("dashboard.get_all_dashboards", {})
    dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": "d1"})
    client = dispatcher._client
    assert client["connection"]["domain"] == "sisense.example.com"
    assert client["connection"]["is_ssl"] is True


def test_unknown_tool(dispatcher):
    with pytest.raises(DispatchError, match="Unknown tool_id"):
        dispatcher.invoke("nope.nothing", {})


def test_missing_creds(sample_tools, fake_sdk):
    d = SisenseDispatcher(make_settings(sisense_domain=None, sisense_token=None), sample_tools)
    with pytest.raises(DispatchError, match="credentials are not configured"):
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


def test_json_string_coercion(dispatcher):
    result = dispatcher.invoke(
        "dashboard.get_dashboard_by_id",
        {"dashboard_id": "d1", "payload": '{"a": 1}'},
    )
    assert result["payload"] == {"a": 1}
