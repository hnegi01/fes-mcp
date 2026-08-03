import pytest

from fes_mcp.credentials import SisenseCredential
from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from tests.conftest import make_settings


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


def test_json_string_coercion(dispatcher):
    result = dispatcher.invoke(
        "dashboard.get_dashboard_by_id",
        {"dashboard_id": "d1", "payload": '{"a": 1}'},
    )
    assert result["payload"] == {"a": 1}
