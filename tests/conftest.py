import pytest

from fes_mcp.settings import Settings


def make_settings(**overrides) -> Settings:
    defaults = dict(
        sisense_domain="sisense.example.com",
        sisense_token="test-token",
        sisense_ssl_verify=True,
        auth_mode="none",
        bearer_token=None,
        allowlist=(),
        allow_mutations=False,
        transport="stdio",
        host="127.0.0.1",
        port=8200,
        registry_path=None,
        log_level="WARNING",
    )
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def sample_tools():
    """Minimal registry entries covering read, write, and args-required cases."""
    return {
        "dashboard.get_all_dashboards": {
            "tool_id": "dashboard.get_all_dashboards",
            "module": "dashboard",
            "class": "Dashboard",
            "method": "get_all_dashboards",
            "description": "Retrieve all dashboards.",
            "mutates": False,
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        "dashboard.get_dashboard_by_id": {
            "tool_id": "dashboard.get_dashboard_by_id",
            "module": "dashboard",
            "class": "Dashboard",
            "method": "get_dashboard_by_id",
            "description": "Retrieve one dashboard.",
            "mutates": False,
            "parameters": {
                "type": "object",
                "properties": {"dashboard_id": {"type": "string"}},
                "required": ["dashboard_id"],
            },
        },
        "dashboard.delete_dashboard": {
            "tool_id": "dashboard.delete_dashboard",
            "module": "dashboard",
            "class": "Dashboard",
            "method": "delete_dashboard",
            "description": "Delete a dashboard.",
            "mutates": True,
            "parameters": {
                "type": "object",
                "properties": {"dashboard_id": {"type": "string"}},
                "required": ["dashboard_id"],
            },
        },
    }


class FakeDashboard:
    """Stands in for pysisense.Dashboard."""

    def __init__(self, api_client):
        self.api_client = api_client
        self.calls = []

    def get_all_dashboards(self):
        return [{"oid": "d1", "title": "Sales"}]

    def get_dashboard_by_id(self, dashboard_id, payload=None):
        self.calls.append(("get_dashboard_by_id", dashboard_id, payload))
        if dashboard_id == "missing":
            return {"error": "Dashboard not found"}
        return {"oid": dashboard_id, "title": "Sales", "payload": payload}

    def delete_dashboard(self, dashboard_id):
        return "deleted"


@pytest.fixture
def fake_sdk(monkeypatch):
    """Patch pysisense so no real client or network is involved."""
    import pysisense

    monkeypatch.setattr(
        pysisense.SisenseClient,
        "from_connection",
        staticmethod(lambda **kw: {"connection": kw}),
    )
    monkeypatch.setattr(pysisense, "Dashboard", FakeDashboard)
    return pysisense
