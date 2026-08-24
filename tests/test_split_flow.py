"""End-to-end AS + RS split: fes-auth in front of fes-mcp.

Boots both services (uvicorn threads): the resource server in upstream mode
on one port, fes-auth on another proxying to it. Runs the exact OAuth dance
an MCP client performs — registration → authorize (optionally with a
resource carrying ?target=) → login page → PKCE exchange → tool calls
through the credential-injecting proxy — plus the abuse paths.
"""

import base64
import hashlib
import re
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, quote, urlparse

import httpx
import pytest
import uvicorn
from fastmcp import Client

import fes_mcp.auth as auth_mod
import fes_mcp.upstream as upstream_mod
from fes_mcp.auth import SisenseAuthProvider
from fes_mcp.authserver import build_auth_app
from fes_mcp.server import build_server
from fes_mcp.settings import DEFAULT_REGISTRY_PATH
from fes_mcp.upstream import UpstreamTokenVerifier, upstream_credential_resolver
from tests.conftest import make_settings

REDIRECT_URI = "http://localhost:45678/callback"
TARGET = "https://acme.sisense.com"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(app, port: int):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    return server, thread


class EchoDashboard:
    """Fake pysisense.Dashboard that echoes which credential reached the SDK."""

    def __init__(self, api_client):
        self.api_client = api_client

    def get_all_dashboards(self):
        conn = self.api_client["connection"]
        return {"domain": conn["domain"], "token": conn["token"]}


@pytest.fixture
def split(monkeypatch):
    """Both services running; Sisense itself fully mocked."""
    import pysisense

    monkeypatch.setattr(
        pysisense.SisenseClient,
        "from_connection",
        staticmethod(lambda **kw: {"connection": kw}),
    )
    monkeypatch.setattr(pysisense, "Dashboard", EchoDashboard)

    state = {"minted": {}, "revoked": set()}

    def fake_login(domain, username, password, ssl_verify):
        if password != "hunter2":
            raise auth_mod.SisenseLoginError("Sisense rejected the username/password.")
        token = f"sisense-token-for-{username}"
        state["minted"]["credential"] = (domain, token)
        return token

    def fake_verify(domain, token, ssl_verify):
        if token in state["revoked"] or not token.startswith("sisense-token-for-"):
            raise auth_mod.SisenseLoginError("Sisense did not accept the API token (HTTP 401).")

    monkeypatch.setattr(auth_mod, "login_with_password", fake_login)
    monkeypatch.setattr(upstream_mod, "verify_api_token", fake_verify)

    # Resource server (verify_ttl=0: re-verify every call, so revocation
    # propagates immediately — keeps the self-healing test deterministic).
    rs_port = _free_port()
    rs_settings = make_settings(
        auth_mode="upstream",
        transport="http",
        sisense_domain=None,
        sisense_token=None,
        registry_path=DEFAULT_REGISTRY_PATH,
        allowlist=("dashboard.get_all_dashboards",),
        verify_ttl=0,
    )
    rs = build_server(
        rs_settings,
        credential_resolver=upstream_credential_resolver,
        auth=UpstreamTokenVerifier(rs_settings),
    )
    rs_server, rs_thread = _serve(rs.http_app(), rs_port)

    # Authorization server / proxy.
    as_port = _free_port()
    as_base = f"http://127.0.0.1:{as_port}"
    as_settings = make_settings(
        auth_mode="upstream",
        transport="http",
        rs_url=f"http://127.0.0.1:{rs_port}",
        registry_path=DEFAULT_REGISTRY_PATH,
    )
    provider = SisenseAuthProvider(as_base)
    as_server, as_thread = _serve(build_auth_app(as_settings, provider), as_port)

    yield as_base, state, provider

    as_server.should_exit = True
    rs_server.should_exit = True
    as_thread.join(timeout=5)
    rs_thread.join(timeout=5)


def _run_oauth_dance(base: str, form_fields: dict, resource: str | None = None):
    """Register a client, authorize, submit the login form; return the login
    POST response and context for the token exchange."""
    http = httpx.Client(base_url=base, follow_redirects=False, timeout=10)

    reg = http.post(
        "/register",
        json={
            "client_name": "pytest-claude",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert reg.status_code == 201, reg.text
    client_info = reg.json()

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    params = {
        "response_type": "code",
        "client_id": client_info["client_id"],
        "redirect_uri": REDIRECT_URI,
        "state": "st4te",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if resource is not None:
        params["resource"] = resource
    authz = http.get("/authorize", params=params)
    assert authz.status_code in (302, 307), authz.text
    login_url = authz.headers["location"]
    assert "/login?session=" in login_url

    page = http.get(login_url)
    assert page.status_code == 200
    assert "Connect to Sisense" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)

    session_id = parse_qs(urlparse(login_url).query)["session"][0]
    submit = http.post("/login", data={"session": session_id, "csrf": csrf, **form_fields})
    ctx = {"http": http, "client_info": client_info, "verifier": verifier,
           "session_id": session_id, "csrf": csrf, "login_page": page.text}
    return submit, ctx


def _exchange_code(submit: httpx.Response, ctx: dict) -> dict:
    location = submit.headers["location"]
    assert location.startswith(REDIRECT_URI)
    qs = parse_qs(urlparse(location).query)
    assert qs["state"] == ["st4te"]

    token_resp = ctx["http"].post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": qs["code"][0],
            "redirect_uri": REDIRECT_URI,
            "client_id": ctx["client_info"]["client_id"],
            "client_secret": ctx["client_info"]["client_secret"],
            "code_verifier": ctx["verifier"],
        },
    )
    assert token_resp.status_code == 200, token_resp.text
    return token_resp.json()


async def test_full_flow_with_target(split):
    base, state, _ = split

    submit, ctx = _run_oauth_dance(
        base,
        {"username": "alice@acme.com", "password": "hunter2"},
        resource=f"{base}/mcp?target={quote(TARGET, safe='')}",
    )
    # target present: the login page fixes the instance and asks no domain
    assert 'name="domain"' not in ctx["login_page"]
    assert TARGET in ctx["login_page"]
    assert submit.status_code == 302

    tokens = _exchange_code(submit, ctx)
    assert tokens["token_type"].lower() == "bearer"
    assert state["minted"]["credential"] == (TARGET, "sisense-token-for-alice@acme.com")

    # tool call through the proxy lands on the RS with alice's credential
    async with Client(f"{base}/mcp", auth=tokens["access_token"]) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools] == ["dashboard_get_all_dashboards"]
        res = await client.call_tool("dashboard_get_all_dashboards", {})
        assert res.structured_content == {
            "domain": TARGET,
            "token": "sisense-token-for-alice@acme.com",
        }

    # refresh rotation still maps to the credential; old access token dies
    refreshed = ctx["http"].post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": ctx["client_info"]["client_id"],
            "client_secret": ctx["client_info"]["client_secret"],
        },
    ).json()
    assert refreshed["access_token"] != tokens["access_token"]
    async with Client(f"{base}/mcp", auth=refreshed["access_token"]) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
        assert res.structured_content["domain"] == TARGET

    old = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {tokens['access_token']}",
        },
    )
    assert old.status_code == 401


async def test_full_flow_without_target_shows_domain_field(split):
    base, state, _ = split
    submit, ctx = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "bob@acme.com", "password": "hunter2"},
    )
    assert 'name="domain"' in ctx["login_page"]  # fallback: domain asked
    assert submit.status_code == 302
    tokens = _exchange_code(submit, ctx)
    async with Client(f"{base}/mcp", auth=tokens["access_token"]) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
    assert res.structured_content["domain"] == "https://acme.sisense.com"


async def test_401_challenge_carries_target(split):
    base, _, _ = split
    resp = httpx.post(
        f"{base}/mcp",
        params={"target": TARGET},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert "/.well-known/oauth-protected-resource/mcp?target=" in challenge
    assert quote(TARGET, safe="") in challenge


async def test_prm_route_echoes_target(split):
    base, _, _ = split
    meta = httpx.get(
        f"{base}/.well-known/oauth-protected-resource/mcp", params={"target": TARGET}
    ).json()
    assert meta["resource"] == f"{base}/mcp?target={quote(TARGET, safe='')}"
    assert meta["authorization_servers"] == [base]
    # without target: plain resource
    plain = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp").json()
    assert plain["resource"] == f"{base}/mcp"


async def test_rs_rejection_self_heals(split):
    base, state, provider = split
    submit, ctx = _run_oauth_dance(
        base,
        {"username": "carol@acme.com", "password": "hunter2"},
        resource=f"{base}/mcp?target={quote(TARGET, safe='')}",
    )
    tokens = _exchange_code(submit, ctx)
    access = tokens["access_token"]
    async with Client(f"{base}/mcp", auth=access) as client:
        await client.call_tool("dashboard_get_all_dashboards", {})

    # Sisense-side revocation: RS starts rejecting, AS must drop the vault
    # entry and re-challenge.
    state["revoked"].add("sisense-token-for-carol@acme.com")
    resp = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {access}",
        },
    )
    assert resp.status_code == 401
    assert "www-authenticate" in resp.headers
    assert provider.credential_for(access) is None  # vault entry gone


async def test_unauthenticated_call_rejected(split):
    base, _, _ = split
    resp = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert resp.status_code == 401


async def test_wrong_password_rerenders_form(split):
    base, _, _ = split
    submit, _ = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "wrong"},
    )
    assert submit.status_code == 200
    assert "rejected the username/password" in submit.text


async def test_expired_login_session_rejected(split):
    base, _, _ = split
    page = httpx.get(f"{base}/login", params={"session": "bogus"})
    assert page.status_code == 400
    assert "invalid or has expired" in page.text


async def test_csrf_mismatch_rejected(split):
    base, _, _ = split
    submit, ctx = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "hunter2"},
    )
    assert submit.status_code == 302  # session consumed by the legit submit

    http = httpx.Client(base_url=base, follow_redirects=False, timeout=10)
    reg = ctx["client_info"]
    authz = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": REDIRECT_URI,
            "state": "s",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    session_id = parse_qs(urlparse(authz.headers["location"]).query)["session"][0]
    forged = http.post(
        "/login",
        data={"session": session_id, "csrf": "forged", "domain": "acme.sisense.com",
              "username": "alice@acme.com", "password": "hunter2"},
    )
    assert forged.status_code == 400
    assert "could not be verified" in forged.text


async def test_login_rate_limited(split):
    base, _, _ = split
    http = httpx.Client(base_url=base, follow_redirects=False, timeout=10)
    reg = http.post(
        "/register",
        json={"client_name": "rl", "redirect_uris": [REDIRECT_URI],
              "grant_types": ["authorization_code", "refresh_token"],
              "response_types": ["code"],
              "token_endpoint_auth_method": "client_secret_post"},
    ).json()

    last = None
    for _ in range(7):
        authz = http.get(
            "/authorize",
            params={"response_type": "code", "client_id": reg["client_id"],
                    "redirect_uri": REDIRECT_URI, "state": "s",
                    "code_challenge": "x" * 43, "code_challenge_method": "S256"},
        )
        login_url = authz.headers["location"]
        page = http.get(login_url)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        session_id = parse_qs(urlparse(login_url).query)["session"][0]
        last = http.post(
            "/login",
            data={"session": session_id, "csrf": csrf, "domain": "acme.sisense.com",
                  "username": "alice@acme.com", "password": "wrong"},
        )
    assert last.status_code == 429
    assert "Too many login attempts" in last.text
