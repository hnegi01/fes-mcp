"""End-to-end OAuth 2.1 flow against a real HTTP server instance.

Simulates exactly what Claude does when a user adds the connector:
dynamic client registration → /authorize → login page → Sisense login
(mocked) → authorization code → PKCE token exchange → authenticated
tools/call running with the logged-in user's credential.
"""

import base64
import hashlib
import re
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn
from fastmcp import Client

import fes_mcp.auth as auth_mod
from fes_mcp.auth import SisenseAuthProvider, make_credential_resolver
from fes_mcp.server import build_server
from fes_mcp.settings import DEFAULT_REGISTRY_PATH
from tests.conftest import make_settings

REDIRECT_URI = "http://localhost:45678/callback"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def oauth_server(fake_sdk, monkeypatch):
    """A running fes-mcp HTTP server in oauth mode, Sisense login mocked."""
    minted = {}

    def fake_login(domain, username, password, ssl_verify):
        if password != "hunter2":
            raise auth_mod.SisenseLoginError("Sisense rejected the username/password.")
        token = f"sisense-token-for-{username}"
        minted["credential"] = (domain, token)
        return token

    monkeypatch.setattr(auth_mod, "login_with_password", fake_login)

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    settings = make_settings(
        auth_mode="oauth",
        transport="http",
        sisense_domain=None,  # oauth mode: no env credential
        sisense_token=None,
        registry_path=DEFAULT_REGISTRY_PATH,
        allowlist=("dashboard.get_all_dashboards",),
    )
    provider = SisenseAuthProvider(base)
    mcp = build_server(
        settings, credential_resolver=make_credential_resolver(provider), auth=provider
    )
    app = mcp.http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)

    yield base, minted

    server.should_exit = True
    thread.join(timeout=5)


def _run_oauth_dance(base: str, form_fields: dict) -> tuple[httpx.Response, dict]:
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
    authz = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_info["client_id"],
            "redirect_uri": REDIRECT_URI,
            "state": "st4te",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
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
           "session_id": session_id, "csrf": csrf}
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


async def test_full_flow_password_login(oauth_server):
    base, minted = oauth_server

    submit, ctx = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "hunter2"},
    )
    assert submit.status_code == 302
    tokens = _exchange_code(submit, ctx)
    assert tokens["token_type"].lower() == "bearer"
    assert tokens["refresh_token"]

    # domain got normalized, Sisense token minted via the (mocked) login API
    assert minted["credential"] == ("https://acme.sisense.com", "sisense-token-for-alice@acme.com")

    # authenticated tool call runs with alice's credential (fake SDK echoes it)
    async with Client(f"{base}/mcp", auth=tokens["access_token"]) as client:
        tools = await client.list_tools()
        assert [t.name for t in tools] == ["dashboard_get_all_dashboards"]
        res = await client.call_tool("dashboard_get_all_dashboards", {})
        assert res.is_error is False

    # refresh rotation: new tokens keep working, old access token dies,
    # and the Sisense credential mapping survives the rotation
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
        assert res.is_error is False

    old = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {tokens['access_token']}",
        },
    )
    assert old.status_code == 401


async def test_unauthenticated_call_rejected(oauth_server):
    base, _ = oauth_server
    resp = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert resp.status_code == 401


async def test_wrong_password_rerenders_form(oauth_server):
    base, _ = oauth_server
    submit, _ = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "wrong"},
    )
    assert submit.status_code == 200
    assert "rejected the username/password" in submit.text


async def test_expired_login_session_rejected(oauth_server):
    base, _ = oauth_server
    http = httpx.Client(base_url=base, timeout=10)
    page = http.get("/login", params={"session": "bogus"})
    assert page.status_code == 400
    assert "invalid or has expired" in page.text


async def test_csrf_mismatch_rejected(oauth_server):
    base, _ = oauth_server
    submit, ctx = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "hunter2"},
    )
    assert submit.status_code == 302  # session consumed by the legit submit

    # a fresh dance, but the POST carries a forged csrf token
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


async def test_login_rate_limited(oauth_server):
    base, _ = oauth_server
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
