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


async def test_iss_in_authorization_response(split):
    # RFC 9207: the redirect back to the client names the issuer, and it must
    # equal the issuer advertised in the AS metadata.
    base, _, _ = split
    issuer = httpx.get(f"{base}/.well-known/oauth-authorization-server").json()["issuer"]
    submit, _ = _run_oauth_dance(
        base, {"domain": "acme.sisense.com", "username": "alice@acme.com", "password": "hunter2"}
    )
    qs = parse_qs(urlparse(submit.headers["location"]).query)
    assert qs["iss"] == [issuer]


async def test_token_bound_to_foreign_resource_rejected(split):
    # RFC 8707 audience enforcement: a token minted for another resource must
    # not work at this server's /mcp, even though it is otherwise valid.
    base, _, _ = split
    submit, ctx = _run_oauth_dance(
        base,
        {"domain": "acme.sisense.com", "username": "mallory@acme.com", "password": "hunter2"},
        resource="https://attacker.example/mcp",
    )
    tokens = _exchange_code(submit, ctx)
    resp = httpx.post(
        f"{base}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {tokens['access_token']}",
        },
    )
    assert resp.status_code == 401


async def test_audience_binding_survives_refresh(split):
    base, _, provider = split
    submit, ctx = _run_oauth_dance(
        base,
        {"username": "dave@acme.com", "password": "hunter2"},
        resource=f"{base}/mcp?target={quote(TARGET, safe='')}",
    )
    tokens = _exchange_code(submit, ctx)
    refreshed = ctx["http"].post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": ctx["client_info"]["client_id"],
            "client_secret": ctx["client_info"]["client_secret"],
        },
    ).json()
    stored = provider.access_tokens[refreshed["access_token"]]
    assert str(stored.resource).startswith(f"{base}/mcp")
    async with Client(f"{base}/mcp", auth=refreshed["access_token"]) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
        assert res.is_error is False


async def test_register_rate_limited(split):
    base, _, _ = split
    reg_body = {
        "client_name": "spam",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }
    from fes_mcp.authserver import _RegisterThrottleMiddleware

    limit = _RegisterThrottleMiddleware.REGISTRATIONS_PER_IP_PER_HOUR
    statuses = [
        httpx.post(f"{base}/register", json=reg_body).status_code
        for _ in range(limit + 1)
    ]
    assert statuses[:limit] == [201] * limit
    assert statuses[limit] == 429


async def test_login_page_names_client_and_redirect(split):
    # Consent-phishing defense: the page must say which OAuth client asked
    # and where the browser is sent afterwards.
    base, _, _ = split
    submit, ctx = _run_oauth_dance(
        base, {"domain": TARGET, "username": "u@x.com", "password": "hunter2"}
    )
    assert "pytest-claude" in ctx["login_page"]
    assert urlparse(REDIRECT_URI).netloc in ctx["login_page"]
    assert submit.status_code == 302


async def test_refresh_token_gets_absolute_expiry(split):
    base, _, provider = split
    submit, ctx = _run_oauth_dance(
        base, {"domain": TARGET, "username": "u@x.com", "password": "hunter2"}
    )
    token = _exchange_code(submit, ctx)
    refresh = provider.refresh_tokens[token["refresh_token"]]
    assert refresh.expires_at is not None
    assert refresh.expires_at <= time.time() + auth_mod.REFRESH_TOKEN_TTL_SECONDS + 5


async def test_login_refuses_disallowed_origin():
    provider = SisenseAuthProvider(
        "http://127.0.0.1:1", allowed_origins=("https://ok.sisense.com",)
    )
    with pytest.raises(auth_mod.SisenseLoginError, match="not configured"):
        provider._authenticate_form(
            "https://evil.example", "u@x.com", "pw", "", False
        )


def test_client_ip_uses_rightmost_forwarded_entry():
    # The leftmost X-Forwarded-For entries are client-supplied (spoofable);
    # the rightmost is appended by our own proxy.
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-forwarded-for", b"6.6.6.6, 9.9.9.9")],
        "client": ("10.0.0.1", 1234),
    }
    assert auth_mod._client_ip(Request(scope)) == "9.9.9.9"

    # Behind Cloudflare the rightmost XFF entry is a shared edge IP;
    # CF-Connecting-IP carries the real client and wins.
    scope["headers"] = [
        (b"x-forwarded-for", b"6.6.6.6, 172.68.0.1"),
        (b"cf-connecting-ip", b"7.7.7.7"),
    ]
    assert auth_mod._client_ip(Request(scope)) == "7.7.7.7"


def test_sweep_evicts_dead_state_but_keeps_refreshable_sessions():
    from mcp.server.auth.provider import AuthorizationCode as Code
    from mcp.server.auth.provider import RefreshToken as Refresh
    from fastmcp.server.auth.auth import AccessToken as Access

    from fes_mcp.credentials import SisenseCredential

    provider = SisenseAuthProvider("http://127.0.0.1:1")
    cred = SisenseCredential(domain=TARGET, token="t")
    past, future = time.time() - 10, time.time() + 3600

    provider.auth_codes["dead-code"] = Code(
        code="dead-code", client_id="c", redirect_uri=REDIRECT_URI,
        redirect_uri_provided_explicitly=True, scopes=[], expires_at=past,
        code_challenge="x",
    )
    provider._credentials["dead-code"] = cred

    provider.access_tokens["dead-access"] = Access(
        token="dead-access", client_id="c", scopes=[], expires_at=int(past)
    )
    provider._credentials["dead-access"] = cred

    provider.access_tokens["live-session"] = Access(
        token="live-session", client_id="c", scopes=[], expires_at=int(past)
    )
    provider._credentials["live-session"] = cred
    provider.refresh_tokens["live-refresh"] = Refresh(
        token="live-refresh", client_id="c", scopes=[], expires_at=int(future)
    )
    provider._access_to_refresh_map["live-session"] = "live-refresh"
    provider._refresh_to_access_map["live-refresh"] = "live-session"
    provider._credentials["live-refresh"] = cred

    provider._sweep_expired_tokens()

    assert "dead-code" not in provider.auth_codes
    assert "dead-code" not in provider._credentials
    assert "dead-access" not in provider.access_tokens
    assert "dead-access" not in provider._credentials
    # Expired access token with a live refresh token survives: it carries the
    # RFC 8707 resource binding that rotation copies forward.
    assert "live-session" in provider.access_tokens
    assert "live-refresh" in provider.refresh_tokens


def test_client_supplied_sisense_url_never_forwarded():
    from fes_mcp.authserver import _SKIP_REQUEST_HEADERS

    assert "x-sisense-url" in _SKIP_REQUEST_HEADERS
    assert "x-forwarded-for" in _SKIP_REQUEST_HEADERS


async def test_browser_get_mcp_gets_explanation_not_bare_401(split):
    base, _, _ = split
    async with httpx.AsyncClient() as http:
        page = await http.get(f"{base}/mcp", headers={"accept": "text/html,*/*"})
        assert page.status_code == 200
        assert "MCP endpoint" in page.text
        # MCP clients are unaffected: no text/html accept -> the challenge.
        sse = await http.get(f"{base}/mcp", headers={"accept": "text/event-stream"})
        assert sse.status_code == 401
        assert "resource_metadata" in sse.headers["www-authenticate"]


async def test_as_metadata_issuer_has_no_trailing_slash(split):
    # RFC 8414 §3.3: issuer must byte-match the URL the client derived the
    # metadata from. Strict clients (MCP Inspector) refuse a trailing slash.
    base, _, _ = split
    async with httpx.AsyncClient() as http:
        meta = (await http.get(f"{base}/.well-known/oauth-authorization-server")).json()
    assert meta["issuer"] == base  # no trailing slash

    # The RFC 9207 iss parameter must byte-match the metadata issuer.
    submit, _ = _run_oauth_dance(
        base, {"domain": TARGET, "username": "u@x.com", "password": "hunter2"}
    )
    iss = parse_qs(urlparse(submit.headers["location"]).query)["iss"][0]
    assert iss == meta["issuer"]


# ---- CIMD (Client ID Metadata Documents) ------------------------------------

CIMD_URL = "https://client.example/claude-cimd.json"


def _fake_cimd_fetch(monkeypatch):
    from fastmcp.server.auth.cimd import CIMDDocument, CIMDFetcher

    doc = CIMDDocument(
        client_id=CIMD_URL,
        client_name="Claude (CIMD test)",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
    )

    async def fake_fetch(self, client_id_url):
        assert client_id_url == CIMD_URL
        return doc

    monkeypatch.setattr(CIMDFetcher, "fetch", fake_fetch)


async def test_metadata_advertises_cimd(split):
    base, _, _ = split
    async with httpx.AsyncClient() as http:
        meta = (await http.get(f"{base}/.well-known/oauth-authorization-server")).json()
    assert meta["client_id_metadata_document_supported"] is True
    assert "none" in meta["token_endpoint_auth_methods_supported"]


async def test_cimd_client_full_flow(split, monkeypatch):
    # A CIMD client never registers: its client_id IS its metadata URL, and
    # it authenticates at /token as a public client (PKCE only).
    base, _, _ = split
    _fake_cimd_fetch(monkeypatch)
    http = httpx.Client(base_url=base, follow_redirects=False, timeout=10)

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    authz = http.get("/authorize", params={
        "response_type": "code",
        "client_id": CIMD_URL,
        "redirect_uri": REDIRECT_URI,
        "state": "st4te",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    assert authz.status_code in (302, 307), authz.text
    login_url = authz.headers["location"]
    page = http.get(login_url)
    assert "Claude (CIMD test)" in page.text  # consent banner names the client
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    session_id = parse_qs(urlparse(login_url).query)["session"][0]

    submit = http.post("/login", data={
        "session": session_id, "csrf": csrf,
        "domain": TARGET, "username": "u@x.com", "password": "hunter2",
    })
    assert submit.status_code == 302, submit.text
    code = parse_qs(urlparse(submit.headers["location"]).query)["code"][0]

    token_resp = http.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CIMD_URL,  # no client_secret: public client
        "code_verifier": verifier,
    })
    assert token_resp.status_code == 200, token_resp.text
    token = token_resp.json()
    assert token["access_token"]

    # The token works end-to-end through the credential-injecting proxy.
    init = http.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token['access_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "cimd-test", "version": "0"},
            },
        },
    )
    assert init.status_code == 200, init.text
    assert "sisense-fes" in init.text  # serverInfo reached through the proxy


def test_cimd_beta_api_drift_guard():
    # Our provider consumes fastmcp's beta CIMD surface; fail loudly if an
    # upgrade reshapes it (see SisenseAuthProvider.get_client).
    from fastmcp.server.auth.cimd import CIMDClientManager, CIMDDocument, CIMDFetcher

    manager = CIMDClientManager(enable_cimd=True)
    assert manager.is_cimd_client_id("https://x.example/doc.json") is True
    assert manager.is_cimd_client_id("plain-client-id") is False
    assert callable(getattr(manager, "get_client"))
    assert callable(getattr(CIMDFetcher, "fetch"))
    doc = CIMDDocument(client_id="https://x.example/doc.json", redirect_uris=["https://x.example/cb"])
    assert doc.token_endpoint_auth_method == "none"  # public client default


def test_origin_allowed_patterns():
    from fes_mcp.auth import origin_allowed

    allowed = ("*.sisense.com", "http://10.185.1.92", "https://onprem.example")
    # wildcard: any HTTPS subdomain of sisense.com
    assert origin_allowed("https://acme.sisense.com", allowed)
    assert origin_allowed("https://deep.sub.sisense.com", allowed)
    # wildcard never sanctions plaintext, lookalikes, or the bare apex
    assert not origin_allowed("http://acme.sisense.com", allowed)
    assert not origin_allowed("https://evilsisense.com", allowed)
    assert not origin_allowed("https://sisense.com", allowed)
    # exact entries: scheme-faithful
    assert origin_allowed("http://10.185.1.92", allowed)
    assert not origin_allowed("https://10.185.1.92", allowed)
    assert origin_allowed("https://onprem.example", allowed)
    assert not origin_allowed("https://attacker.example", allowed)
    # unset = accept any; empty tuple = refuse all
    assert origin_allowed("https://anything.example", None)
    assert not origin_allowed("https://anything.example", ())
