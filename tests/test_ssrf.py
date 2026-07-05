"""Tests for the SSRF protection middleware and connector."""

import inspect
from ipaddress import ip_address
from typing import cast
from unittest import mock

import pytest
from aiohttp import ClientRequest, ClientResponse, ClientSession, TCPConnector, web
from aiohttp.abc import ResolveResult
from pytest_aiohttp import AiohttpClient, AiohttpServer
from yarl import URL

from aiohttp_client_middlewares.ssrf import (
    SSRFConnector,
    SSRFError,
    SSRFMiddleware,
    _normalize_host,
    is_unsafe_address,
)


async def _ok_handler(request: web.Request) -> web.Response:
    return web.Response(text="OK")


def _ok_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api", _ok_handler)
    return app


def _fake_request(url: str) -> ClientRequest:
    """A stand-in ``ClientRequest`` exposing just ``.url``."""
    req = mock.Mock()
    req.url = URL(url)
    return cast(ClientRequest, req)


async def _passing_handler(request: ClientRequest) -> ClientResponse:
    return cast(ClientResponse, mock.Mock())


async def _forbidden_handler(request: ClientRequest) -> ClientResponse:
    raise AssertionError("the middleware must reject before calling the handler")


async def _middleware_call_ok(url: str, middleware: SSRFMiddleware) -> ClientResponse:
    """Run *middleware* on *url* with a handler that must be reached."""
    return await middleware(_fake_request(url), _passing_handler)


def _fake_results(*ips: str) -> "list[ResolveResult]":
    return [
        cast(
            ResolveResult,
            {
                "hostname": "example.com",
                "host": ip,
                "port": 80,
                "family": 0,
                "proto": 0,
                "flags": 0,
            },
        )
        for ip in ips
    ]


# --- Address classification ---------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "10.0.0.1",  # private
        "172.16.0.1",  # private
        "192.168.1.1",  # private
        "169.254.169.254",  # link-local + cloud metadata endpoint
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "100.64.0.1",  # carrier-grade NAT (is_private and is_global both False)
        "192.88.99.1",  # 6to4 relay anycast (ipaddress reports is_global=True)
        "198.18.0.1",  # benchmarking, not globally routable
        "192.0.2.1",  # TEST-NET-1
        "::1",  # IPv6 loopback
        "::",  # IPv6 unspecified
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # unique-local
        "fd00:ec2::254",  # AWS IPv6 metadata endpoint (unique-local)
        "ff02::1",  # IPv6 multicast
        "64:ff9b::808:808",  # NAT64-mapped: routes into an IPv4 translator
        "64:ff9b:1::1",  # NAT64 local-use
        "2002:808:808::1",  # 6to4: embeds an arbitrary IPv4 address
        "2001::1",  # Teredo: embeds an arbitrary IPv4 address
        "3fff::1",  # RFC 9637 documentation range (is_global varies by version)
        "3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff",  # RFC 9637 range, upper end
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "::ffff:169.254.169.254",  # IPv4-mapped metadata endpoint
        "not-an-ip-address",  # unparsable input fails closed
    ],
)
def test_unsafe_addresses_blocked(address: str) -> None:
    """Internal, special-purpose, and unparsable addresses are unsafe."""
    assert is_unsafe_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "2600:1901::1",
        "::ffff:8.8.8.8",  # IPv4-mapped *public* address is judged as 8.8.8.8
    ],
)
def test_public_addresses_allowed(address: str) -> None:
    """Globally-routable public addresses are not flagged."""
    assert not is_unsafe_address(address)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("EXAMPLE.com.", "example.com"),  # lowercased, trailing dot stripped
        ("☃.internal", "xn--n3h.internal"),  # Unicode -> punycode
        ("xn--n3h.internal", "xn--n3h.internal"),  # already punycode (idempotent)
        ("127.0.0.1", "127.0.0.1"),  # IP literal untouched
        ("a" * 70 + ".example", "a" * 70 + ".example"),  # un-encodable -> fallback
    ],
)
def test_normalize_host(host: str, expected: str) -> None:
    """Hosts fold to a single IDNA/case/dot form; bad input falls back as-is."""
    assert _normalize_host(host) == expected


def test_classifier_accepts_address_objects() -> None:
    """``IPv4Address``/``IPv6Address`` inputs work the same as strings."""
    assert is_unsafe_address(ip_address("10.0.0.1"))
    assert not is_unsafe_address(ip_address("2606:4700:4700::1111"))


def test_ssrf_error_carries_host_and_reason() -> None:
    """The exception exposes what was blocked and why."""
    err = SSRFError("victim.internal", "resolved to non-public address")
    assert err.host == "victim.internal"
    assert err.reason == "resolved to non-public address"
    assert "victim.internal" in str(err)


# --- Middleware (URL-level rules; no network needed) --------------------------


async def test_middleware_rejects_disallowed_scheme() -> None:
    """Schemes outside ``allowed_schemes`` are rejected before the handler."""
    middleware = SSRFMiddleware()
    with pytest.raises(SSRFError, match="scheme"):
        await middleware(_fake_request("ftp://example.com/file"), _forbidden_handler)


async def test_middleware_custom_schemes() -> None:
    """A custom ``allowed_schemes`` replaces the default set."""
    middleware = SSRFMiddleware(allowed_schemes=("https",))
    with pytest.raises(SSRFError, match="scheme"):
        await middleware(_fake_request("http://example.com/"), _forbidden_handler)


async def test_middleware_rejects_missing_host() -> None:
    """A URL without a host cannot be validated and is rejected."""
    middleware = SSRFMiddleware()
    req = mock.Mock()
    req.url.scheme = "http"
    req.url.host = None
    with pytest.raises(SSRFError, match="no host"):
        await middleware(cast(ClientRequest, req), _forbidden_handler)


async def test_middleware_passes_plain_hostname() -> None:
    """With no rules, a hostname URL passes through to the handler."""
    middleware = SSRFMiddleware()
    response = await middleware(
        _fake_request("http://example.com/path"), _passing_handler
    )
    assert response is not None


async def test_middleware_blocks_unsafe_literal_ip() -> None:
    """A literal internal IP is rejected without waiting for the connector."""
    middleware = SSRFMiddleware()
    with pytest.raises(SSRFError, match="not publicly routable"):
        await middleware(
            _fake_request("http://169.254.169.254/latest/meta-data/"),
            _forbidden_handler,
        )


async def test_middleware_passes_public_literal_ip() -> None:
    """A literal public IP passes the default rules."""
    response = await _middleware_call_ok("http://8.8.8.8/", SSRFMiddleware())
    assert response is not None


@pytest.mark.parametrize(
    "url",
    ["http://victim.com/", "http://VICTIM.COM./steal"],
)
async def test_middleware_denylist_matches_exact_host(url: str) -> None:
    """Denylisted hostnames match case-insensitively, ignoring a trailing dot."""
    middleware = SSRFMiddleware(denylist=["victim.com"])
    with pytest.raises(SSRFError, match="denylisted"):
        await middleware(_fake_request(url), _forbidden_handler)


@pytest.mark.parametrize(
    "url",
    ["http://notvictim.com/", "http://victim.com.evil.example/"],
)
async def test_middleware_denylist_is_anchored(url: str) -> None:
    """A denylist entry never matches by substring or suffix."""
    middleware = SSRFMiddleware(denylist=["victim.com"])
    response = await _middleware_call_ok(url, middleware)
    assert response is not None


async def test_middleware_denylist_cidr_blocks_literal_ip() -> None:
    """A CIDR denylist entry blocks literal-IP hosts inside it."""
    middleware = SSRFMiddleware(denylist=["8.8.8.0/24"])
    with pytest.raises(SSRFError, match="denylisted"):
        await middleware(_fake_request("http://8.8.8.8/"), _forbidden_handler)


async def test_middleware_denylist_wins_over_allowlist() -> None:
    """The denylist is checked before the allowlist."""
    middleware = SSRFMiddleware(allowlist=["example.com"], denylist=["example.com"])
    with pytest.raises(SSRFError, match="denylisted"):
        await middleware(_fake_request("http://example.com/"), _forbidden_handler)


async def test_middleware_allowlist_mode() -> None:
    """With an allowlist, only matching hosts pass; everything else fails."""
    middleware = SSRFMiddleware(allowlist=["api.example.com"])
    response = await _middleware_call_ok("http://api.example.com/v1", middleware)
    assert response is not None
    with pytest.raises(SSRFError, match="not on the allowlist"):
        await middleware(_fake_request("http://other.example.com/"), _forbidden_handler)


async def test_middleware_allowlist_cidr_overrides_unsafe_check() -> None:
    """An allowlisted internal literal IP is deliberately reachable."""
    middleware = SSRFMiddleware(allowlist=["192.0.2.0/24"])
    response = await _middleware_call_ok("http://192.0.2.1/", middleware)
    assert response is not None
    with pytest.raises(SSRFError, match="not on the allowlist"):
        await middleware(_fake_request("http://8.8.8.8/"), _forbidden_handler)


async def test_one_idn_rule_matches_both_layers() -> None:
    """A single Unicode IDN rule matches in the connector and the middleware.

    The connector receives the punycode ``raw_host`` while the middleware
    receives the Unicode ``host``; IDNA-normalizing both the rule and the host
    lets one entry cover both. Without normalization the rule would silently
    no-op in one layer.
    """
    # Middleware sees the Unicode host.
    middleware = SSRFMiddleware(denylist=["☃.example"])  # ☃.example
    with pytest.raises(SSRFError, match="denylisted"):
        await middleware(_fake_request("http://☃.example/"), _forbidden_handler)

    # Connector sees the punycode host aiohttp passes to _resolve_host.
    connector = SSRFConnector(allowlist=["☃.internal"])  # ☃.internal
    try:
        with mock.patch.object(
            TCPConnector,
            "_resolve_host",
            mock.AsyncMock(return_value=_fake_results("10.0.0.5")),
        ):
            resolved = await connector._resolve_host("xn--n3h.internal", 80)
            assert len(resolved) == 1  # allowlisted -> internal address exempt
    finally:
        await connector.close()


# --- Connector (resolved-address rules) ---------------------------------------


async def test_connector_blocks_private_resolution() -> None:
    """A hostname resolving to a private address is refused."""
    connector = SSRFConnector()
    try:
        with mock.patch.object(
            TCPConnector,
            "_resolve_host",
            mock.AsyncMock(return_value=_fake_results("10.0.0.5")),
        ):
            with pytest.raises(SSRFError, match="10.0.0.5"):
                await connector._resolve_host("internal.example.com", 80)
    finally:
        await connector.close()


async def test_connector_passes_public_resolution() -> None:
    """Public resolved addresses are returned untouched."""
    connector = SSRFConnector()
    results = _fake_results("93.184.216.34")
    try:
        with mock.patch.object(
            TCPConnector, "_resolve_host", mock.AsyncMock(return_value=results)
        ):
            assert await connector._resolve_host("example.com", 80) == results
    finally:
        await connector.close()


async def test_connector_fails_closed_on_unparsable_result() -> None:
    """A resolver result that is not a numeric address is refused."""
    connector = SSRFConnector()
    try:
        with mock.patch.object(
            TCPConnector,
            "_resolve_host",
            mock.AsyncMock(return_value=_fake_results("garbage")),
        ):
            with pytest.raises(SSRFError, match="garbage"):
                await connector._resolve_host("example.com", 80)
    finally:
        await connector.close()


async def test_connector_allowlisted_hostname_skips_checks() -> None:
    """An allowlisted hostname is trusted regardless of what it resolves to."""
    connector = SSRFConnector(allowlist=["internal.example.com"])
    results = _fake_results("10.0.0.5")
    try:
        with mock.patch.object(
            TCPConnector, "_resolve_host", mock.AsyncMock(return_value=results)
        ):
            resolved = await connector._resolve_host("INTERNAL.example.COM.", 80)
            assert resolved == results
    finally:
        await connector.close()


async def test_connector_allowlisted_network_permits_addresses_inside_it() -> None:
    """A CIDR allowlist entry exempts resolved addresses inside it only."""
    connector = SSRFConnector(allowlist=["10.0.0.0/8"])
    try:
        with mock.patch.object(
            TCPConnector,
            "_resolve_host",
            mock.AsyncMock(return_value=_fake_results("10.0.0.5", "10.9.9.9")),
        ):
            assert len(await connector._resolve_host("internal.example.com", 80)) == 2
        with mock.patch.object(
            TCPConnector,
            "_resolve_host",
            mock.AsyncMock(return_value=_fake_results("10.0.0.5", "192.168.1.1")),
        ):
            with pytest.raises(SSRFError, match="192.168.1.1"):
                await connector._resolve_host("internal.example.com", 80)
    finally:
        await connector.close()


def test_resolve_host_override_matches_aiohttp_signature() -> None:
    """Fail loudly if aiohttp changes the ``_resolve_host`` signature."""
    ours = inspect.signature(SSRFConnector._resolve_host)
    theirs = inspect.signature(TCPConnector._resolve_host)
    assert list(ours.parameters) == list(theirs.parameters)


# --- End to end against a local server ----------------------------------------


async def test_connector_blocks_local_server_by_default(
    aiohttp_server: AiohttpServer,
) -> None:
    """The connector refuses a literal 127.0.0.1 target (resolver shortcut path)."""
    server = await aiohttp_server(_ok_app())
    async with ClientSession(connector=SSRFConnector()) as session:
        with pytest.raises(SSRFError, match="127.0.0.1"):
            await session.get(server.make_url("/api"))


async def test_connector_allowlist_reenables_local_server(
    aiohttp_server: AiohttpServer,
) -> None:
    """A CIDR allowlist entry deliberately re-enables a local target."""
    server = await aiohttp_server(_ok_app())
    connector = SSRFConnector(allowlist=["127.0.0.0/8"])
    async with ClientSession(connector=connector) as session:
        async with session.get(server.make_url("/api")) as resp:
            assert resp.status == 200


async def test_connector_blocks_redirect_hop(aiohttp_server: AiohttpServer) -> None:
    """A redirect from an allowed host to an internal address is blocked."""
    app = _ok_app()
    target: list[URL] = []  # filled in once the server port is known

    async def redirect_handler(request: web.Request) -> web.Response:
        raise web.HTTPFound(location=str(target[0]))

    app.router.add_get("/redirect", redirect_handler)
    server = await aiohttp_server(app)
    target.append(server.make_url("/api"))  # http://127.0.0.1:<port>/api

    connector = SSRFConnector(allowlist=["localhost"])
    async with ClientSession(connector=connector) as session:
        with pytest.raises(SSRFError, match="127.0.0.1"):
            await session.get(f"http://localhost:{server.port}/redirect")


async def test_middleware_end_to_end(aiohttp_client: AiohttpClient) -> None:
    """The middleware blocks the local literal-IP target unless allowlisted."""
    client = await aiohttp_client(_ok_app(), middlewares=(SSRFMiddleware(),))
    with pytest.raises(SSRFError, match="not publicly routable"):
        await client.get("/api")

    allowing = SSRFMiddleware(allowlist=["127.0.0.1"])
    client = await aiohttp_client(_ok_app(), middlewares=(allowing,))
    async with client.get("/api") as resp:
        assert resp.status == 200
