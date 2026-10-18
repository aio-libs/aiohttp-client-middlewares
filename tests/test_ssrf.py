"""Tests for the SSRF protection connector."""

import copy
import inspect
import pickle
import socket
from collections.abc import Callable
from ipaddress import ip_address, ip_network
from typing import cast
from unittest import mock

import pytest
from aiohttp import (
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    ClientSession,
    TCPConnector,
    WSMsgType,
    web,
)
from aiohttp.abc import AbstractResolver, ResolveResult
from pytest_aiohttp import AiohttpServer
from yarl import URL

from aiohttp_client_middlewares.ssrf import (
    SSRFConnector,
    SSRFError,
    _normalize_hostname,
    is_unsafe_address,
)


def _result(host: str, address: str, port: int = 80) -> ResolveResult:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return ResolveResult(
        hostname=host, host=address, port=port, family=family, proto=0, flags=0
    )


def _fake_results(*addresses: str) -> "list[ResolveResult]":
    return [_result("example.com", address) for address in addresses]


class _StubResolver(AbstractResolver):
    """Resolves every name to fixed addresses, as an attacker's DNS would."""

    def __init__(self, *addresses: str) -> None:
        self._addresses = addresses or ("127.0.0.1",)

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> "list[ResolveResult]":
        return [_result(host, address, port) for address in self._addresses]

    async def close(self) -> None:
        """Nothing to release."""


def _check(connector: SSRFConnector, url: str, proxy: "str | None" = None) -> None:
    """Run the connector's URL checks on a stand-in request."""
    request = mock.Mock(url=URL(url), proxy=None if proxy is None else URL(proxy))
    connector._check_target(cast(ClientRequest, request))


def _blocked(
    connector: SSRFConnector, url: str, match: str, proxy: "str | None" = None
) -> SSRFError:
    with pytest.raises(SSRFError, match=match) as excinfo:
        _check(connector, url, proxy)
    return excinfo.value


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
        "192.0.0.8",  # IPv4 dummy address; global to ipaddress before 3.12.4
        "::1",  # IPv6 loopback
        "::",  # IPv6 unspecified
        "fe80::1",  # IPv6 link-local
        "fe80::1%eth0",  # IPv6 link-local with a zone
        "fc00::1",  # unique-local
        "fec0::1",  # site-local (RFC 3879); ipaddress reports is_global=True
        "fd00:ec2::254",  # AWS IPv6 metadata endpoint (unique-local)
        "ff02::1",  # IPv6 multicast
        "64:ff9b::a00:1",  # NAT64 translation of 10.0.0.1
        "64:ff9b::a9fe:a9fe",  # NAT64 translation of the metadata endpoint
        "64:ff9b:1::1",  # NAT64 local-use
        "2002:808:808::1",  # 6to4: embeds an arbitrary IPv4 address
        "2001::1",  # Teredo: embeds an arbitrary IPv4 address
        "3fff::1",  # RFC 9637 documentation range (is_global varies by version)
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "::ffff:169.254.169.254",  # IPv4-mapped metadata endpoint
        "::ffff:192.88.99.1",  # IPv4-mapped: the extra ranges apply after unwrapping
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
        "64:ff9b::808:808",  # NAT64, how an IPv6-only host reaches 8.8.8.8
    ],
)
def test_public_addresses_allowed(address: str) -> None:
    """Globally-routable public addresses are not flagged."""
    assert not is_unsafe_address(address)


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",
        "100.127.255.255",
        "192.0.0.8",
        "192.0.0.255",
        "192.88.99.1",
        "192.88.99.255",
        "64:ff9b:1::1",
        "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        "2002:808:808::1",
        "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001::1",
        "2001:0:ffff:ffff:ffff:ffff:ffff:ffff",
        "fec0::1",
        "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "3fff::1",
        "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
    ],
)
def test_ranges_blocked_even_where_ipaddress_calls_them_global(address: str) -> None:
    """Some CPythons classify these as global; block them anyway.

    Patching ``ipaddress`` to classify nothing is what makes the test mean the
    same on every CPython, instead of passing for free on a patched one. Both
    ends of each range are checked, so a narrowed range would fail.
    """
    ip = ip_address(address)
    with mock.patch.multiple(
        type(ip),
        is_global=True,
        is_private=False,
        is_loopback=False,
        is_link_local=False,
        is_multicast=False,
        is_reserved=False,
        is_unspecified=False,
    ):
        assert is_unsafe_address(ip)


def test_classifier_accepts_address_objects() -> None:
    """``IPv4Address``/``IPv6Address`` inputs work the same as strings."""
    assert is_unsafe_address(ip_address("10.0.0.1"))
    assert not is_unsafe_address(ip_address("2606:4700:4700::1111"))


@pytest.mark.parametrize("value", [ip_network("0.0.0.0/0"), 2130706433, None, b""])
def test_classifier_rejects_other_types(value: object) -> None:
    """A network, an int or None is a caller bug, not a public address."""
    with pytest.raises(TypeError, match="expected an IP address"):
        is_unsafe_address(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("EXAMPLE.com.", "example.com"),  # lowercased, trailing dot dropped
        ("example.com..", "example.com"),  # every trailing dot, as aiohttp does
        ("☃.internal", "xn--n3h.internal"),  # Unicode -> punycode
        ("xn--n3h.internal", "xn--n3h.internal"),  # already punycode
        ("faß.example", "xn--fa-hia.example"),  # UTS-46, not IDNA 2003's "fass"
        ("a b.com", "a b.com"),  # yarl refuses it, so it is kept as it is
    ],
)
def test_normalize_hostname(host: str, expected: str) -> None:
    """Hosts fold to one case, dot and IDNA form."""
    assert _normalize_hostname(host) == expected


# --- SSRFError ----------------------------------------------------------------


def test_ssrf_error_carries_host_reason_and_address() -> None:
    """The address is an attribute, kept out of the user-facing message."""
    err = SSRFError("victim.internal", "resolved to a non-public address", "10.0.0.5")
    assert (err.host, err.reason, err.address) == (
        "victim.internal",
        "resolved to a non-public address",
        "10.0.0.5",
    )
    assert "victim.internal" in str(err)
    assert "10.0.0.5" not in str(err)


def test_ssrf_error_survives_pickle_and_copy() -> None:
    """The error crosses process boundaries and can be copied."""
    err = SSRFError("victim.internal", "resolved to a non-public address", "10.0.0.5")
    for restored in (pickle.loads(pickle.dumps(err)), copy.copy(err)):
        assert (restored.host, restored.reason, restored.address) == (
            err.host,
            err.reason,
            err.address,
        )
        assert str(restored) == str(err)


# --- Rule parsing: a malformed rule must never become a silent no-op ----------


@pytest.mark.parametrize(
    "entry",
    [
        "10.0.0.0/33",  # impossible prefix length
        "203.0.113.0/244",  # transposed digits
        "10.1.2.3/16",  # host bits set: would silently widen the rule
        " 192.168.1.0/24",  # stray leading space
        "192.168.1.0/24 ",  # stray trailing space
        "*.evil.example",  # glob, which is not supported
        ".internal.example",  # NO_PROXY-style suffix, which is not supported
        "internal..example",  # empty label
        "10.0.0.0/8,127.0.0.0/8",  # comma-joined config value
        "http://victim.example",  # a URL pasted instead of a host
        "victim.example:8080",  # host:port instead of a host
        "user@victim.example",  # userinfo
        "victim.example?x=1",  # query
        "[victim.example]",  # brackets
        "victim.example#",  # fragment
        "victim.example\\",  # backslash
        "vic%74im.example",  # percent-encoding
        "victim.example\n",  # a line read with readlines()
        "\tvictim.example",  # tab
        "",  # blank line from a config file
        ".",  # nothing but a dot
        "127.1",  # non-canonical IPv4 would be kept as a hostname
        "2130706433",  # decimal IPv4
        "0x7f000001",  # hex IPv4
        "0X7F000001",  # hex IPv4, upper case
        "0177.0.0.1",  # octal IPv4
        "127.0.0.1.",  # trailing dot on an address
        "::ffff:10.0.0.1",  # IPv4-mapped: matched as 10.0.0.1, so write that
        "64:ff9b::/96",  # NAT64: likewise matched as IPv4
    ],
)
def test_malformed_rule_entry_raises(entry: str) -> None:
    """A rule that cannot be parsed raises instead of matching nothing."""
    with pytest.raises(ValueError, match="invalid rule entry"):
        SSRFConnector(denylist=[entry])


def test_suffix_rule_says_why_it_is_refused() -> None:
    """A leading-dot entry explains that there is no suffix matching."""
    with pytest.raises(ValueError, match="no suffix or wildcard matching"):
        SSRFConnector(denylist=[".internal.example"])


@pytest.mark.parametrize(
    "entry",
    [
        "1.example.com",
        "0x7f.example",
        "::/0",
        "_service.example",
        "victim.example.",
        "victim.example..",
        "a" * 70 + ".example",
    ],
)
async def test_rule_lookalikes_still_parse(entry: str) -> None:
    """Only the last label makes a name numeric, and ``::/0`` is plain IPv6."""
    connector = SSRFConnector(denylist=[entry])
    await connector.close()


@pytest.mark.parametrize(
    "build",
    [
        lambda: SSRFConnector(allowlist="victim.example"),
        lambda: SSRFConnector(denylist="victim.example"),
        lambda: SSRFConnector(exempt_hosts="victim.example"),
    ],
    ids=["allowlist", "denylist", "exempt_hosts"],
)
def test_bare_string_rules_rejected(build: Callable[[], SSRFConnector]) -> None:
    """A bare string would be read one character at a time, so reject it.

    No ignore is needed: ``str`` satisfies ``Iterable[str]``, which is exactly
    why this has to be caught at runtime.
    """
    with pytest.raises(TypeError, match="one character at a time"):
        build()


def test_non_string_rule_entries_rejected() -> None:
    """A network object would otherwise be iterated address by address."""
    with pytest.raises(TypeError, match="entries must be strings"):
        SSRFConnector(denylist=[ip_network("10.0.0.0/8")])  # type: ignore[list-item]


def test_bare_string_schemes_rejected() -> None:
    """``allowed_schemes="https"`` would allow the letters h, t, p and s."""
    with pytest.raises(TypeError, match="string"):
        SSRFConnector(allowed_schemes="https")


# --- URL checks, run by connect() for every request and redirect hop ----------


async def test_url_checks_run_in_connect() -> None:
    """``connect()`` refuses a blocked URL before any connection is made."""
    connector = SSRFConnector()
    async with connector:
        request = mock.Mock(url=URL("http://127.0.0.1/"), proxy=None)
        with pytest.raises(SSRFError, match="not publicly routable"):
            await connector.connect(cast(ClientRequest, request), [], mock.Mock())


@pytest.mark.parametrize("url", ["ftp://example.com/file", "tcp://example.com/"])
async def test_schemes_outside_the_default_are_refused(url: str) -> None:
    """``TCPConnector`` itself accepts ``tcp://``; the default does not."""
    connector = SSRFConnector()
    async with connector:
        _blocked(connector, url, "scheme")


async def test_custom_schemes_replace_the_default() -> None:
    """``("https", "wss")`` requires TLS; schemes match case-insensitively."""
    connector = SSRFConnector(allowed_schemes=("HTTPS", "wss"))
    async with connector:
        _check(connector, "https://example.com/")
        _check(connector, "wss://example.com/socket")
        err = _blocked(connector, "http://example.com/p", "scheme 'http'")
        assert err.host == "example.com"


@pytest.mark.parametrize("scheme", ["ws", "wss"])
async def test_websocket_schemes_pass_by_default(scheme: str) -> None:
    """``ws_connect()`` goes through the connector, so ws/wss must pass."""
    connector = SSRFConnector()
    async with connector:
        _check(connector, f"{scheme}://example.com/socket")


async def test_url_without_host_is_refused() -> None:
    """A URL with no host cannot be checked, so it fails closed."""
    connector = SSRFConnector()
    async with connector:
        _blocked(connector, "http:/path", "no host")


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "[::1]",
        "[fe80::1%25eth0]",  # a zone ID does not hide a link-local address
        "[::ffff:127.0.0.1]",
        "0x7f000001",  # legacy forms that resolvers and proxies accept
        "2130706433",
        "127.1",
        "0177.0.0.1",
        "127.0.0.1.",  # WHATWG URL parsers drop the trailing dot
        "0x7f000001.",
        "127.1.",
        "2130706433.",
    ],
)
async def test_internal_ip_literals_are_refused(host: str) -> None:
    """Every spelling of an internal address is judged as that address."""
    connector = SSRFConnector()
    async with connector:
        _blocked(connector, f"http://{host}/", "not publicly routable")


@pytest.mark.parametrize(
    "host",
    ["8.8.8.8", "[2606:4700:4700::1111]", "134744072", "0x08080808", "example.com"],
)
async def test_public_targets_pass(host: str) -> None:
    """Public addresses in any spelling, and hostnames, pass the URL checks."""
    connector = SSRFConnector()
    async with connector:
        _check(connector, f"http://{host}/path")


async def test_undecodable_punycode_host_is_not_an_error() -> None:
    """The ASCII host is checked, so bad punycode cannot raise UnicodeError."""
    connector = SSRFConnector()
    async with connector:
        _check(connector, "http://xn--zz.example/")


@pytest.mark.parametrize(
    "host",
    ["victim.com", "VICTIM.COM.", "victim.com..", "victim.com..."],
)
async def test_denylist_matches_whatever_aiohttp_would_resolve(host: str) -> None:
    """aiohttp resolves any run of trailing dots as one, so they all match."""
    connector = SSRFConnector(denylist=["victim.com"])
    async with connector:
        _blocked(connector, f"http://{host}/", "denylisted")


@pytest.mark.parametrize("host", ["notvictim.com", "victim.com.evil.example"])
async def test_denylist_is_anchored(host: str) -> None:
    """A denylist entry never matches by substring or suffix."""
    connector = SSRFConnector(denylist=["victim.com"])
    async with connector:
        _check(connector, f"http://{host}/")


@pytest.mark.parametrize(
    ("rule", "host"),
    [
        ("8.8.8.0/24", "8.8.8.8"),
        ("93.184.216.34", "[::ffff:93.184.216.34]"),  # mapped form of the rule
        ("93.184.216.34", "[64:ff9b::5db8:d822]"),  # NAT64 form of the rule
        ("::/0", "[::ffff:8.8.8.8]"),  # an IPv6 rule covering the mapped form
        ("64:ff9b::/32", "[64:ff9b::808:808]"),  # a rule wider than NAT64
    ],
)
async def test_denylisted_networks_match_every_spelling(rule: str, host: str) -> None:
    """A deny rule matches the address as written and as it is reached."""
    connector = SSRFConnector(denylist=[rule])
    async with connector:
        _blocked(connector, f"http://{host}/", "denylisted")


@pytest.mark.parametrize(
    "build",
    [
        lambda: SSRFConnector(denylist=["example.com"], allowlist=["example.com"]),
        lambda: SSRFConnector(denylist=["example.com"], exempt_hosts=["example.com"]),
    ],
    ids=["allowlist", "exempt_hosts"],
)
async def test_denylist_wins(build: Callable[[], SSRFConnector]) -> None:
    """The denylist is checked before anything that could let a host in."""
    connector = build()
    async with connector:
        _blocked(connector, "http://example.com/", "denylisted")


async def test_allowlist_admits_only_its_entries() -> None:
    """With an allowlist, only matching hosts pass."""
    connector = SSRFConnector(allowlist=["api.example.com", "8.8.8.0/24"])
    async with connector:
        _check(connector, "http://api.example.com/v1")
        _check(connector, "http://8.8.8.8/")
        _check(connector, "http://[::ffff:8.8.8.8]/")  # the mapped form of 8.8.8.8
        _blocked(connector, "http://other.example.com/", "not on the allowlist")


@pytest.mark.parametrize("url", ["http://example.com/", "http://8.8.8.8/"])
async def test_empty_allowlist_blocks_everything(url: str) -> None:
    """An empty allowlist fails closed rather than disabling the check."""
    connector = SSRFConnector(allowlist=[])
    async with connector:
        _blocked(connector, url, "not on the allowlist")


async def test_allowlist_only_narrows() -> None:
    """An allowlisted internal address still needs an exemption."""
    connector = SSRFConnector(allowlist=["192.0.2.0/24"])
    async with connector:
        _blocked(connector, "http://192.0.2.1/", "not publicly routable")
    connector = SSRFConnector(allowlist=["192.0.2.0/24"], exempt_hosts=["192.0.2.0/24"])
    async with connector:
        _check(connector, "http://192.0.2.1/")


async def test_exempt_network_admits_internal_literals_inside_it() -> None:
    """An exemption re-enables addresses inside it, IPv4-mapped forms too."""
    connector = SSRFConnector(exempt_hosts=["10.0.0.0/8"])
    async with connector:
        _check(connector, "http://10.1.2.3/")
        _check(connector, "http://[::ffff:10.1.2.3]/")
        _blocked(connector, "http://192.168.1.1/", "not publicly routable")


async def test_ipv6_exemption_does_not_cover_embedded_ipv4() -> None:
    """``::/0`` exempts IPv6 addresses, not the IPv4 ones mapped into it."""
    connector = SSRFConnector(exempt_hosts=["::/0"])
    async with connector:
        _check(connector, "http://[fd00::1]/")
        _blocked(connector, "http://[::ffff:10.0.0.1]/", "not publicly routable")


@pytest.mark.parametrize("entry", ["☃.example", "xn--n3h.example"])
async def test_idn_rules_match_the_punycode_host(entry: str) -> None:
    """A Unicode or punycode rule matches the ASCII host aiohttp connects to."""
    connector = SSRFConnector(denylist=[entry])
    async with connector:
        _blocked(connector, "http://☃.example/", "denylisted")


@pytest.mark.parametrize("entry", ["faß.example", "xn--fa-hia.example"])
async def test_idn_rules_follow_uts46_not_idna2003(entry: str) -> None:
    """``ß`` is where the stdlib codec (IDNA 2003) and yarl (UTS-46) differ."""
    connector = SSRFConnector(denylist=[entry])
    async with connector:
        _blocked(connector, "http://faß.example/", "denylisted")
        _check(connector, "http://fass.example/")


# --- Behind a forward proxy ---------------------------------------------------

_PROXY = "http://proxy.example:3128"


async def test_proxied_hostname_is_refused_by_default() -> None:
    """The proxy resolves the target, so the connector cannot vouch for it."""
    connector = SSRFConnector()
    async with connector:
        _blocked(connector, "http://example.com/", "a proxy resolves this host", _PROXY)


@pytest.mark.parametrize(
    "build",
    [
        lambda: SSRFConnector(allowlist=["example.com"]),
        lambda: SSRFConnector(exempt_hosts=["example.com"]),
        lambda: SSRFConnector(trust_proxy=True),
    ],
    ids=["allowlisted", "exempt", "trust_proxy"],
)
async def test_proxied_hostname_passes_when_vouched_for(
    build: Callable[[], SSRFConnector],
) -> None:
    """An allowlisted or exempt host, or a trusted proxy, lets it through."""
    connector = build()
    async with connector:
        _check(connector, "http://example.com/", _PROXY)


async def test_proxied_ip_literals_are_still_judged() -> None:
    """A literal target is checked even when the proxy is trusted."""
    connector = SSRFConnector(trust_proxy=True)
    async with connector:
        _blocked(connector, "http://127.0.0.1./", "not publicly routable", _PROXY)
        _check(connector, "http://8.8.8.8/", _PROXY)


# --- Resolved addresses -------------------------------------------------------


async def _resolve(
    connector: SSRFConnector, host: str, *addresses: str
) -> "list[ResolveResult]":
    """Run the override on a canned DNS answer."""
    results = _fake_results(*addresses)
    with mock.patch.object(
        TCPConnector, "_resolve_host", mock.AsyncMock(return_value=results)
    ):
        return await connector._resolve_host(host, 80)


async def test_private_resolution_is_refused() -> None:
    """The error names the queried host; the address is an attribute only."""
    connector = SSRFConnector()
    async with connector:
        with pytest.raises(SSRFError, match="non-public address") as excinfo:
            await _resolve(connector, "internal.example.com", "10.0.0.5")
    assert excinfo.value.host == "internal.example.com"
    assert excinfo.value.address == "10.0.0.5"
    assert "10.0.0.5" not in str(excinfo.value)


async def test_public_resolution_is_returned_untouched() -> None:
    """Public answers come back exactly as the resolver gave them."""
    connector = SSRFConnector()
    async with connector:
        resolved = await _resolve(connector, "example.com", "93.184.216.34", "1.1.1.1")
    assert resolved == _fake_results("93.184.216.34", "1.1.1.1")


@pytest.mark.parametrize(
    "answer",
    [("10.0.0.5", "93.184.216.34"), ("93.184.216.34", "10.0.0.5")],
    ids=["internal-first", "internal-last"],
)
async def test_one_internal_answer_refuses_the_whole_answer(
    answer: "tuple[str, str]",
) -> None:
    """aiohttp may try any answer, so every one of them is checked."""
    connector = SSRFConnector()
    async with connector:
        with pytest.raises(SSRFError, match="non-public address"):
            await _resolve(connector, "example.com", *answer)


@pytest.mark.parametrize(
    "internal",
    ["::1", "fd00:ec2::254", "fe80::1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"],
)
async def test_internal_ipv6_answers_are_refused(internal: str) -> None:
    """IPv6 answers are judged like IPv4 ones, embedded addresses included."""
    connector = SSRFConnector()
    async with connector:
        with pytest.raises(SSRFError, match="non-public address"):
            await _resolve(connector, "example.com", "93.184.216.34", internal)


@pytest.mark.parametrize("answer", ["garbage", "/var/run/docker.sock"])
async def test_unparsable_answer_fails_closed(answer: str) -> None:
    """A resolver result that is not an IP address is refused."""
    connector = SSRFConnector()
    async with connector:
        with pytest.raises(SSRFError, match="not an IP address"):
            await _resolve(connector, "example.com", answer)


async def test_empty_answer_fails_closed() -> None:
    """A resolver that returns nothing is refused explicitly."""
    connector = SSRFConnector()
    async with connector:
        with pytest.raises(SSRFError, match="no addresses"):
            await _resolve(connector, "example.com")


@pytest.mark.parametrize(
    "host", ["internal.example.com", "INTERNAL.example.COM.", "internal.example.com.."]
)
async def test_exempt_hostname_may_resolve_internally(host: str) -> None:
    """An exempt hostname is trusted whatever it resolves to."""
    connector = SSRFConnector(exempt_hosts=["internal.example.com"])
    async with connector:
        assert await _resolve(connector, host, "10.0.0.5") == _fake_results("10.0.0.5")


@pytest.mark.parametrize(
    "host", ["notinternal.example.com", "internal.example.com.evil.example"]
)
async def test_exempt_hostname_is_anchored(host: str) -> None:
    """An exempt hostname never matches by substring or suffix."""
    connector = SSRFConnector(exempt_hosts=["internal.example.com"])
    async with connector:
        with pytest.raises(SSRFError, match="non-public address"):
            await _resolve(connector, host, "10.0.0.5")


async def test_exempt_network_covers_answers_inside_it_only() -> None:
    """A CIDR exemption covers resolved addresses inside it, mapped forms too."""
    connector = SSRFConnector(exempt_hosts=["10.0.0.0/8"])
    async with connector:
        await _resolve(connector, "internal.test", "10.0.0.5", "::ffff:10.9.9.9")
        with pytest.raises(SSRFError, match="non-public address"):
            await _resolve(connector, "internal.test", "10.0.0.5", "192.168.1.1")


@pytest.mark.parametrize(
    ("rule", "answer"),
    [
        ("168.63.129.16", "168.63.129.16"),  # Azure's platform address is global
        ("::/0", "::ffff:8.8.8.8"),
    ],
)
async def test_denylisted_networks_apply_to_answers(rule: str, answer: str) -> None:
    """A hostname cannot reach a denied network by resolving into it."""
    connector = SSRFConnector(denylist=[rule])
    async with connector:
        with pytest.raises(SSRFError, match="denylisted network"):
            await _resolve(connector, "wire.attacker.example", answer)


async def test_denylisted_network_beats_exempt_hostname() -> None:
    """An exempt name still cannot resolve into a denied network."""
    connector = SSRFConnector(
        exempt_hosts=["internal.example.com"], denylist=["10.0.0.0/8"]
    )
    async with connector:
        with pytest.raises(SSRFError, match="denylisted network"):
            await _resolve(connector, "internal.example.com", "10.0.0.5")


async def test_traces_reach_the_resolver() -> None:
    """``traces`` is passed on, so DNS tracing keeps working."""
    resolve = mock.AsyncMock(return_value=_fake_results("93.184.216.34"))
    traces = [mock.Mock()]
    connector = SSRFConnector()
    async with connector:
        with mock.patch.object(TCPConnector, "_resolve_host", resolve):
            await connector._resolve_host("example.com", 80, traces)
    resolve.assert_awaited_once_with("example.com", 80, traces)


@pytest.mark.parametrize("name", ["_resolve_host", "connect"])
def test_overrides_match_aiohttp_signatures(name: str) -> None:
    """Fail loudly if aiohttp changes a signature the connector overrides."""
    ours = inspect.signature(getattr(SSRFConnector, name))
    theirs = inspect.signature(getattr(TCPConnector, name))
    # Names alone would not notice a parameter changing kind, so compare both.
    assert [(p.name, p.kind) for p in ours.parameters.values()] == [
        (p.name, p.kind) for p in theirs.parameters.values()
    ]


# --- End to end, through aiohttp -----------------------------------------------


async def _ok(request: web.Request) -> web.Response:
    return web.Response(text="OK")


async def _ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    await ws.close()
    return ws


def _app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api", _ok)
    app.router.add_get("/ws", _ws)
    return app


@pytest.mark.parametrize("use_dns_cache", [True, False])
async def test_hostname_resolving_internally_is_refused(
    aiohttp_server: AiohttpServer, use_dns_cache: bool
) -> None:
    """A name that resolves to 127.0.0.1 is refused, cached lookups included."""
    server = await aiohttp_server(_app())
    connector = SSRFConnector(resolver=_StubResolver(), use_dns_cache=use_dns_cache)
    async with ClientSession(connector=connector) as session:
        for _ in range(2):
            with pytest.raises(SSRFError, match="non-public address") as excinfo:
                await session.get(f"http://internal.test:{server.port}/api")
            assert excinfo.value.host == "internal.test"
            assert excinfo.value.address == "127.0.0.1"


async def test_exempt_hostname_reaches_an_internal_service(
    aiohttp_server: AiohttpServer,
) -> None:
    """Exempting a name lets requests to it through."""
    server = await aiohttp_server(_app())
    connector = SSRFConnector(resolver=_StubResolver(), exempt_hosts=["internal.test"])
    async with ClientSession(connector=connector) as session:
        async with session.get(f"http://internal.test:{server.port}/api") as resp:
            assert resp.status == 200


async def test_literal_loopback_is_refused_unless_exempt(
    aiohttp_server: AiohttpServer,
) -> None:
    """A literal internal target is refused, and an exemption re-enables it."""
    server = await aiohttp_server(_app())
    async with ClientSession(connector=SSRFConnector()) as session:
        with pytest.raises(SSRFError, match="not publicly routable"):
            await session.get(server.make_url("/api"))
    connector = SSRFConnector(exempt_hosts=["127.0.0.0/8"])
    async with ClientSession(connector=connector) as session:
        async with session.get(server.make_url("/api")) as resp:
            assert resp.status == 200


@pytest.mark.parametrize("dots", ["", ".", "..", "..."])
async def test_trailing_dots_cannot_reach_a_denylisted_host(
    aiohttp_server: AiohttpServer, dots: str
) -> None:
    """The exempt-and-deny pairing holds however many dots the URL has."""
    server = await aiohttp_server(_app())
    connector = SSRFConnector(
        resolver=_StubResolver(),
        exempt_hosts=["internal.test"],
        denylist=["internal.test"],
    )
    async with ClientSession(connector=connector) as session:
        with pytest.raises(SSRFError, match="denylisted"):
            await session.get(f"http://internal.test{dots}:{server.port}/api")


async def test_request_level_middlewares_cannot_skip_the_checks(
    aiohttp_server: AiohttpServer,
) -> None:
    """``middlewares=()`` replaces the session's middlewares, not the connector."""
    server = await aiohttp_server(_app())
    async with ClientSession(connector=SSRFConnector()) as session:
        with pytest.raises(SSRFError, match="not publicly routable"):
            await session.get(server.make_url("/api"), middlewares=())


async def test_a_url_rewritten_by_a_middleware_is_checked(
    aiohttp_server: AiohttpServer,
) -> None:
    """The connector sees the URL after every middleware has run."""
    server = await aiohttp_server(_app())

    async def rewrite(
        request: ClientRequest, handler: ClientHandlerType
    ) -> ClientResponse:
        request.url = request.url.with_host("127.0.0.1")
        return await handler(request)

    connector = SSRFConnector(resolver=_StubResolver(), exempt_hosts=["public.test"])
    async with ClientSession(connector=connector, middlewares=(rewrite,)) as session:
        with pytest.raises(SSRFError, match="not publicly routable"):
            await session.get(f"http://public.test:{server.port}/api")


@pytest.mark.parametrize(
    ("location", "allowlist", "match", "blocked_host"),
    [
        ("http://127.0.0.1:{port}/api", None, "not publicly routable", "127.0.0.1"),
        (
            "http://other.test:{port}/api",
            ["public.test"],
            "not on the allowlist",
            "other.test",
        ),
    ],
    ids=["internal-address", "outside-allowlist"],
)
async def test_redirect_hops_are_checked(
    aiohttp_server: AiohttpServer,
    location: str,
    allowlist: "list[str] | None",
    match: str,
    blocked_host: str,
) -> None:
    """Each hop is a new request, so it goes through the same checks."""
    redirects: list[str] = []
    app = _app()

    async def redirect(request: web.Request) -> web.Response:
        redirects.append(request.path)
        raise web.HTTPFound(location=location.format(port=request.url.port))

    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)
    connector = SSRFConnector(
        resolver=_StubResolver(),
        exempt_hosts=["public.test", "other.test"],
        allowlist=allowlist,
    )
    async with ClientSession(connector=connector) as session:
        with pytest.raises(SSRFError, match=match) as excinfo:
            await session.get(f"http://public.test:{server.port}/redirect")
    assert redirects == ["/redirect"]
    assert excinfo.value.host == blocked_host


async def test_ws_connect_is_checked(aiohttp_server: AiohttpServer) -> None:
    """``ws_connect()`` goes through the connector like any request."""
    server = await aiohttp_server(_app())
    url = f"ws://127.0.0.1:{server.port}/ws"
    async with ClientSession(connector=SSRFConnector()) as session:
        with pytest.raises(SSRFError, match="not publicly routable"):
            await session.ws_connect(url)
    connector = SSRFConnector(exempt_hosts=["127.0.0.0/8"])
    async with ClientSession(connector=connector) as session:
        async with session.ws_connect(url) as ws:
            message = await ws.receive()
    assert message.type is WSMsgType.CLOSE


async def test_tcp_scheme_is_refused_end_to_end() -> None:
    """aiohttp hands ``tcp://`` URLs to ``TCPConnector``; this one refuses them."""
    async with ClientSession(connector=SSRFConnector()) as session:
        with pytest.raises(SSRFError, match="scheme 'tcp'"):
            await session.get("tcp://example.test/")


def _proxy_connector(
    allowlist: "list[str] | None" = None, trust_proxy: bool = False
) -> SSRFConnector:
    """A connector set up as the docs describe for an internal proxy."""
    return SSRFConnector(
        resolver=_StubResolver(),
        exempt_hosts=["proxy.test"],
        denylist=["proxy.test"],
        allowlist=allowlist,
        trust_proxy=trust_proxy,
    )


@pytest.mark.parametrize(
    ("allowlist", "trust_proxy", "passes"),
    [(None, False, False), (["target.test"], False, True), (None, True, True)],
    ids=["default", "allowlisted", "trust_proxy"],
)
async def test_proxied_requests(
    aiohttp_server: AiohttpServer,
    allowlist: "list[str] | None",
    trust_proxy: bool,
    passes: bool,
) -> None:
    """Behind a proxy, a hostname target must be vouched for."""
    server = await aiohttp_server(_app())  # answers as the proxy
    proxy = f"http://proxy.test:{server.port}"
    connector = _proxy_connector(allowlist, trust_proxy)
    async with ClientSession(connector=connector) as session:
        if passes:
            async with session.get("http://target.test/api", proxy=proxy) as resp:
                assert resp.status == 200
        else:
            with pytest.raises(SSRFError, match="a proxy resolves this host"):
                await session.get("http://target.test/api", proxy=proxy)
        with pytest.raises(SSRFError, match="denylisted"):
            # The proxy itself cannot be requested as a target.
            await session.get(f"http://proxy.test:{server.port}/api", proxy=proxy)


async def test_proxy_from_the_environment_is_seen(
    aiohttp_server: AiohttpServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``trust_env=True`` picks the proxy before connect(), which still sees it."""
    server = await aiohttp_server(_app())
    proxy = f"http://proxy.test:{server.port}"
    for name in ("http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(name, proxy)
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    async with ClientSession(connector=_proxy_connector(), trust_env=True) as session:
        with pytest.raises(SSRFError, match="a proxy resolves this host"):
            await session.get("http://target.test/api")
