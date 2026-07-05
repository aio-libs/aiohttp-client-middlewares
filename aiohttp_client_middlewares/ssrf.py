"""Server-side request forgery (SSRF) protection for aiohttp clients.

Two cooperating layers:

- :class:`SSRFConnector` -- the primary control for *direct* connections. It
  validates every address a request would actually connect to (DNS answers and
  IP-literals alike, on every redirect hop) and refuses non-public addresses.
  When a forward proxy is configured (``proxy=``, or ``trust_env=True`` with
  ``HTTP_PROXY``/``HTTPS_PROXY``) the connector resolves and validates only the
  *proxy* endpoint -- the proxy resolves the target, which the connector never
  sees.
- :class:`SSRFMiddleware` -- the URL-level layer. It enforces URL-scheme and
  hostname allow/deny rules before any connection is attempted. It is required
  for scheme policing and is the only layer that can constrain the target when
  a proxy is configured (it sees ``request.url``); on its own it cannot stop a
  hostname that *resolves* to an internal address. Never use it as the sole
  control.

This replaces the simplified ``ssrf_middleware``/``SSRFConnector`` example
from aiohttp's client middleware cookbook (which only blocks ``127.0.0.1`` and
``localhost``) with a production-oriented implementation.
"""

import logging
from collections.abc import Iterable, Sequence
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Any

from aiohttp import (
    ClientError,
    ClientHandlerType,
    ClientRequest,
    ClientResponse,
    TCPConnector,
)
from aiohttp.abc import ResolveResult
from aiohttp.tracing import Trace

_LOGGER = logging.getLogger(__name__)

_IPAddress = IPv4Address | IPv6Address
_IPNetwork = IPv4Network | IPv6Network

# Ranges that must be blocked but that ``ipaddress`` either classifies as
# global or classifies inconsistently across CPython patch levels
# (CVE-2024-4032 fixed several such ranges only in 3.10.14/3.11.9/3.12.4).
_EXTRA_BLOCKED_NETWORKS: tuple[_IPNetwork, ...] = (
    ip_network("100.64.0.0/10"),  # carrier-grade NAT (RFC 6598)
    ip_network("192.88.99.0/24"),  # 6to4 relay anycast (RFC 3068/7526)
    ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
    ip_network("64:ff9b:1::/48"),  # NAT64 local-use prefixes (RFC 8215)
    ip_network("2002::/16"),  # 6to4: embeds an arbitrary IPv4 address
    ip_network("2001::/32"),  # Teredo: embeds an arbitrary IPv4 address
    # IPv6 documentation range (RFC 9637); is_global is only False on
    # CPython 3.12.7+/3.13+, so block it explicitly on every supported version.
    ip_network("3fff::/20"),
)


class SSRFError(ClientError):
    """A request was blocked because it could reach internal infrastructure."""

    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"Blocked potential SSRF request to {host!r}: {reason}")


def is_unsafe_address(address: "str | _IPAddress") -> bool:
    """Return True unless *address* is a public, globally-routable IP.

    Deny by default: loopback, private, link-local, multicast, reserved,
    unspecified and otherwise non-global addresses are all unsafe, as are
    carrier-grade NAT, NAT64, 6to4 and Teredo ranges (which ``ipaddress``
    treats as global or classifies inconsistently across patch releases).
    IPv4-mapped IPv6 addresses are judged by their embedded IPv4 address.
    A string that does not parse as an IP address is unsafe (fail closed).
    """
    if isinstance(address, str):
        try:
            ip: _IPAddress = ip_address(address)
        except ValueError:
            return True
    else:
        ip = address
    if isinstance(ip, IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return is_unsafe_address(mapped)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True
    return any(ip in network for network in _EXTRA_BLOCKED_NETWORKS)


def _normalize_host(host: str) -> str:
    """Normalize a hostname for exact matching (case, trailing dot, IDNA).

    Encoding to IDNA/punycode lets a single rule entry match in both layers:
    the connector sees the punycode ``raw_host`` while the middleware sees the
    Unicode ``host``, and both normalize to the same ASCII form. Non-encodable
    input (IP literals, oversized labels, empty host) is left as-is; the
    connector still enforces the resolved-address check regardless.
    """
    host = host.lower().removesuffix(".")
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def _parse_host_rules(
    entries: Iterable[str],
) -> "tuple[frozenset[str], tuple[_IPNetwork, ...]]":
    """Split allow/deny entries into exact hostnames and IP networks.

    An entry that parses as an IP address or CIDR becomes a network; anything
    else is an exact hostname (matched case-insensitively, ignoring a trailing
    dot). Hostname matching is deliberately exact -- no substring or suffix
    matching -- so ``"victim.com"`` can never match ``"notvictim.com"``.
    """
    hosts = set()
    networks = []
    for entry in entries:
        try:
            networks.append(ip_network(entry, strict=False))
        except ValueError:
            hosts.add(_normalize_host(entry))
    return frozenset(hosts), tuple(networks)


def _matches_rules(
    host: str,
    ip: "_IPAddress | None",
    hosts: "frozenset[str]",
    networks: "tuple[_IPNetwork, ...]",
) -> bool:
    """Return True if *host* (or its literal IP form) matches the rules."""
    if _normalize_host(host) in hosts:
        return True
    return ip is not None and any(ip in network for network in networks)


class SSRFMiddleware:
    """Client middleware enforcing scheme and hostname rules against SSRF.

    This is the URL-level layer of the protection: it rejects requests before a
    connection is attempted, based on what is visible in the URL. It cannot see
    what a hostname resolves to, so it must be paired with :class:`SSRFConnector`
    (or an equivalent resolved-address control) to stop attacker-controlled DNS.
    It is nonetheless required, not merely defense in depth: it is the only
    layer that polices the URL scheme, and the only one that can constrain the
    target when a forward proxy is configured (the connector then sees only the
    proxy). The middleware runs for every redirect hop.

    The literal-IP fast path recognizes only canonical addresses. Non-canonical
    numeric forms (``0x7f000001``, ``2130706433``, ``127.1``, ``0177.0.0.1``)
    are treated as hostnames here and stopped only by :class:`SSRFConnector`
    (aiohttp rejects the decimal/octal/short IPv4 forms as non-canonical; the
    hex form is caught after resolution) -- another reason not to rely on the
    middleware alone.

    :param allowlist: When given, only requests whose URL host matches one of
        these entries are allowed; everything else raises :exc:`SSRFError`.
        ``None`` disables the allowlist; an empty list blocks every request
        (fail closed). Entries are exact hostnames (case-insensitive, trailing
        dot ignored, IDNA-normalized) or IP addresses/CIDR networks matched
        against literal-IP URL hosts.
    :type allowlist: iterable of str or None
    :param denylist: Requests whose URL host matches one of these entries
        raise :exc:`SSRFError`. Same entry forms as ``allowlist``. Checked
        before the allowlist.
    :type denylist: iterable of str or None
    :param allowed_schemes: URL schemes that may pass (default ``http`` and
        ``https``); anything else raises :exc:`SSRFError`.
    :type allowed_schemes: iterable of str
    :raises SSRFError: for a rejected request.
    """

    def __init__(
        self,
        *,
        allowlist: "Iterable[str] | None" = None,
        denylist: "Iterable[str] | None" = None,
        allowed_schemes: Iterable[str] = ("http", "https"),
    ) -> None:
        self._allowed_schemes = frozenset(s.lower() for s in allowed_schemes)
        self._allow = None if allowlist is None else _parse_host_rules(allowlist)
        self._deny_hosts, self._deny_networks = _parse_host_rules(denylist or ())

    async def __call__(
        self,
        request: ClientRequest,
        handler: ClientHandlerType,
    ) -> ClientResponse:
        """Reject the request unless it passes every URL-level rule."""
        url = request.url
        if url.scheme not in self._allowed_schemes:
            raise SSRFError(str(url), f"scheme {url.scheme!r} is not allowed")
        host = url.host
        if host is None:
            raise SSRFError(str(url), "URL has no host")
        try:
            ip: "_IPAddress | None" = ip_address(host)
        except ValueError:
            ip = None
        if _matches_rules(host, ip, self._deny_hosts, self._deny_networks):
            raise SSRFError(host, "host is denylisted")
        if self._allow is not None:
            if not _matches_rules(host, ip, *self._allow):
                raise SSRFError(host, "host is not on the allowlist")
        elif ip is not None and is_unsafe_address(ip):
            # A literal-IP URL can be rejected without waiting for the
            # connector; hostnames must still be judged after resolution.
            raise SSRFError(host, "address is not publicly routable")
        return await handler(request)


class SSRFConnector(TCPConnector):
    """A ``TCPConnector`` that refuses to connect to non-public addresses.

    This is the primary SSRF control for direct connections: it validates the
    addresses a request would actually use -- IP-literals and DNS answers
    alike, on the initial request and on every redirect hop -- closing the gap
    where an attacker-controlled hostname resolves to an internal address.

    .. note::
       When a forward proxy is configured (``proxy=`` on the request, or
       ``trust_env=True`` with ``HTTP_PROXY``/``HTTPS_PROXY`` set), the
       connector resolves and validates only the *proxy* endpoint; the target
       is resolved by the proxy and is not seen here. Pair with
       :class:`SSRFMiddleware` to constrain proxied targets.

    :param allowlist: Entries exempted from blocking, layered on top of the
        default public-only policy -- an empty list means "no extra exemptions"
        and public traffic still passes (the opposite sense to the middleware's
        restrictive ``allowlist``). An exact hostname (case-insensitive,
        trailing dot ignored, IDNA-normalized) exempts everything that host
        resolves to; an IP address or CIDR network exempts resolved addresses
        inside it. Use this to reach known-internal services deliberately.
    :type allowlist: iterable of str or None

    All positional and keyword arguments other than ``allowlist`` are passed
    through to :class:`~aiohttp.TCPConnector`.

    :raises SSRFError: when a request would connect to a blocked address.
    """

    def __init__(
        self, *args: Any, allowlist: "Iterable[str] | None" = None, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self._allowed_hosts, self._allowed_networks = _parse_host_rules(allowlist or ())

    async def _resolve_host(
        self, host: str, port: int, traces: "Sequence[Trace] | None" = None
    ) -> "list[ResolveResult]":
        """Resolve *host* and refuse any non-public resolved address."""
        results = await super()._resolve_host(host, port, traces)
        if _normalize_host(host) in self._allowed_hosts:
            return results
        for result in results:
            resolved = result["host"]
            try:
                ip: "_IPAddress | None" = ip_address(resolved)
            except ValueError:
                ip = None
            if ip is not None and any(
                ip in network for network in self._allowed_networks
            ):
                continue
            if ip is None or is_unsafe_address(ip):
                _LOGGER.debug(
                    "Blocking connection to %r (resolved from %r)", resolved, host
                )
                raise SSRFError(host, f"resolved to non-public address {resolved!r}")
        return results
