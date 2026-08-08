"""Server-side request forgery (SSRF) protection for aiohttp clients.

Two cooperating layers:

- :class:`SSRFConnector` -- the primary control for *direct* connections. It
  validates every address a request would actually connect to (DNS answers and
  IP-literals alike, on every redirect hop) and refuses non-public addresses.
- :class:`SSRFMiddleware` -- the URL-level layer. It applies hostname
  allow/deny rules and narrows the URL scheme before any connection is
  attempted. On its own it cannot stop a hostname that *resolves* to an
  internal address, so it is never the sole control.

Neither layer covers a forward proxy on its own. With ``proxy=`` (or
``trust_env=True`` and ``HTTP_PROXY``/``HTTPS_PROXY``) the connector resolves
and validates only the *proxy* endpoint -- the proxy resolves the target,
which the connector never sees -- so the middleware's hostname rules are the
only constraint left. Use an ``allowlist`` when proxying.

This replaces the simplified ``ssrf_middleware``/``SSRFConnector`` example
from aiohttp's client middleware cookbook with a production-oriented
implementation.
"""

import logging
import socket
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
from yarl import URL

_LOGGER = logging.getLogger(__name__)

_IPAddress = IPv4Address | IPv6Address
_IPNetwork = IPv4Network | IPv6Network

# Characters that never appear in a hostname or a CIDR and that indicate a
# rule was pasted or joined wrongly (a URL, a comma-separated list, a glob).
_INVALID_RULE_CHARS = frozenset(" \t\n\r,*?@[]")

# Ranges that must be blocked but that ``ipaddress`` does not classify on
# every supported CPython (CVE-2024-4032 fixed several of these only in
# 3.10.14/3.11.9/3.12.4, and this package supports 3.10 onwards).
_EXTRA_BLOCKED_NETWORKS: tuple[_IPNetwork, ...] = (
    ip_network("100.64.0.0/10"),  # carrier-grade NAT (RFC 6598)
    ip_network("192.88.99.0/24"),  # 6to4 relay anycast (RFC 3068/7526)
    ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
    ip_network("64:ff9b:1::/48"),  # NAT64 local-use prefixes (RFC 8215)
    ip_network("2002::/16"),  # 6to4: embeds an arbitrary IPv4 address
    ip_network("2001::/32"),  # Teredo: embeds an arbitrary IPv4 address
    ip_network("fec0::/10"),  # site-local (RFC 3879); ipaddress calls it global
    ip_network("3fff::/20"),  # IPv6 documentation range (RFC 9637)
)


class SSRFError(ClientError):
    """A request was blocked because it could reach internal infrastructure.

    ``host`` is the blocked host, or the full URL (with any credentials
    removed) when the rejection is not host-specific. ``reason`` is a
    human-readable explanation.
    """

    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"Blocked potential SSRF request to {host!r}: {reason}")

    def __reduce__(self) -> "tuple[type[SSRFError], tuple[str, str]]":
        # ``args`` holds one formatted string, so the default reduction would
        # call ``__init__`` with a single argument. Copying and pickling an
        # exception must keep working (concurrent.futures, multiprocessing).
        return (type(self), (self.host, self.reason))


def is_unsafe_address(address: "str | _IPAddress") -> bool:
    """Return True unless *address* is a public, globally-routable IP.

    Deny by default: loopback, private, link-local, site-local, multicast,
    reserved, unspecified and otherwise non-global addresses are all unsafe,
    as are the carrier-grade NAT, NAT64, 6to4 and Teredo ranges that
    ``ipaddress`` does not classify on every supported CPython.
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


def _as_ip_literal(host: str) -> "_IPAddress | None":
    """Parse *host* as an IP address, including non-canonical IPv4 forms.

    ``ip_address`` accepts canonical text only, but the resolver still honours
    the legacy ``inet_aton`` forms -- ``0x7f000001``, ``2130706433``,
    ``127.1``, ``0177.0.0.1`` all reach 127.0.0.1. Recognising them here is
    what lets the middleware judge them as addresses instead of passing them
    through as opaque hostnames, which matters most when a proxy is
    configured and the connector never sees the target. A host that is not
    numeric at all returns ``None``.
    """
    try:
        return ip_address(host)
    except ValueError:
        pass
    try:
        return IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def _normalize_host(host: str) -> str:
    """Normalize a hostname for exact matching (case, trailing dot, IDNA).

    Encoding through yarl -- the encoder aiohttp itself uses to build
    ``raw_host`` -- is what lets a single rule entry match in both layers:
    the connector sees the punycode ``raw_host`` while the middleware sees
    the Unicode ``host``, and both normalize to the same ASCII form. The
    stdlib ``idna`` codec cannot be used here: it implements IDNA 2003, which
    disagrees with yarl's UTS-46 on ``ß`` and final sigma, so a rule would
    silently match in one layer only.
    """
    host = host.lower().removesuffix(".")
    try:
        return URL.build(host=host).raw_host or host
    except (UnicodeError, ValueError):
        return host


def _parse_host_rules(
    entries: Iterable[str],
) -> "tuple[frozenset[str], tuple[_IPNetwork, ...]]":
    """Split allow/deny entries into exact hostnames and IP networks.

    An entry containing ``/`` must parse as a CIDR network; anything else that
    parses as an IP address becomes a network, and the rest are exact
    hostnames (matched case-insensitively, ignoring a trailing dot). Hostname
    matching is deliberately exact -- no substring or suffix matching -- so
    ``"victim.com"`` can never match ``"notvictim.com"``.

    A malformed entry raises rather than degrading into a hostname rule that
    can never match: a security rule that cannot be parsed must never become
    a rule that silently does nothing.
    """
    if isinstance(entries, str):
        raise TypeError(
            f"expected an iterable of rules, got the string {entries!r}; "
            "a bare string would be read one character at a time"
        )
    hosts = set()
    networks = []
    for entry in entries:
        if not entry or _INVALID_RULE_CHARS.intersection(entry):
            raise ValueError(f"invalid rule entry: {entry!r}")
        if "/" in entry:
            # Explicitly a network: let a bad prefix length raise.
            networks.append(ip_network(entry, strict=False))
            continue
        try:
            networks.append(ip_network(entry, strict=False))
        except ValueError:
            if ":" in entry:
                # A colon is legal only in an IPv6 address, which would have
                # parsed above; here it means a port or a pasted URL.
                raise ValueError(f"invalid rule entry: {entry!r}") from None
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
    """Client middleware enforcing hostname and scheme rules against SSRF.

    This is the URL-level layer: it rejects requests before a connection is
    attempted, based on what is visible in the URL, and it runs for every
    redirect hop. It cannot see what a hostname resolves to, so it must be
    paired with :class:`SSRFConnector` (or an equivalent resolved-address
    control) to stop attacker-controlled DNS. It is nonetheless required
    rather than merely defence in depth, because it is the only layer that
    can constrain the target when a forward proxy is configured -- the
    connector then validates only the proxy endpoint.

    ``allowlist`` is restrictive: when given, only requests whose URL host
    matches one of its entries are allowed and everything else raises
    :exc:`SSRFError`. ``None`` disables it; an empty list blocks every
    request. Note that supplying an allowlist replaces the default
    public-only check rather than adding to it, so an entry may deliberately
    permit an internal address. ``denylist`` rejects matching hosts and is
    checked first. Entries in both are exact hostnames (case-insensitive,
    trailing dot ignored, IDNA-normalized) or IP addresses/CIDR networks
    matched against literal-IP URL hosts; a malformed entry raises at
    construction.

    ``allowed_schemes`` narrows the schemes aiohttp already permits (it
    rejects anything outside http/https/ws/wss with ``NonHttpUrlClientError``
    before middlewares run); set it to ``("https",)`` to require TLS.
    """

    def __init__(
        self,
        *,
        allowlist: "Iterable[str] | None" = None,
        denylist: "Iterable[str] | None" = None,
        allowed_schemes: Iterable[str] = ("http", "https", "ws", "wss"),
    ) -> None:
        if isinstance(allowed_schemes, str):
            raise TypeError(
                f"expected an iterable of schemes, got the string "
                f"{allowed_schemes!r}"
            )
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
            raise SSRFError(
                url.host or str(url.with_user(None)),
                f"scheme {url.scheme!r} is not allowed",
            )
        host = url.host
        if host is None:
            raise SSRFError(str(url.with_user(None)), "URL has no host")
        ip = _as_ip_literal(host)
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
       ``trust_env=True`` with ``HTTP_PROXY``/``HTTPS_PROXY`` set), only the
       *proxy* endpoint is resolved and validated here; the target is
       resolved by the proxy and is never seen. Constrain proxied targets
       with :class:`SSRFMiddleware` and an ``allowlist``.

    ``exempt_hosts`` layers exemptions on top of the default public-only
    policy -- unlike :class:`SSRFMiddleware`'s restrictive ``allowlist``, it
    does not narrow what is reachable, so an empty value still lets all public
    traffic through. An exact hostname (case-insensitive, trailing dot
    ignored, IDNA-normalized) exempts everything that host resolves to; an IP
    address or CIDR network exempts resolved addresses inside it. Use it to
    reach known-internal services deliberately. A malformed entry raises at
    construction. Every other keyword argument is passed to
    :class:`~aiohttp.TCPConnector`, which takes no positional arguments.
    """

    def __init__(
        self, *, exempt_hosts: "Iterable[str] | None" = None, **kwargs: Any
    ) -> None:
        # Validate before building the connector: a rejected rule must not
        # leave an unclosed TCPConnector behind.
        self._exempt_hosts, self._exempt_networks = _parse_host_rules(
            exempt_hosts or ()
        )
        super().__init__(**kwargs)

    async def _resolve_host(
        self, host: str, port: int, traces: "Sequence[Trace] | None" = None
    ) -> "list[ResolveResult]":
        """Resolve *host* and refuse any non-public resolved address."""
        results = await super()._resolve_host(host, port, traces)
        if _normalize_host(host) in self._exempt_hosts:
            _LOGGER.info("Skipping SSRF checks for exempt host %r", host)
            return results
        for result in results:
            resolved = result["host"]
            try:
                ip: "_IPAddress | None" = ip_address(resolved)
            except ValueError:
                ip = None
            if ip is not None and any(
                ip in network for network in self._exempt_networks
            ):
                continue
            if ip is None or is_unsafe_address(ip):
                _LOGGER.warning(
                    "Blocking connection to %r (resolved from %r)", resolved, host
                )
                raise SSRFError(host, f"resolved to non-public address {resolved!r}")
        return results
