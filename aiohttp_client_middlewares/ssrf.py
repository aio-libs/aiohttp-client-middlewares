"""Server-side request forgery (SSRF) protection for aiohttp clients.

:class:`SSRFConnector` refuses to connect to anything that is not a public,
globally-routable address. It checks each request's URL against its rules in
:meth:`~aiohttp.BaseConnector.connect`, which aiohttp calls for every request,
redirect hop and ``ws_connect()``, and it checks every address a hostname
resolves to before aiohttp connects to it. Because the checks live in the
connector, a request-level ``middlewares=`` argument cannot skip them, and
they see the URL after any middleware has rewritten it.

Behind a forward proxy the connector sees only the proxy, never what the
target resolves to, so a proxied request to a hostname is refused unless the
host is allowlisted or ``trust_proxy=True`` is set.
"""

import re
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
from typing import Any, NamedTuple

from aiohttp import ClientError, ClientRequest, ClientTimeout, TCPConnector
from aiohttp.abc import ResolveResult
from aiohttp.connector import Connection
from aiohttp.tracing import Trace
from yarl import URL

_IPAddress = IPv4Address | IPv6Address
_IPNetwork = IPv4Network | IPv6Network

# What a hostname, in a rule or a URL, may contain once encoded to ASCII:
# labels of letters, digits, hyphens and underscores, separated by single dots.
_HOSTNAME_RULE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")

# A hostname never ends in a numeric label and an IPv4 address always does,
# so an entry ending in one is an address, written canonically or not.
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*", re.IGNORECASE)

# IPv6 prefixes whose last 32 bits are the IPv4 address a connection actually
# reaches, so that address is what gets classified and matched against rules.
_IPV4_EMBEDDING_NETWORKS: tuple[IPv6Network, ...] = (
    IPv6Network("::ffff:0:0/96"),  # IPv4-mapped (RFC 4291)
    IPv6Network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
)

# Ranges that must be blocked but that ``ipaddress`` calls global on some or
# all supported CPythons (several only before the CVE-2024-4032 fix in
# 3.10.15, 3.11.10 and 3.12.4), so the result is the same on every version.
_EXTRA_BLOCKED_NETWORKS: tuple[_IPNetwork, ...] = (
    ip_network("100.64.0.0/10"),  # carrier-grade NAT (RFC 6598)
    ip_network("192.0.0.0/24"),  # IETF protocol assignments (RFC 6890)
    ip_network("192.88.99.0/24"),  # 6to4 relay anycast (RFC 3068/7526)
    ip_network("64:ff9b:1::/48"),  # NAT64 local-use prefixes (RFC 8215)
    ip_network("2002::/16"),  # 6to4: embeds an arbitrary IPv4 address
    ip_network("2001::/32"),  # Teredo: embeds an arbitrary IPv4 address
    ip_network("fec0::/10"),  # site-local (RFC 3879); ipaddress calls it global
    ip_network("3fff::/20"),  # IPv6 documentation range (RFC 9637)
)


class SSRFError(ClientError):
    """A request was blocked because it could reach internal infrastructure.

    ``host`` is the blocked host in its ASCII (punycode) form and ``reason``
    says why. ``address`` is the resolved address that was refused when a
    DNS answer was the reason; it is kept out of the message, so the message
    can be shown to users without revealing internal addresses.

    A block is a policy decision, not a network failure: sending the same
    request again gives the same answer.
    """

    def __init__(self, host: str, reason: str, address: "str | None" = None) -> None:
        self.host = host
        self.reason = reason
        self.address = address
        super().__init__(f"Blocked potential SSRF request to {host!r}: {reason}")

    def __reduce__(
        self,
    ) -> "tuple[type[SSRFError], tuple[str, str, str | None]]":
        # ``args`` holds one formatted string, so the default reduction would
        # call ``__init__`` with a single argument. Copying and pickling an
        # exception must keep working (concurrent.futures, multiprocessing).
        return (type(self), (self.host, self.reason, self.address))


def is_unsafe_address(address: "str | _IPAddress") -> bool:
    """Return True unless *address* is a public, globally-routable IP.

    Deny by default: loopback, private, link-local, site-local, multicast,
    reserved, unspecified and otherwise non-global addresses are all unsafe,
    as are special-purpose ranges -- carrier-grade NAT, 6to4, Teredo and
    others -- that ``ipaddress`` does not classify on every supported
    CPython. IPv4-mapped and NAT64 (``64:ff9b::/96``) addresses are judged
    by the IPv4 address they embed. A string that does not parse as an IP
    address is unsafe (fail closed); anything that is neither a string nor
    an address raises :exc:`TypeError`.
    """
    if isinstance(address, str):
        try:
            address = ip_address(address)
        except ValueError:
            return True
    elif not isinstance(address, (IPv4Address, IPv6Address)):
        raise TypeError(f"expected an IP address or a string, got {address!r}")
    ip = _effective_address(address)
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


def _effective_address(ip: _IPAddress) -> _IPAddress:
    """Return the IPv4 address an IPv4-mapped or NAT64 *ip* reaches, else *ip*.

    ``::ffff:10.0.0.1`` connects to 10.0.0.1 and ``64:ff9b::a00:1`` is
    translated to it, so both must be judged -- and matched against rules --
    as 10.0.0.1, or a rule written for 10.0.0.1 is one bracketed URL away
    from a bypass.
    """
    if isinstance(ip, IPv6Address) and any(
        ip in network for network in _IPV4_EMBEDDING_NETWORKS
    ):
        return IPv4Address(ip.packed[-4:])
    return ip


def _as_ip_literal(host: str) -> "_IPAddress | None":
    """Parse a URL host as an IP address, or return ``None`` for a hostname.

    Besides canonical text this accepts a trailing dot, which URL parsers
    following the WHATWG rules drop, and the legacy ``inet_aton`` spellings
    (``0x7f000001``, ``2130706433``, ``127.1``, ``0177.0.0.1``), which many
    resolvers and proxies map onto 127.0.0.1. Judging these as addresses is
    what keeps them from passing as hostnames, which matters most behind a
    proxy, where nothing else sees the target.
    """
    host = host.rstrip(".")
    try:
        return ip_address(host)
    except ValueError:
        pass
    # inet_aton stops reading at whitespace, so it would take
    # "1.2.3.4 x.evil.example" for 1.2.3.4 while the resolver looks up the
    # whole name; only numeric labels may reach it.
    if not all(_NUMERIC_LABEL.fullmatch(label) for label in host.split(".")):
        return None
    try:
        return IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def _normalize_hostname(host: str) -> str:
    """Fold a URL or resolver hostname into the form rules are stored in.

    The case is folded, every trailing dot is dropped (aiohttp resolves
    ``host..`` as ``host.``, which is ``host``), and the name is IDNA-encoded
    with yarl, the encoder aiohttp itself uses, so a Unicode rule and the
    punycode host aiohttp connects to compare equal. A host that yarl
    refuses comes back unchanged and so matches no hostname rule. For a
    deny rule that would fail open, because a resolver can read such a name
    as another host (getaddrinfo stops at a NUL), so the URL check refuses
    any host that does not come back as a valid hostname.
    """
    host = host.lower().rstrip(".")
    try:
        return URL.build(host=host).raw_host or host
    except (UnicodeError, ValueError):
        return host


class _Rules(NamedTuple):
    """Parsed rule entries: exact hostnames and IP networks."""

    hosts: "frozenset[str]"
    networks: "tuple[_IPNetwork, ...]"

    def contains(self, ip: _IPAddress, *, either_form: bool = False) -> bool:
        """Return True if *ip* is inside one of the networks.

        *ip* is judged as the address it reaches, so an IPv4 rule covers the
        IPv4-mapped and NAT64 spellings of its addresses. With *either_form*
        the address as written counts too, which a deny rule needs so that
        ``::/0`` or ``64:ff9b::/32`` also denies the embedded forms.
        """
        effective = _effective_address(ip)
        return any(
            effective in network or (either_form and ip in network)
            for network in self.networks
        )


def _parse_rules(entries: "Iterable[str] | None", what: str) -> _Rules:
    """Parse rule *entries* into exact hostnames and IP networks, or raise.

    A rule that cannot be parsed raises instead of becoming one that never
    matches: a silent no-op in a security rule fails open. An entry with a
    ``/`` or ``:``, or whose last label is numeric as written or once
    IDNA-encoded, must be a canonical IP address or CIDR network without
    host bits; anything else must be a hostname, which is matched exactly.
    """
    if entries is None:
        return _Rules(frozenset(), ())
    if isinstance(entries, str):
        raise TypeError(
            f"{what} must be an iterable of rules, got the string {entries!r}; "
            "a bare string would be read one character at a time"
        )
    hosts = set()
    networks = []
    for entry in entries:
        if not isinstance(entry, str):
            raise TypeError(f"{what} entries must be strings, got {entry!r}")
        last_label = entry.rstrip(".").rpartition(".")[2]
        if "/" in entry or ":" in entry or _NUMERIC_LABEL.fullmatch(last_label):
            networks.append(_parse_network(entry))
        else:
            hosts.add(_parse_hostname(entry))
    return _Rules(frozenset(hosts), tuple(networks))


def _parse_network(entry: str) -> _IPNetwork:
    """Parse an address or CIDR rule, rejecting forms that could never match."""
    try:
        network = ip_network(entry)
    except ValueError as exc:
        raise ValueError(f"invalid rule entry {entry!r}: {exc}") from None
    if isinstance(network, IPv6Network) and any(
        network.subnet_of(prefix) for prefix in _IPV4_EMBEDDING_NETWORKS
    ):
        raise ValueError(
            f"invalid rule entry {entry!r}: addresses in it are matched as the "
            "IPv4 address they embed, so write that instead"
        )
    return network


def _parse_hostname(entry: str) -> str:
    """Parse a hostname rule into its normalized ASCII form."""
    name = entry.lower().rstrip(".")
    if name.startswith("."):
        raise ValueError(
            f"invalid rule entry {entry!r}: hostnames are matched exactly, "
            "with no suffix or wildcard matching, so list each host"
        )
    try:
        encoded = URL.build(host=name).raw_host
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"invalid rule entry {entry!r}: {exc}") from None
    if not encoded or not _HOSTNAME_RULE.fullmatch(encoded):
        raise ValueError(f"invalid rule entry {entry!r}")
    # IDNA folds full-width digits and ideographic dots to ASCII, so an entry
    # that was no address as written can be one once encoded. As a hostname
    # it would match no resolved address, and as an address it is not
    # canonical, so it is refused like "127.1" is.
    if _NUMERIC_LABEL.fullmatch(encoded.rpartition(".")[2]):
        raise ValueError(
            f"invalid rule entry {entry!r}: IDNA turns it into the address "
            f"{encoded!r}; write addresses in canonical ASCII form"
        )
    return encoded


class SSRFConnector(TCPConnector):
    """A ``TCPConnector`` that refuses to reach non-public addresses.

    Every request's URL is checked in :meth:`connect`: its scheme against
    ``allowed_schemes``, its host against ``denylist`` and ``allowlist``,
    and an IP-literal host against the public-only policy; a host that is
    neither an IP address nor a valid hostname is refused. Every address a
    hostname resolves to is checked before aiohttp connects to it, and one
    unsafe address refuses the whole answer. ``exempt_hosts`` names the
    internal hosts or networks that may be reached on purpose.

    Behind a forward proxy only the proxy is resolved here; the proxy
    resolves the target. A proxied request to a hostname is therefore
    refused unless the host is allowlisted or exempt, or ``trust_proxy`` is
    set because the proxy refuses internal targets itself. A literal-IP
    target is checked either way.

    Rule entries are exact hostnames (case-insensitive, trailing dots
    ignored, IDNA-normalized, no suffix or wildcard matching) or IP
    addresses and CIDR networks; a malformed entry raises at construction.
    Every other keyword argument is passed to :class:`~aiohttp.TCPConnector`.
    """

    def __init__(
        self,
        *,
        allowlist: "Iterable[str] | None" = None,
        denylist: "Iterable[str] | None" = None,
        exempt_hosts: "Iterable[str] | None" = None,
        allowed_schemes: Iterable[str] = ("http", "https", "ws", "wss"),
        trust_proxy: bool = False,
        **kwargs: Any,
    ) -> None:
        # Validate before building the connector: a rejected rule must not
        # leave an unclosed TCPConnector behind.
        if isinstance(allowed_schemes, str):
            raise TypeError(
                f"allowed_schemes must be an iterable of schemes, got the "
                f"string {allowed_schemes!r}"
            )
        self._allowed_schemes = frozenset(scheme.lower() for scheme in allowed_schemes)
        self._allow = (
            None if allowlist is None else _parse_rules(allowlist, "allowlist")
        )
        self._deny = _parse_rules(denylist, "denylist")
        self._exempt = _parse_rules(exempt_hosts, "exempt_hosts")
        self._trust_proxy = trust_proxy
        super().__init__(**kwargs)

    async def connect(
        self, req: ClientRequest, traces: "list[Trace]", timeout: ClientTimeout
    ) -> Connection:
        """Refuse *req* unless its URL passes every rule, then connect."""
        self._check_target(req)
        return await super().connect(req, traces, timeout)

    def _check_target(self, req: ClientRequest) -> None:
        """Raise :exc:`SSRFError` unless the request URL passes every rule."""
        url = req.url
        host = url.raw_host or ""
        if url.scheme not in self._allowed_schemes:
            raise SSRFError(host, f"scheme {url.scheme!r} is not allowed")
        if not host:
            raise SSRFError(host, "the URL has no host")
        ip = _as_ip_literal(host)
        name = _normalize_hostname(host)
        if ip is None and not _HOSTNAME_RULE.fullmatch(name):
            raise SSRFError(host, "host is not a valid hostname or IP address")
        if name in self._deny.hosts or (
            ip is not None and self._deny.contains(ip, either_form=True)
        ):
            raise SSRFError(host, "host is denylisted")
        if self._allow is not None and not (
            name in self._allow.hosts or (ip is not None and self._allow.contains(ip))
        ):
            raise SSRFError(host, "host is not on the allowlist")
        if ip is not None:
            if is_unsafe_address(ip) and not self._exempt.contains(ip):
                raise SSRFError(host, "address is not publicly routable")
        elif (
            req.proxy is not None
            and self._allow is None
            and not self._trust_proxy
            and name not in self._exempt.hosts
        ):
            raise SSRFError(
                host,
                "a proxy resolves this host, so what it reaches cannot be "
                "checked; allowlist the host or set trust_proxy=True",
            )

    async def _resolve_host(
        self, host: str, port: int, traces: "Sequence[Trace] | None" = None
    ) -> "list[ResolveResult]":
        """Resolve *host*, and refuse the whole answer if any address is unsafe.

        aiohttp connects only to the addresses returned here, so a later DNS
        answer cannot swap in another one. Proxy endpoints are resolved, and
        checked, here too.
        """
        results = await super()._resolve_host(host, port, traces)
        if not results:
            raise SSRFError(host, "resolved to no addresses")
        exempt = _normalize_hostname(host) in self._exempt.hosts
        for result in results:
            resolved = result["host"]
            try:
                ip = ip_address(resolved)
            except ValueError:
                raise SSRFError(
                    host, "resolved to something that is not an IP address", resolved
                ) from None
            if self._deny.contains(ip, either_form=True):
                raise SSRFError(host, "resolved into a denylisted network", resolved)
            if not (exempt or self._exempt.contains(ip)) and is_unsafe_address(ip):
                raise SSRFError(host, "resolved to a non-public address", resolved)
        return results
