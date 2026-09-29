"""Network checks: TLS certificate, RDAP, DNS and HTTP.

Every function here that touches the network is small and can be replaced by
an injectable callable (see runner.Backends), so the evaluation logic can be
tested with fake data.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

USER_AGENT = "domain-ssl-watch/1.0 (+https://github.com/dreadmoreeee/domain-ssl-watch)"
DEFAULT_RDAP_BASE = "https://rdap.org"

# Small list of well-known multi-part public suffixes. Anything else falls
# back to "last two labels"; use --registrable HOST=DOMAIN for the rest.
MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "com.mx", "com.ar", "com.co",
        "co.za", "co.in", "com.cn", "com.hk", "com.sg", "com.tr",
    }
)


class CertVerifyError(Exception):
    """The server presented a certificate that failed chain verification."""


class RdapError(Exception):
    """RDAP lookup failed or returned no expiration event."""


@dataclass
class CertInfo:
    not_after: datetime
    issuer: str
    sans: list[str] = field(default_factory=list)


def registrable_domain(host: str, overrides: dict[str, str] | None = None) -> str:
    """Return the registrable domain for host (simple suffix heuristic)."""
    host = host.strip().lower().rstrip(".")
    if overrides:
        for key, value in overrides.items():
            if host == key or host.endswith("." + key):
                return value.strip().lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _san_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not pattern.startswith("*."):
        return host == pattern
    # A wildcard covers exactly one label, and only as the leftmost label.
    suffix = pattern[1:]  # ".example.com"
    if not host.endswith(suffix):
        return False
    head = host[: -len(suffix)]
    return bool(head) and "." not in head


def hostname_matches(host: str, sans: list[str]) -> bool:
    return any(_san_matches(host, san) for san in sans)


def parse_certificate(cert: dict) -> CertInfo:
    """Convert the dict returned by SSLSocket.getpeercert() to a CertInfo."""
    not_after = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
    )
    issuer_fields: dict[str, str] = {}
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            issuer_fields.setdefault(key, value)
    issuer = (
        issuer_fields.get("organizationName")
        or issuer_fields.get("commonName")
        or "unknown"
    )
    cn = issuer_fields.get("commonName")
    if cn and cn != issuer:
        issuer = f"{issuer} ({cn})"
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    return CertInfo(not_after=not_after, issuer=issuer, sans=sans)


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0) -> CertInfo:
    """TLS handshake with chain verification; hostname is checked by us."""
    ctx = ssl.create_default_context()
    # Hostname matching is done separately so the SAN list can still be
    # reported when the certificate is for a different name.
    ctx.check_hostname = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise CertVerifyError(exc.verify_message or str(exc)) from exc
    if not cert:
        raise CertVerifyError("no certificate presented")
    return parse_certificate(cert)


def resolve_host(host: str) -> list[str]:
    """Return the unique addresses for host (raises OSError on failure)."""
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def http_check(url: str, timeout: float = 10.0) -> tuple[int, str]:
    """One GET, following redirects. Returns (final status, final URL)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.geturl()
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.geturl()
        finally:
            exc.close()


def _parse_event_date(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = datetime.strptime(text[:10], "%Y-%m-%d")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_rdap_expiry(data: dict) -> datetime:
    for event in data.get("events", []) or []:
        if str(event.get("eventAction", "")).lower() == "expiration":
            date = event.get("eventDate")
            if date:
                return _parse_event_date(date)
    raise RdapError("no expiration event in RDAP response")


def rdap_expiry(
    domain: str, base_url: str = DEFAULT_RDAP_BASE, timeout: float = 10.0
) -> datetime:
    """Query RDAP for the registration expiry of a registrable domain."""
    url = f"{base_url.rstrip('/')}/domain/{domain}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rdap+json, application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RdapError(f"RDAP HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise RdapError(f"RDAP lookup failed: {exc}") from exc
    if not isinstance(data, dict):
        raise RdapError("unexpected RDAP response")
    return parse_rdap_expiry(data)


class Throttle:
    """Guarantees a minimum gap between consecutive network requests."""

    def __init__(self, delay: float, clock=time.monotonic, sleep=time.sleep):
        self.delay = delay
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None:
            remaining = self.delay - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last = now
