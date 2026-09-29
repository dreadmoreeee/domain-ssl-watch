import http.server
import json
import ssl
import threading
from datetime import datetime, timezone

import pytest

from domain_ssl_watch import checks


# ---------------------------------------------------------------- helpers

class _Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}
    seen: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).seen.append((self.path, self.headers.get("User-Agent")))
        status, headers, body = self.routes.get(self.path, (404, {}, b"nope"))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    handler = type("H", (_Handler,), {"routes": {}, "seen": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    handler.base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield handler
    srv.shutdown()
    srv.server_close()


# ------------------------------------------------- registrable / matching

@pytest.mark.parametrize(
    "host,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("a.b.example.ca", "example.ca"),
        ("shop.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("www.example.com.au", "example.com.au"),
        ("Example.COM.", "example.com"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host, expected):
    assert checks.registrable_domain(host) == expected


def test_registrable_override():
    overrides = {"portal.example.gov.xx": "example.gov.xx"}
    assert checks.registrable_domain("portal.example.gov.xx", overrides) == "example.gov.xx"
    assert checks.registrable_domain("a.portal.example.gov.xx", overrides) == "example.gov.xx"
    assert checks.registrable_domain("other.example.com", overrides) == "example.com"


@pytest.mark.parametrize(
    "host,sans,expected",
    [
        ("example.com", ["example.com"], True),
        ("EXAMPLE.com", ["example.COM"], True),
        ("www.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], False),
        ("a.b.example.com", ["*.example.com"], False),
        ("www.example.com", ["example.com"], False),
        ("evilexample.com", ["*.example.com"], False),
        ("www.example.com", ["example.com", "*.example.com"], True),
        ("example.com", [], False),
    ],
)
def test_hostname_matches(host, sans, expected):
    assert checks.hostname_matches(host, sans) is expected


def test_parse_certificate():
    cert = {
        "notAfter": "Jan  5 09:34:43 2030 GMT",
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Example CA"),),
            (("commonName", "Example CA R3"),),
        ),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"), ("IP Address", "1.2.3.4")),
    }
    info = checks.parse_certificate(cert)
    assert info.not_after == datetime(2030, 1, 5, 9, 34, 43, tzinfo=timezone.utc)
    assert info.issuer == "Example CA (Example CA R3)"
    assert info.sans == ["example.com", "*.example.com"]


# ------------------------------------------------------------- TLS (mock)

class _FakeTLS:
    def __init__(self, cert):
        self.cert = cert

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self):
        return self.cert


class _FakeCtx:
    def __init__(self, cert=None, error=None):
        self.cert, self.error = cert, error
        self.check_hostname = True
        self.server_hostname = None

    def wrap_socket(self, sock, server_hostname=None):
        self.server_hostname = server_hostname
        if self.error:
            raise self.error
        return _FakeTLS(self.cert)


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_tls(monkeypatch, ctx):
    calls = []

    def fake_connect(addr, timeout=None):
        calls.append((addr, timeout))
        return _FakeSock()

    monkeypatch.setattr(checks.socket, "create_connection", fake_connect)
    monkeypatch.setattr(checks.ssl, "create_default_context", lambda: ctx)
    return calls


def test_fetch_certificate_ok(monkeypatch):
    cert = {
        "notAfter": "Jan  5 09:34:43 2030 GMT",
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
    }
    ctx = _FakeCtx(cert=cert)
    calls = _patch_tls(monkeypatch, ctx)
    info = checks.fetch_certificate("example.com", 443, 5.0)
    assert info.sans == ["example.com"]
    assert info.issuer == "Test CA"
    assert calls == [(("example.com", 443), 5.0)]
    assert ctx.server_hostname == "example.com"
    assert ctx.check_hostname is False


def test_fetch_certificate_verify_failure(monkeypatch):
    err = ssl.SSLCertVerificationError(1, "certificate verify failed")
    err.verify_message = "certificate has expired"
    _patch_tls(monkeypatch, _FakeCtx(error=err))
    with pytest.raises(checks.CertVerifyError, match="expired"):
        checks.fetch_certificate("example.com")


def test_fetch_certificate_connection_error_propagates(monkeypatch):
    def boom(addr, timeout=None):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(checks.socket, "create_connection", boom)
    monkeypatch.setattr(checks.ssl, "create_default_context", lambda: _FakeCtx())
    with pytest.raises(ConnectionRefusedError):
        checks.fetch_certificate("example.com")


# ------------------------------------------------------------------- DNS

def test_resolve_host_dedupes(monkeypatch):
    infos = [
        (2, 1, 6, "", ("1.2.3.4", 443)),
        (2, 1, 6, "", ("1.2.3.4", 443)),
        (10, 1, 6, "", ("::1", 443, 0, 0)),
    ]
    monkeypatch.setattr(checks.socket, "getaddrinfo", lambda *a, **k: infos)
    assert checks.resolve_host("example.com") == ["1.2.3.4", "::1"]


# ------------------------------------------------------------------ HTTP

def test_http_check_ok_and_user_agent(server):
    server.routes["/"] = (200, {}, b"hello")
    status, url = checks.http_check(server.base + "/", timeout=5)
    assert (status, url) == (200, server.base + "/")
    assert server.seen[0][1] == checks.USER_AGENT


def test_http_check_follows_redirect(server):
    server.routes["/"] = (301, {"Location": "/final"}, b"")
    server.routes["/final"] = (200, {}, b"ok")
    status, url = checks.http_check(server.base + "/", timeout=5)
    assert status == 200
    assert url == server.base + "/final"


def test_http_check_error_status(server):
    status, url = checks.http_check(server.base + "/missing", timeout=5)
    assert status == 404
    assert url.endswith("/missing")


def test_http_check_connection_refused():
    with pytest.raises(OSError):
        checks.http_check("http://127.0.0.1:1/", timeout=2)


# ------------------------------------------------------------------ RDAP

def test_parse_rdap_expiry():
    data = {"events": [
        {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2031-03-04T12:30:00Z"},
    ]}
    assert checks.parse_rdap_expiry(data) == datetime(2031, 3, 4, 12, 30, tzinfo=timezone.utc)


def test_parse_rdap_expiry_offset_and_date_only():
    a = checks.parse_rdap_expiry({"events": [{"eventAction": "expiration", "eventDate": "2031-03-04T00:00:00+02:00"}]})
    assert a.utcoffset().total_seconds() == 7200
    b = checks.parse_rdap_expiry({"events": [{"eventAction": "expiration", "eventDate": "2031-03-04"}]})
    assert b.year == 2031 and b.tzinfo is not None


def test_parse_rdap_expiry_missing():
    with pytest.raises(checks.RdapError):
        checks.parse_rdap_expiry({"events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}]})
    with pytest.raises(checks.RdapError):
        checks.parse_rdap_expiry({})


def test_rdap_expiry_with_redirect(server):
    body = json.dumps({"events": [{"eventAction": "expiration", "eventDate": "2030-06-01T00:00:00Z"}]}).encode()
    server.routes["/domain/example.com"] = (302, {"Location": "/real/example.com"}, b"")
    server.routes["/real/example.com"] = (200, {"Content-Type": "application/rdap+json"}, body)
    when = checks.rdap_expiry("example.com", server.base, timeout=5)
    assert when == datetime(2030, 6, 1, tzinfo=timezone.utc)
    assert server.seen[0][1] == checks.USER_AGENT


def test_rdap_expiry_http_error(server):
    with pytest.raises(checks.RdapError, match="404"):
        checks.rdap_expiry("nothing.example", server.base, timeout=5)


def test_rdap_expiry_bad_json(server):
    server.routes["/domain/example.com"] = (200, {}, b"<html>not json</html>")
    with pytest.raises(checks.RdapError):
        checks.rdap_expiry("example.com", server.base, timeout=5)


def test_rdap_expiry_unreachable():
    with pytest.raises(checks.RdapError):
        checks.rdap_expiry("example.com", "http://127.0.0.1:1", timeout=2)


# -------------------------------------------------------------- Throttle

def test_throttle_enforces_gap():
    now = [100.0]
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    th = checks.Throttle(1.0, clock=lambda: now[0], sleep=sleep)
    th.wait()              # first call never sleeps
    now[0] += 0.25
    th.wait()              # 0.75 s still owed
    th.wait()              # a full second owed again
    assert slept == [pytest.approx(0.75), pytest.approx(1.0)]
