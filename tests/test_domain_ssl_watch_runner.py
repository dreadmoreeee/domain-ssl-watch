from datetime import datetime, timedelta, timezone

from domain_ssl_watch import checks
from domain_ssl_watch.runner import Backends, Config, run_checks

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class NoThrottle:
    def __init__(self):
        self.calls = 0

    def wait(self):
        self.calls += 1


def make_backends(cert_days=90, reg_days=400, rdap_calls=None, fail_hosts=()):
    rdap_calls = rdap_calls if rdap_calls is not None else []

    def resolve(host):
        if host in fail_hosts:
            raise OSError("no such host")
        return ["192.0.2.1"]

    def fetch_cert(host, port, timeout):
        return checks.CertInfo(
            not_after=NOW + timedelta(days=cert_days), issuer="Fake CA",
            sans=["example.com", "*.example.com"])

    def http(url, timeout):
        return 200, url

    def rdap(domain, base, timeout):
        rdap_calls.append((domain, base))
        if reg_days is None:
            raise checks.RdapError("RDAP HTTP 404")
        return NOW + timedelta(days=reg_days)

    return Backends(resolve=resolve, fetch_cert=fetch_cert, http_check=http,
                    rdap_expiry=rdap, throttle=NoThrottle())


def test_rdap_queried_once_per_registrable_domain():
    calls = []
    reports = run_checks(
        ["example.com", "www.example.com", "api.example.com", "example.co.uk"],
        Config(), make_backends(rdap_calls=calls), NOW)
    assert [c[0] for c in calls] == ["example.com", "example.co.uk"]
    assert all(r.reg_days == 400 for r in reports)


def test_rdap_failure_reported_unknown_and_cached():
    calls = []
    reports = run_checks(["example.com", "www.example.com"], Config(),
                         make_backends(reg_days=None, rdap_calls=calls), NOW)
    assert len(calls) == 1
    for r in reports:
        assert r.reg_expires is None
        assert "unknown" in r.notes[0]
        assert r.status == "OK"


def test_no_rdap_flag():
    calls = []
    run_checks(["example.com"], Config(use_rdap=False),
               make_backends(rdap_calls=calls), NOW)
    assert calls == []


def test_rdap_base_and_override_passed_through():
    calls = []
    cfg = Config(rdap_base="http://127.0.0.1:9", overrides={"a.example.xx": "example.xx"})
    run_checks(["a.example.xx"], cfg, make_backends(rdap_calls=calls), NOW)
    assert calls == [("example.xx", "http://127.0.0.1:9")]


def test_hostname_mismatch_detected():
    reports = run_checks(["other.net"], Config(), make_backends(), NOW)
    assert reports[0].cert_hostname_match is False
    assert reports[0].status == "CRIT"


def test_wildcard_match_and_ok():
    (r,) = run_checks(["www.example.com"], Config(), make_backends(), NOW)
    assert r.cert_hostname_match is True
    assert r.status == "OK"
    assert r.http_status == 200
    assert r.http_url == "https://www.example.com/"


def test_dns_failure_skips_tls_and_http():
    (r,) = run_checks(["nx.example.com"], Config(), make_backends(fail_hosts={"nx.example.com"}), NOW)
    assert r.status == "ERROR"
    assert r.cert_expires is None and r.http_status is None


def test_verify_error_and_http_error():
    b = make_backends()

    def bad_cert(host, port, timeout):
        raise checks.CertVerifyError("certificate has expired")

    def bad_http(url, timeout):
        raise ConnectionResetError("reset")

    b.fetch_cert, b.http_check = bad_cert, bad_http
    (r,) = run_checks(["example.com"], Config(), b, NOW)
    assert r.cert_verify_failed and r.http_error == "reset"
    assert r.status == "ERROR"


def test_throttle_called_before_every_network_stage():
    b = make_backends()
    run_checks(["example.com", "www.example.com"], Config(), b, NOW)
    # per domain: cert + http; plus a single RDAP query
    assert b.throttle.calls == 5


def test_warn_when_cert_close_to_expiry():
    (r,) = run_checks(["example.com"], Config(), make_backends(cert_days=10), NOW)
    assert r.status == "WARN"
