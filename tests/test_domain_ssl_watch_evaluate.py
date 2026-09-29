from datetime import datetime, timedelta, timezone

import pytest

from domain_ssl_watch.evaluate import (
    DomainReport, evaluate, exit_code, level_for_days, worst,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make(**kw):
    base = dict(
        domain="example.com", registrable="example.com",
        cert_expires=NOW + timedelta(days=90), cert_hostname_match=True,
        reg_expires=NOW + timedelta(days=400), http_status=200,
    )
    base.update(kw)
    return DomainReport(**base)


def test_all_ok():
    r = evaluate(make(), 30, 7, NOW)
    assert r.status == "OK"
    assert r.cert_days == 90
    assert r.reg_days == 400
    assert r.issues == []


@pytest.mark.parametrize(
    "days,expected",
    [(31, "OK"), (30, "WARN"), (8, "WARN"), (7, "CRIT"), (0, "CRIT"), (-3, "CRIT")],
)
def test_level_for_days(days, expected):
    assert level_for_days(days, 30, 7) == expected


def test_cert_warn():
    r = evaluate(make(cert_expires=NOW + timedelta(days=20, hours=3)), 30, 7, NOW)
    assert r.status == "WARN"
    assert r.cert_days == 20
    assert "certificate expires in 20" in r.issues[0]


def test_cert_expired_is_crit():
    r = evaluate(make(cert_expires=NOW - timedelta(days=2)), 30, 7, NOW)
    assert r.status == "CRIT"
    assert "expired" in r.issues[0]


def test_registration_crit():
    r = evaluate(make(reg_expires=NOW + timedelta(days=3)), 30, 7, NOW)
    assert r.status == "CRIT"
    assert "registration" in r.issues[0]


def test_custom_thresholds():
    r = evaluate(make(cert_expires=NOW + timedelta(days=50)), 60, 55, NOW)
    assert r.status == "CRIT"


def test_hostname_mismatch_is_crit():
    r = evaluate(make(cert_hostname_match=False), 30, 7, NOW)
    assert r.status == "CRIT"
    assert any("SAN" in i for i in r.issues)


def test_verify_failure_is_crit():
    r = evaluate(
        make(cert_expires=None, cert_hostname_match=None,
             cert_error="certificate has expired", cert_verify_failed=True),
        30, 7, NOW)
    assert r.status == "CRIT"
    assert "certificate invalid" in r.issues[0]


def test_connection_failure_is_error():
    r = evaluate(
        make(cert_expires=None, cert_hostname_match=None, cert_error="refused",
             http_status=None, http_error="refused"),
        30, 7, NOW)
    assert r.status == "ERROR"


def test_dns_failure_is_error_without_duplicate_issues():
    r = evaluate(
        DomainReport(domain="nx.example.com", registrable="example.com",
                     dns_error="not found", reg_expires=NOW + timedelta(days=400)),
        30, 7, NOW)
    assert r.status == "ERROR"
    assert len(r.issues) == 1


def test_rdap_unknown_is_only_a_note():
    r = evaluate(make(reg_expires=None, reg_error="RDAP HTTP 404"), 30, 7, NOW)
    assert r.status == "OK"
    assert r.reg_days is None
    assert "unknown" in r.notes[0]


def test_http_error_status_is_warn():
    r = evaluate(make(http_status=503), 30, 7, NOW)
    assert r.status == "WARN"


def test_worst_and_exit_code():
    assert worst(["OK", "WARN", "OK"]) == "WARN"
    assert worst(["CRIT", "ERROR"]) == "ERROR"
    assert worst([]) == "OK"

    def rep(status):
        return DomainReport(domain="x", status=status)

    assert exit_code([rep("OK")]) == 0
    assert exit_code([rep("OK"), rep("WARN")]) == 1
    assert exit_code([rep("WARN"), rep("CRIT")]) == 2
    assert exit_code([rep("ERROR")]) == 2


def test_to_dict_is_json_serialisable():
    import json
    r = evaluate(make(cert_issuer="CA", cert_sans=["example.com"]), 30, 7, NOW)
    data = json.loads(json.dumps(r.to_dict()))
    assert data["certificate"]["days_left"] == 90
    assert data["registration"]["expires"].startswith("2027")
