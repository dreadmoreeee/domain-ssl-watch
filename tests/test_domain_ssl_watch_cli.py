import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from domain_ssl_watch import checks
from domain_ssl_watch.cli import main, normalize_domain, read_domain_file
from domain_ssl_watch.runner import Backends

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parent.parent


class NoThrottle:
    def wait(self):
        pass


def backends(cert_days=90, reg_days=400):
    return Backends(
        resolve=lambda host: ["192.0.2.1"],
        fetch_cert=lambda h, p, t: checks.CertInfo(
            NOW + timedelta(days=cert_days), "Fake CA", ["example.com", "*.example.com"]),
        http_check=lambda url, t: (200, url),
        rdap_expiry=lambda d, b, t: NOW + timedelta(days=reg_days),
        throttle=NoThrottle(),
    )


def test_normalize_domain():
    assert normalize_domain(" HTTPS://Example.com/path?x=1 ") == "example.com"
    assert normalize_domain("example.com.") == "example.com"


def test_read_domain_file_comments(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("# header\nexample.com\n\n  www.example.com   # trailing\n#skip.com\n", encoding="utf-8")
    assert read_domain_file(str(f)) == ["example.com", "www.example.com"]


def test_table_output_and_exit_ok(capsys):
    code = main(["example.com", "--delay", "0"], backends=backends(), now=NOW)
    out = capsys.readouterr().out
    assert code == 0
    assert "DOMAIN" in out.splitlines()[0]
    assert "example.com" in out and "Fake CA" in out and "OK" in out
    assert "Overall: OK" in out


def test_exit_codes(capsys):
    assert main(["example.com"], backends=backends(cert_days=20), now=NOW) == 1
    assert main(["example.com"], backends=backends(cert_days=3), now=NOW) == 2
    assert main(["example.com", "--warn-days", "100"], backends=backends(cert_days=90), now=NOW) == 1
    assert main(["example.com", "--warn-days", "100", "--crit-days", "95"],
                backends=backends(cert_days=90), now=NOW) == 2
    capsys.readouterr()


def test_error_exit_code(capsys):
    b = backends()
    b.resolve = lambda host: (_ for _ in ()).throw(OSError("nope"))
    assert main(["example.com"], backends=b, now=NOW) == 2
    capsys.readouterr()


def test_json_format(capsys):
    main(["example.com", "www.example.com", "--format", "json"], backends=backends(), now=NOW)
    data = json.loads(capsys.readouterr().out)
    assert data["overall"] == "OK"
    assert [r["domain"] for r in data["results"]] == ["example.com", "www.example.com"]
    assert data["results"][0]["certificate"]["sans"] == ["example.com", "*.example.com"]
    assert data["results"][1]["registrable_domain"] == "example.com"


def test_markdown_format(capsys):
    main(["example.com", "--format", "markdown"], backends=backends(cert_days=20), now=NOW)
    out = capsys.readouterr().out
    assert out.startswith("| DOMAIN |")
    assert "| WARN |" in out
    assert "certificate expires in 20" in out


def test_domain_file_and_dedupe(tmp_path, capsys):
    f = tmp_path / "d.txt"
    f.write_text("example.com # dup\nwww.example.com\n", encoding="utf-8")
    main(["example.com", "-f", str(f), "--format", "json"], backends=backends(), now=NOW)
    data = json.loads(capsys.readouterr().out)
    assert [r["domain"] for r in data["results"]] == ["example.com", "www.example.com"]


def test_no_domains_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main([], backends=backends(), now=NOW)
    assert exc.value.code == 2
    capsys.readouterr()


def test_missing_file_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["-f", "does-not-exist.txt"], backends=backends(), now=NOW)
    assert exc.value.code == 2
    capsys.readouterr()


def test_alert_only_when_warn_or_worse(capsys):
    sent = []

    class SMTP:
        def __init__(self, *a, **k):
            sent.append("connect")

        def __enter__(self):
            return self

        def __exit__(self, *e):
            return False

        def ehlo(self): pass
        def starttls(self): pass
        def login(self, *a): pass
        def send_message(self, msg): sent.append(msg["Subject"])

    env = {"DSW_SMTP_HOST": "h", "DSW_ALERT_TO": "a@b", "DSW_ALERT_FROM": "c@d"}
    main(["example.com", "--alert"], env=env, backends=backends(), now=NOW, smtp_factory=SMTP)
    assert sent == []
    code = main(["example.com", "--alert"], env=env, backends=backends(cert_days=3),
                now=NOW, smtp_factory=SMTP)
    assert code == 2
    assert sent[0] == "connect" and "CRIT" in sent[1]
    capsys.readouterr()


def test_no_alert_without_flag(capsys):
    def factory(*a, **k):
        raise AssertionError("SMTP must not be used without --alert")

    env = {"DSW_SMTP_HOST": "h", "DSW_ALERT_TO": "a@b", "DSW_ALERT_FROM": "c@d"}
    assert main(["example.com"], env=env, backends=backends(cert_days=3),
                now=NOW, smtp_factory=factory) == 2
    capsys.readouterr()


def test_python_dash_m_help():
    proc = subprocess.run([sys.executable, "-m", "domain_ssl_watch", "--help"],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "exit codes" in proc.stdout


def test_sources_are_ascii():
    for path in list((ROOT / "domain_ssl_watch").glob("*.py")) + list((ROOT / "tests").glob("*.py")):
        path.read_bytes().decode("ascii")
