import urllib.parse

from domain_ssl_watch import alerts
from domain_ssl_watch.evaluate import DomainReport

ENV_EMAIL = {
    "DSW_SMTP_HOST": "smtp.test", "DSW_SMTP_PORT": "2525",
    "DSW_SMTP_USER": "u", "DSW_SMTP_PASSWORD": "p",
    "DSW_ALERT_TO": "to@test", "DSW_ALERT_FROM": "from@test",
}
ENV_TG = {"DSW_TELEGRAM_BOT_TOKEN": "123:abc", "DSW_TELEGRAM_CHAT_ID": "42"}


def rep(status, domain="example.com", issues=()):
    return DomainReport(domain=domain, status=status, issues=list(issues))


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.log = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.log.append("ehlo")

    def starttls(self):
        self.log.append("starttls")

    def login(self, user, password):
        self.log.append(("login", user, password))

    def send_message(self, msg):
        self.log.append(("send", msg))


class FakeResp:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b"{}"


def setup_function():
    FakeSMTP.instances.clear()


def test_email_sent_with_starttls_and_login():
    sent, errors = alerts.send_alerts(
        [rep("CRIT", issues=["certificate expires in 2 day(s)"]), rep("OK", "fine.com")],
        ENV_EMAIL, smtp_factory=FakeSMTP)
    assert sent == ["email"] and errors == []
    smtp = FakeSMTP.instances[0]
    assert (smtp.host, smtp.port) == ("smtp.test", 2525)
    assert smtp.log.index("starttls") < smtp.log.index(("login", "u", "p"))
    msg = smtp.log[-1][1]
    assert msg["To"] == "to@test" and msg["From"] == "from@test"
    assert "CRIT" in msg["Subject"]
    body = msg.get_content()
    assert "example.com" in body and "expires in 2" in body
    assert "fine.com" not in body


def test_telegram_posts_to_bot_api():
    captured = []

    def opener(req, timeout=None):
        captured.append(req)
        return FakeResp()

    sent, errors = alerts.send_alerts([rep("WARN", issues=["x"])], ENV_TG, opener=opener)
    assert sent == ["telegram"] and errors == []
    req = captured[0]
    assert req.full_url == "https://api.telegram.org/bot123:abc/sendMessage"
    assert req.get_method() == "POST"
    form = urllib.parse.parse_qs(req.data.decode())
    assert form["chat_id"] == ["42"]
    assert "example.com" in form["text"][0]


def test_nothing_sent_when_all_ok():
    def opener(req, timeout=None):
        raise AssertionError("must not be called")

    sent, errors = alerts.send_alerts([rep("OK")], {**ENV_EMAIL, **ENV_TG},
                                      smtp_factory=FakeSMTP, opener=opener)
    assert sent == [] and errors == []
    assert FakeSMTP.instances == []


def test_not_configured_reports_message():
    sent, errors = alerts.send_alerts([rep("WARN")], {}, smtp_factory=FakeSMTP)
    assert sent == []
    assert "no alert channel" in errors[0]


def test_failures_are_reported_not_raised():
    def bad_smtp(*a, **k):
        raise OSError("connection refused")

    def bad_opener(req, timeout=None):
        raise OSError("network down")

    sent, errors = alerts.send_alerts([rep("CRIT")], {**ENV_EMAIL, **ENV_TG},
                                      smtp_factory=bad_smtp, opener=bad_opener)
    assert sent == []
    assert len(errors) == 2


def test_default_smtp_port_and_no_login_without_user():
    env = {"DSW_SMTP_HOST": "h", "DSW_ALERT_TO": "a@b", "DSW_ALERT_FROM": "c@d"}
    alerts.send_alerts([rep("WARN")], env, smtp_factory=FakeSMTP)
    smtp = FakeSMTP.instances[0]
    assert smtp.port == 587
    assert not any(isinstance(x, tuple) and x[0] == "login" for x in smtp.log)
