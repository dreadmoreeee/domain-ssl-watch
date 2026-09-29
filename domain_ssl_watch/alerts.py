"""Optional alerts: SMTP email and Telegram. Never required."""

from __future__ import annotations

import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Mapping

from .checks import USER_AGENT
from .evaluate import DomainReport, worst

TELEGRAM_API = "https://api.telegram.org"


def build_alert_text(reports: list[DomainReport]) -> tuple[str, str]:
    """Return (subject, body) listing domains that are WARN or worse."""
    bad = [r for r in reports if r.status != "OK"]
    overall = worst(r.status for r in reports)
    subject = f"[domain-ssl-watch] {overall}: {len(bad)} of {len(reports)} domain(s) need attention"
    lines = []
    for r in bad:
        lines.append(f"{r.status} {r.domain}")
        for issue in r.issues:
            lines.append(f"  - {issue}")
    return subject, "\n".join(lines)


def email_configured(env: Mapping[str, str]) -> bool:
    return all(env.get(k) for k in ("DSW_SMTP_HOST", "DSW_ALERT_TO", "DSW_ALERT_FROM"))


def telegram_configured(env: Mapping[str, str]) -> bool:
    return all(env.get(k) for k in ("DSW_TELEGRAM_BOT_TOKEN", "DSW_TELEGRAM_CHAT_ID"))


def send_email(env: Mapping[str, str], subject: str, body: str, smtp_factory=None) -> None:
    smtp_factory = smtp_factory or smtplib.SMTP
    host = env["DSW_SMTP_HOST"]
    port = int(env.get("DSW_SMTP_PORT") or 587)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = env["DSW_ALERT_FROM"]
    msg["To"] = env["DSW_ALERT_TO"]
    msg.set_content(body)
    with smtp_factory(host, port, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        user = env.get("DSW_SMTP_USER")
        if user:
            smtp.login(user, env.get("DSW_SMTP_PASSWORD", ""))
        smtp.send_message(msg)


def send_telegram(env: Mapping[str, str], text: str, opener=None) -> None:
    opener = opener or urllib.request.urlopen
    token = env["DSW_TELEGRAM_BOT_TOKEN"]
    data = urllib.parse.urlencode(
        {"chat_id": env["DSW_TELEGRAM_CHAT_ID"], "text": text[:4000]}
    ).encode("ascii")
    req = urllib.request.Request(
        f"{TELEGRAM_API}/bot{token}/sendMessage",
        data=data,
        headers={"User-Agent": USER_AGENT},
        method="POST",
    )
    with opener(req, timeout=30) as resp:
        resp.read()


def send_alerts(
    reports: list[DomainReport],
    env: Mapping[str, str],
    smtp_factory=None,
    opener=None,
) -> tuple[list[str], list[str]]:
    """Send alerts if any report is WARN or worse.

    Returns (channels_sent, error_messages). Does nothing when everything is
    OK or when no channel is configured.
    """
    sent: list[str] = []
    errors: list[str] = []
    if worst(r.status for r in reports) == "OK":
        return sent, errors
    subject, body = build_alert_text(reports)
    if email_configured(env):
        try:
            send_email(env, subject, body, smtp_factory)
            sent.append("email")
        except Exception as exc:  # alert failure must not hide the results
            errors.append(f"email alert failed: {exc}")
    if telegram_configured(env):
        try:
            send_telegram(env, subject + "\n" + body, opener)
            sent.append("telegram")
        except Exception as exc:
            errors.append(f"telegram alert failed: {exc}")
    if not sent and not errors:
        errors.append("--alert given but no alert channel is configured")
    return sent, errors
