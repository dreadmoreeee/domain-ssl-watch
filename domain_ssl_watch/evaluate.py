"""Pure evaluation logic: turn collected facts into a status. No I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

STATUS_ORDER = ("OK", "WARN", "CRIT", "ERROR")


@dataclass
class DomainReport:
    domain: str
    registrable: str = ""
    status: str = "OK"
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # DNS
    dns_addresses: list[str] = field(default_factory=list)
    dns_error: str | None = None
    # TLS
    cert_expires: datetime | None = None
    cert_days: int | None = None
    cert_issuer: str | None = None
    cert_sans: list[str] = field(default_factory=list)
    cert_hostname_match: bool | None = None
    cert_error: str | None = None
    cert_verify_failed: bool = False
    # Registration (RDAP)
    reg_expires: datetime | None = None
    reg_days: int | None = None
    reg_error: str | None = None
    # HTTP
    http_status: int | None = None
    http_url: str | None = None
    http_error: str | None = None

    def to_dict(self) -> dict:
        def iso(value: datetime | None) -> str | None:
            return value.isoformat() if value else None

        return {
            "domain": self.domain,
            "registrable_domain": self.registrable,
            "status": self.status,
            "issues": list(self.issues),
            "notes": list(self.notes),
            "dns": {"addresses": list(self.dns_addresses), "error": self.dns_error},
            "certificate": {
                "expires": iso(self.cert_expires),
                "days_left": self.cert_days,
                "issuer": self.cert_issuer,
                "sans": list(self.cert_sans),
                "hostname_match": self.cert_hostname_match,
                "error": self.cert_error,
            },
            "registration": {
                "expires": iso(self.reg_expires),
                "days_left": self.reg_days,
                "error": self.reg_error,
            },
            "http": {
                "status": self.http_status,
                "final_url": self.http_url,
                "error": self.http_error,
            },
        }


def worst(statuses) -> str:
    result = "OK"
    for status in statuses:
        if STATUS_ORDER.index(status) > STATUS_ORDER.index(result):
            result = status
    return result


def days_until(when: datetime, now: datetime) -> int:
    """Whole days from now until when (negative once past)."""
    return (when - now).days


def level_for_days(days: int, warn_days: int, crit_days: int) -> str:
    if days <= crit_days:
        return "CRIT"
    if days <= warn_days:
        return "WARN"
    return "OK"


def _describe_days(what: str, days: int, when: datetime | None) -> str:
    date = when.strftime("%Y-%m-%d") if when else "?"
    if days < 0:
        return f"{what} expired {-days} day(s) ago ({date})"
    return f"{what} expires in {days} day(s) ({date})"


def evaluate(
    report: DomainReport, warn_days: int, crit_days: int, now: datetime
) -> DomainReport:
    """Fill in cert_days/reg_days, issues and status on report (in place)."""
    levels: list[str] = []
    report.issues = []

    if report.dns_error:
        levels.append("ERROR")
        report.issues.append(f"DNS lookup failed: {report.dns_error}")

    if report.cert_error:
        if report.cert_verify_failed:
            levels.append("CRIT")
            report.issues.append(f"certificate invalid: {report.cert_error}")
        elif not report.dns_error:
            levels.append("ERROR")
            report.issues.append(f"TLS connection failed: {report.cert_error}")
    elif report.cert_expires is not None:
        report.cert_days = days_until(report.cert_expires, now)
        level = level_for_days(report.cert_days, warn_days, crit_days)
        levels.append(level)
        if level != "OK":
            report.issues.append(
                _describe_days("certificate", report.cert_days, report.cert_expires)
            )
        if report.cert_hostname_match is False:
            levels.append("CRIT")
            report.issues.append("hostname does not match certificate SANs")

    if report.reg_expires is not None:
        report.reg_days = days_until(report.reg_expires, now)
        level = level_for_days(report.reg_days, warn_days, crit_days)
        levels.append(level)
        if level != "OK":
            report.issues.append(
                _describe_days(
                    f"domain registration ({report.registrable})",
                    report.reg_days,
                    report.reg_expires,
                )
            )
    elif report.reg_error:
        report.notes.append(f"registration expiry unknown: {report.reg_error}")

    if report.http_error:
        if not report.dns_error:
            levels.append("ERROR")
            report.issues.append(f"HTTPS request failed: {report.http_error}")
    elif report.http_status is not None and report.http_status >= 400:
        levels.append("WARN")
        report.issues.append(f"HTTP status {report.http_status}")

    report.status = worst(levels)
    return report


def exit_code(reports: list[DomainReport]) -> int:
    """0 = all OK, 1 = worst is WARN, 2 = any CRIT or ERROR."""
    overall = worst(r.status for r in reports)
    return {"OK": 0, "WARN": 1, "CRIT": 2, "ERROR": 2}[overall]
