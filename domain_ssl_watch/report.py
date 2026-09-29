"""Output formatters: table (default), json, markdown."""

from __future__ import annotations

import json
from datetime import datetime

from .evaluate import DomainReport, worst

HEADERS = [
    "DOMAIN", "STATUS", "CERT EXPIRES", "CERT DAYS", "ISSUER",
    "SAN MATCH", "REG EXPIRES", "REG DAYS", "DNS", "HTTP",
]


def _date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "-"


def _num(value: int | None) -> str:
    return "-" if value is None else str(value)


def _row(r: DomainReport) -> list[str]:
    if r.cert_hostname_match is None:
        san = "-"
    else:
        san = "yes" if r.cert_hostname_match else "NO"
    if r.http_status is not None:
        http = str(r.http_status)
    else:
        http = "ERR" if r.http_error else "-"
    return [
        r.domain,
        r.status,
        _date(r.cert_expires),
        _num(r.cert_days),
        r.cert_issuer or "-",
        san,
        _date(r.reg_expires) if r.reg_expires else "unknown" if r.reg_error else "-",
        _num(r.reg_days),
        "FAIL" if r.dns_error else "ok",
        http,
    ]


def _notes(r: DomainReport) -> list[str]:
    notes = list(r.issues) + list(r.notes)
    if r.http_url and r.http_url != f"https://{r.domain}/":
        notes.append(f"HTTP final URL: {r.http_url}")
    return notes


def format_table(reports: list[DomainReport]) -> str:
    rows = [HEADERS] + [_row(r) for r in reports]
    widths = [max(len(row[i]) for row in rows) for i in range(len(HEADERS))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
             for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    out = "\n".join(lines)
    notes = [f"{r.domain}: {n}" for r in reports for n in _notes(r)]
    if notes:
        out += "\n\nNotes:\n" + "\n".join(f"  {n}" for n in notes)
    out += f"\n\nOverall: {worst(r.status for r in reports)}"
    return out


def format_json(reports: list[DomainReport], now: datetime) -> str:
    payload = {
        "generated": now.isoformat(),
        "overall": worst(r.status for r in reports),
        "results": [r.to_dict() for r in reports],
    }
    return json.dumps(payload, indent=2)


def format_markdown(reports: list[DomainReport], now: datetime) -> str:
    def cell(text: str) -> str:
        return text.replace("|", "\\|")

    lines = [
        "| " + " | ".join(HEADERS) + " |",
        "|" + "|".join(" --- " for _ in HEADERS) + "|",
    ]
    for r in reports:
        lines.append("| " + " | ".join(cell(c) for c in _row(r)) + " |")
    notes = [f"- **{r.domain}**: {n}" for r in reports for n in _notes(r)]
    out = "\n".join(lines)
    if notes:
        out += "\n\n" + "\n".join(notes)
    out += (
        f"\n\nOverall: **{worst(r.status for r in reports)}** "
        f"(checked {now.strftime('%Y-%m-%d %H:%M UTC')})"
    )
    return out


def render(fmt: str, reports: list[DomainReport], now: datetime) -> str:
    if fmt == "json":
        return format_json(reports, now)
    if fmt == "markdown":
        return format_markdown(reports, now)
    return format_table(reports)
