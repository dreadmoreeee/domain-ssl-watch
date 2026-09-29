"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .alerts import send_alerts
from .evaluate import exit_code
from .report import render
from .runner import Backends, Config, run_checks

EPILOG = """\
exit codes:
  0  every domain is OK
  1  worst status is WARN
  2  at least one domain is CRIT or ERROR (also used for usage errors)
"""


def normalize_domain(text: str) -> str:
    value = text.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/", 1)[0].split("?", 1)[0]
    return value.rstrip(".")


def read_domain_file(path: str) -> list[str]:
    domains = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.split("#", 1)[0].strip()
            if entry:
                domains.append(normalize_domain(entry))
    return domains


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-ssl-watch",
        description="Check TLS certificate expiry, domain registration expiry "
        "(RDAP), DNS and HTTP status for a list of domains.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN", help="domains to check")
    parser.add_argument("-f", "--file", action="append", default=[],
                        help="file with one domain per line (# starts a comment)")
    parser.add_argument("--warn-days", type=int, default=30,
                        help="WARN at or below this many days left (default 30)")
    parser.add_argument("--crit-days", type=int, default=7,
                        help="CRIT at or below this many days left (default 7)")
    parser.add_argument("--format", choices=("table", "json", "markdown"),
                        default="table", help="output format (default table)")
    parser.add_argument("--alert", action="store_true",
                        help="send email/Telegram alerts when status is WARN or worse")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="network timeout in seconds (default 10)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="minimum seconds between network requests (default 1.0)")
    parser.add_argument("--rdap-base", default=os.environ.get("DSW_RDAP_BASE", "https://rdap.org"),
                        help="RDAP base URL (default https://rdap.org)")
    parser.add_argument("--no-rdap", action="store_true",
                        help="skip the domain registration (RDAP) check")
    parser.add_argument("--registrable", action="append", default=[], metavar="HOST=DOMAIN",
                        help="override the registrable domain used for RDAP, "
                        "e.g. example.gov.xx=example.gov.xx (repeatable)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv=None, env=None, backends: Backends | None = None,
         now: datetime | None = None, smtp_factory=None, opener=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    env = os.environ if env is None else env

    domains: list[str] = [normalize_domain(d) for d in args.domains]
    for path in args.file:
        try:
            domains.extend(read_domain_file(path))
        except OSError as exc:
            parser.error(f"cannot read {path}: {exc}")
    domains = list(dict.fromkeys(d for d in domains if d))
    if not domains:
        parser.error("no domains given (use DOMAIN arguments or -f FILE)")
    if args.crit_days > args.warn_days:
        parser.error("--crit-days must not exceed --warn-days")

    overrides = {}
    for item in args.registrable:
        if "=" not in item:
            parser.error(f"--registrable expects HOST=DOMAIN, got {item!r}")
        host, reg = item.split("=", 1)
        overrides[normalize_domain(host)] = normalize_domain(reg)

    cfg = Config(
        warn_days=args.warn_days, crit_days=args.crit_days, timeout=args.timeout,
        delay=args.delay, rdap_base=args.rdap_base, use_rdap=not args.no_rdap,
        overrides=overrides,
    )
    now = now or datetime.now(timezone.utc)
    reports = run_checks(domains, cfg, backends or Backends(), now)

    print(render(args.format, reports, now))

    if args.alert:
        sent, errors = send_alerts(reports, env, smtp_factory, opener)
        for channel in sent:
            print(f"alert sent via {channel}", file=sys.stderr)
        for message in errors:
            print(message, file=sys.stderr)

    return exit_code(reports)


if __name__ == "__main__":
    sys.exit(main())
