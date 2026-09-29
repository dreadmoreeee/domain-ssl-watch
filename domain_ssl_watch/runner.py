"""Collect facts for each domain using injectable backends, then evaluate."""

from __future__ import annotations

import http.client
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from . import checks
from .evaluate import DomainReport, evaluate


@dataclass
class Config:
    warn_days: int = 30
    crit_days: int = 7
    timeout: float = 10.0
    delay: float = 1.0
    rdap_base: str = checks.DEFAULT_RDAP_BASE
    use_rdap: bool = True
    overrides: dict[str, str] = field(default_factory=dict)


@dataclass
class Backends:
    """Network operations; replace any of them to test without a network."""

    resolve: Callable[[str], list[str]] = checks.resolve_host
    fetch_cert: Callable[[str, int, float], checks.CertInfo] = checks.fetch_certificate
    http_check: Callable[[str, float], tuple[int, str]] = checks.http_check
    rdap_expiry: Callable[[str, str, float], datetime] = checks.rdap_expiry
    throttle: checks.Throttle | None = None


def check_domain(
    domain: str,
    cfg: Config,
    backends: Backends,
    rdap_cache: dict[str, tuple[datetime | None, str | None]],
    now: datetime,
) -> DomainReport:
    report = DomainReport(domain=domain)
    report.registrable = checks.registrable_domain(domain, cfg.overrides)
    throttle = backends.throttle or checks.Throttle(cfg.delay)

    try:
        report.dns_addresses = backends.resolve(domain)
    except OSError as exc:
        report.dns_error = str(exc)

    if not report.dns_error:
        throttle.wait()
        try:
            info = backends.fetch_cert(domain, 443, cfg.timeout)
            report.cert_expires = info.not_after
            report.cert_issuer = info.issuer
            report.cert_sans = list(info.sans)
            report.cert_hostname_match = checks.hostname_matches(domain, info.sans)
        except checks.CertVerifyError as exc:
            report.cert_error = str(exc)
            report.cert_verify_failed = True
        except (OSError, ValueError) as exc:
            report.cert_error = str(exc) or type(exc).__name__

        throttle.wait()
        try:
            status, final_url = backends.http_check(f"https://{domain}/", cfg.timeout)
            report.http_status = status
            report.http_url = final_url
        except (OSError, http.client.HTTPException, ValueError) as exc:
            report.http_error = str(exc) or type(exc).__name__

    if cfg.use_rdap:
        reg = report.registrable
        if reg not in rdap_cache:
            throttle.wait()
            try:
                rdap_cache[reg] = (
                    backends.rdap_expiry(reg, cfg.rdap_base, cfg.timeout),
                    None,
                )
            except (checks.RdapError, OSError, ValueError) as exc:
                rdap_cache[reg] = (None, str(exc))
        report.reg_expires, report.reg_error = rdap_cache[reg]

    return evaluate(report, cfg.warn_days, cfg.crit_days, now)


def run_checks(
    domains: list[str], cfg: Config, backends: Backends, now: datetime
) -> list[DomainReport]:
    if backends.throttle is None:
        backends.throttle = checks.Throttle(cfg.delay)
    cache: dict[str, tuple[datetime | None, str | None]] = {}
    return [check_domain(d, cfg, backends, cache, now) for d in domains]
