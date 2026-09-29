# domain-ssl-watch

Watch a list of domains and report, for each one, the TLS certificate expiry, the domain registration expiry (via RDAP), whether DNS resolves and the final HTTPS status. Built for cron: the exit code tells you when something needs attention. Python standard library only.

## Why

Expired certificates and lapsed domain registrations are boring, avoidable outages. This tool checks the things that actually expire, in one command, without an account or a background service.

For every domain it reports:

- **Certificate**: expiry date, days left, issuer, SAN list, and whether the hostname matches the SANs (wildcards supported).
- **Registration**: expiry date from RDAP. Subdomains are folded into their registrable domain, which is queried once per run.
- **DNS and HTTP**: whether the name resolves, and the final status code and URL of one `GET https://<domain>/` (redirects followed).

## Install

Requires Python 3.10+.

```
pip install .
```

or run it in place with `python -m domain_ssl_watch`.

## Usage

```
domain-ssl-watch example.com www.example.org
domain-ssl-watch -f domains.txt --warn-days 45 --crit-days 14
domain-ssl-watch -f domains.txt --format markdown
```

The domains file has one domain per line; `#` starts a comment (see `examples/domains.txt`).

| Option | Default | Meaning |
| --- | --- | --- |
| `-f, --file FILE` | | file with domains (repeatable) |
| `--warn-days N` | 30 | WARN at or below N days left (certificate or registration) |
| `--crit-days N` | 7 | CRIT at or below N days left |
| `--format` | `table` | `table`, `json` or `markdown` |
| `--alert` | off | send email/Telegram when status is WARN or worse |
| `--timeout S` | 10 | network timeout in seconds |
| `--delay S` | 1.0 | minimum gap between network requests |
| `--rdap-base URL` | `https://rdap.org` | RDAP endpoint (also `DSW_RDAP_BASE`) |
| `--registrable HOST=DOMAIN` | | override the registrable domain for RDAP (repeatable) |
| `--no-rdap` | off | skip the registration check |

Status per domain is `OK`, `WARN`, `CRIT` or `ERROR`:

- `WARN`: certificate or registration within `--warn-days`, or the final HTTP status is 400 or above.
- `CRIT`: within `--crit-days` (or already expired), certificate fails verification, or the hostname does not match the SANs.
- `ERROR`: DNS, TLS connection or HTTPS request failed.

An RDAP failure never changes the status; the registration expiry is shown as `unknown`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | every domain is OK |
| 1 | worst status is WARN |
| 2 | at least one CRIT or ERROR (also usage errors) |

Ready-made schedules are in `examples/`: a crontab line, a systemd service and timer, and a GitHub Actions workflow.

## Alerts configuration

Alerts are optional and only sent with `--alert`, and only when the overall status is WARN or worse. Configure either channel, or both, with environment variables.

Email (SMTP with STARTTLS):

```
DSW_SMTP_HOST=smtp.example.com
DSW_SMTP_PORT=587            # default 587
DSW_SMTP_USER=alerts@example.com
DSW_SMTP_PASSWORD=...
DSW_ALERT_TO=you@example.com
DSW_ALERT_FROM=alerts@example.com
```

Telegram (Bot API):

```
DSW_TELEGRAM_BOT_TOKEN=123456:ABC...
DSW_TELEGRAM_CHAT_ID=123456789
```

If `--alert` is given and nothing is configured, a message is printed to stderr. A failed alert is reported on stderr and does not change the exit code.

## Measured result

One real run, no `--alert`, against three hostnames I operate. Traffic was 3 HTTPS GETs and 1 RDAP GET to rdap.org (4 HTTP requests in total, at least 1 s apart, identifying User-Agent), plus 3 TLS handshakes and DNS lookups.

```
python -m domain_ssl_watch demarkstudio.ca demo.demarkstudio.ca marvin.demarkstudio.ca
```

```
DOMAIN                  STATUS  CERT EXPIRES  CERT DAYS  ISSUER                       SAN MATCH  REG EXPIRES  REG DAYS  DNS  HTTP
----------------------  ------  ------------  ---------  ---------------------------  ---------  -----------  --------  ---  ----
demarkstudio.ca         OK      2026-12-10    71         Google Trust Services (WE1)  yes        2027-09-11   346       ok   200
demo.demarkstudio.ca    OK      2026-12-10    71         Google Trust Services (WE1)  yes        2027-09-11   346       ok   200
marvin.demarkstudio.ca  OK      2026-12-10    71         Google Trust Services (WE1)  yes        2027-09-11   346       ok   200

Notes:
  demarkstudio.ca: HTTP final URL: https://demarkstudio.ca/en/
  demo.demarkstudio.ca: HTTP final URL: https://demo.demarkstudio.ca/app/login

Overall: OK
```

Exit code 0. The three hostnames share one registrable domain, so RDAP was queried once. Tests (no internet; local `http.server` instances stand in for HTTP and RDAP, and TLS is mocked):

```
84 passed in 7.44s
```

## Limitations

- RDAP coverage varies by TLD. Some registries publish no expiration event or are not reachable through rdap.org; those domains show `unknown`.
- The registrable domain is the last two labels plus a small built-in list of multi-part suffixes (`co.uk`, `com.au`, ...). Use `--registrable` for anything else.
- The certificate is read after normal chain verification. An expired or untrusted certificate is reported as CRIT with the verification message, without its dates.
- The HTTP check is a single GET of `https://<domain>/`; it does not check other paths or ports.
- Hostname matching uses the SAN list only, as modern clients do.

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
