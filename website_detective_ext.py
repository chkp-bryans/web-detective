"""Extras layered on the core scanner: markdown, timing samples, SSL expiry."""

from __future__ import annotations

import os
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from website_detective import (
    SECURITY_HEADERS,
    ScanError,
    USER_AGENT,
    assert_url_allowed,
)
from website_detective_explain import explain_vendors, format_performance

APP_RELEASE = os.environ.get("RELEASE") or os.environ.get("APP_RELEASE") or "1.2.1"
SAMPLE_TIMEOUT = 5
SSL_EXPIRY_DAYS = 30
REPORT_SECTIONS = [
    ("Performance", "perf"),
    ("Connection", "performance"),
    ("Important headers", "headers"),
    ("DNS records", "dns_full"),
    ("IP investigations", "ip_info"),
    ("CDN", "cdn"),
    ("Load balancer / proxy", "load_balancer"),
    ("WAF", "waf"),
    ("Third-party connections", "third_party"),
    ("WHOIS", "whois"),
    ("SSL certificate", "ssl"),
    ("Technology stack", "tech"),
    ("Smart detective", "smart"),
    ("Security headers", "security"),
    ("Check Point WAF summary", "summary"),
]


def _fmt_ms(ms):
    if ms is None:
        return "n/a"
    if ms < 10:
        return f"{ms:.1f} ms"
    return f"{round(ms)} ms"


def _fmt_bytes(n):
    if n is None:
        return "n/a"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def parse_ssl_expiry(cert=None, now=None, ssl_text=""):
    not_after = None
    if cert and cert.get("notAfter"):
        not_after = str(cert.get("notAfter"))
    elif ssl_text:
        for line in ssl_text.splitlines():
            if "Not after" in line and ":" in line:
                not_after = line.split(":", 1)[1].strip()
                break
    if not not_after:
        return False, None
    try:
        ts = ssl.cert_time_to_seconds(not_after)
        expiry = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OverflowError, OSError, TypeError):
        return False, None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return expiry <= current + timedelta(days=SSL_EXPIRY_DAYS), expiry.strftime("%Y-%m-%d")


def curl_timing_command(url: str) -> str:
    """Single-line bash probe. curl -w times are seconds, cumulative from start."""
    safe = (url or "").replace('"', '\\"')
    return (
        "curl -sS -o /dev/null -L -w "
        "'dns %{time_namelookup}s | tcp %{time_connect}s | tls %{time_appconnect}s | "
        "ttfb %{time_starttransfer}s | total %{time_total}s | code %{http_code}\\n' "
        f'"{safe}"'
    )


def sample_ttfb(url: str, extra: int = 0, timeout: int = SAMPLE_TIMEOUT):
    samples = []
    for _ in range(extra):
        session = requests.Session()
        session.headers["User-Agent"] = USER_AGENT
        try:
            assert_url_allowed(url)
            resp = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
            samples.append(resp.elapsed.total_seconds() * 1000)
            resp.close()
        except (ScanError, requests.RequestException, OSError):
            pass
        finally:
            session.close()
    return samples


def _probe_url(report: dict) -> str:
    final = (report.get("url") or "").strip()
    domain = (report.get("domain") or "").strip().lower().rstrip(".")
    if domain:
        scheme = urlparse(final).scheme if final else "https"
        if scheme not in ("http", "https"):
            scheme = "https"
        return f"{scheme}://{domain}"
    return final


def _connect_tls_ms(url: str):
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    started = time.perf_counter()
    sock = None
    wrapped = None
    try:
        sock = socket.create_connection((host, port), timeout=SAMPLE_TIMEOUT)
        if parsed.scheme == "https":
            wrapped = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        return (time.perf_counter() - started) * 1000
    except OSError:
        return None
    finally:
        for s in (wrapped, sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def _total_time_ms(performance: str):
    for line in (performance or "").splitlines():
        if "total time" in line.lower() and ":" in line:
            raw = line.split(":", 1)[1].strip().split()[0]
            try:
                return float(raw) * 1000
            except ValueError:
                return None
    return None


def detect_rate_limit(report: dict):
    status = str(report.get("status") or "")
    err = str(report.get("error") or "").lower()
    headers = str(report.get("headers") or "").lower()
    reasons = []
    if status in {"429", "503"}:
        reasons.append(f"HTTP {status}")
    if "429" in err or "too many requests" in err:
        reasons.append("request error looks like rate limiting")
    if "retry-after" in headers:
        reasons.append("Retry-After header")
    if status == "403" and ("cf-ray" in headers or "cloudflare" in headers):
        reasons.append("Cloudflare 403 — this scanner IP may be challenged")
    return bool(reasons), "; ".join(reasons)


def measure_timing(url: str, extra: int = 0) -> dict:
    """DNS + one TCP/TLS handshake. No extra GET to the target (avoids rate limits)."""
    out = {
        "perf_dns_ms": None,
        "perf_connect_ms": None,
        "perf_ttfb_samples": [],
        "perf_ttfb_ms": None,
        "perf_ttfb_min_ms": None,
        "perf_ttfb_max_ms": None,
        "perf_body_ms": None,
        "perf_body_bytes": None,
        "perf_redirects": [],
        "curl_timing": curl_timing_command(url),
    }
    if not url:
        return out
    try:
        t0 = time.perf_counter()
        assert_url_allowed(url)
        out["perf_dns_ms"] = (time.perf_counter() - t0) * 1000
    except ScanError:
        return out
    out["perf_connect_ms"] = _connect_tls_ms(url)
    if extra:
        samples = sample_ttfb(url, extra=extra)
        if samples:
            out["perf_ttfb_samples"] = samples
            out["perf_ttfb_ms"] = _median(samples)
            out["perf_ttfb_min_ms"] = min(samples)
            out["perf_ttfb_max_ms"] = max(samples)
    return out


def to_markdown(report: dict, meta=None) -> str:
    domain = report.get("domain") or "unknown"
    if report.get("error"):
        title = f"# Website Detective — {domain}" if report.get("domain") else "# Website Detective"
        return f"{title}\n\nScan failed: {report['error']}\n"
    cloudguard = "Yes — i2.checkpoint.com CNAME" if report.get("cloudguard") else "No"
    ttfb_line = _fmt_ms(report.get("perf_ttfb_ms"))
    samples = report.get("perf_ttfb_samples") or []
    if report.get("perf_ttfb_ms") is not None and len(samples) > 1:
        ttfb_line += f" (median of {len(samples)}, from scanner host)"
    elif report.get("perf_ttfb_ms") is not None:
        ttfb_line += " (from scanner host)"
    lines = [
        f"# Website Detective — {domain}",
        "",
        f"- **Scanned:** {report.get('scanned_at') or 'N/A'}",
        f"- **URL:** {report.get('url') or ''}",
        f"- **Release:** {report.get('release') or APP_RELEASE}",
        f"- **Check Point WAF:** {cloudguard}",
        f"- **TTFB:** {ttfb_line}",
    ]
    meta = meta or {}
    if (meta.get("ticket") or "").strip():
        lines.append(f"- **Ticket:** {meta['ticket'].strip()}")
    if (meta.get("customer") or "").strip():
        lines.append(f"- **Customer:** {meta['customer'].strip()}")
    notes = (meta.get("notes") or "").strip()
    if notes:
        quoted = "\n".join(f"> {n}" if n else ">" for n in notes.splitlines())
        lines.extend(["", quoted])
    for title, key in REPORT_SECTIONS:
        body = report.get(key) or "N/A"
        lines.extend(["", f"## {title}", "", "```", str(body).rstrip(), "```"])
    lines.extend([
        "",
        "## Next step",
        "",
        "Detective is passive recon from the scanner host (DNS, headers, WAF fingerprints).",
        "For browser-path questions (cache, 403/429, login, p95), capture a before/after HAR and open WAFBuddy.",
        "",
    ])
    curl = report.get("curl_timing") or curl_timing_command(report.get("url") or "")
    if curl:
        lines.extend(["Customer-side timing probe:", "", "```bash", curl, "```", ""])
    return "\n".join(lines)


def _security_flags(security_text: str) -> dict:
    flags = {}
    for name in SECURITY_HEADERS:
        flags[name] = f"\u2705 {name}" in (security_text or "")
    return flags


def _checkpoint_waf_copy(text):
    if not isinstance(text, str) or "CloudGuard" not in text:
        return text
    text = text.replace("Check Point CloudGuard WAF", "Check Point WAF")
    text = text.replace("CloudGuard WAF", "Check Point WAF")
    text = text.replace("Check Point CloudGuard CNAME", "Check Point WAF CNAME")
    return text


def enhance(report: dict) -> dict:
    """Add markdown/timing/expiry onto a core scan result. Never raises."""
    if not isinstance(report, dict):
        return report
    report.setdefault("release", APP_RELEASE)
    try:
        for key in ("waf", "summary", "smart"):
            if report.get(key):
                report[key] = _checkpoint_waf_copy(report[key])
        if not report.get("error"):
            report["cdn"] = explain_vendors(report, report.get("cdn") or "", "cdn")
            report["waf"] = explain_vendors(report, report.get("waf") or "", "waf")
            report["load_balancer"] = explain_vendors(
                report, report.get("load_balancer") or "", "lb"
            )
        expiring, expires_on = parse_ssl_expiry(ssl_text=report.get("ssl") or "")
        report["ssl_expiring"] = expiring
        report["ssl_expires_on"] = expires_on
        report["security_flags"] = _security_flags(report.get("security") or "")
        limited, reason = detect_rate_limit(report)
        report["rate_limited"] = limited
        report["rate_limit_reason"] = reason
        url = _probe_url(report)
        if url and not report.get("error") and report.get("perf_dns_ms") is None:
            measured = measure_timing(url, extra=0)
            total_ms = _total_time_ms(report.get("performance") or "")
            if total_ms is not None and not measured.get("perf_ttfb_ms"):
                measured["perf_ttfb_ms"] = total_ms
                measured["perf_ttfb_samples"] = [total_ms]
                measured["perf_ttfb_min_ms"] = total_ms
                measured["perf_ttfb_max_ms"] = total_ms
            for key, value in measured.items():
                if report.get(key) in (None, "", []):
                    report[key] = value
        final_url = report.get("url") or url
        report["curl_timing"] = report.get("curl_timing") or curl_timing_command(final_url)
        report.setdefault("perf_redirects", [])
        report["perf"] = format_performance(report)
        report["markdown"] = to_markdown(report)
    except Exception:
        report.setdefault("markdown", to_markdown(report))
        report.setdefault("perf", report.get("perf") or "")
        report.setdefault("ssl_expiring", False)
    return report
