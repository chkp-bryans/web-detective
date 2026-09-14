"""Keep DNS / WHOIS / HTTP going when HTTPS or TLS fails."""

from __future__ import annotations

import whois
from urllib.parse import urlparse

import requests

from website_detective import (
    INTERESTING_HEADERS,
    USER_AGENT,
    ScanError,
    assert_url_allowed,
    clean_date,
    collect_dns,
    detect_cdn,
    detect_load_balancer_and_proxy,
    detect_waf,
    format_ssl,
    get_ip_info,
    get_ssl_info,
    make_smart_guesses,
)

_FETCH_HINTS = (
    "request failed",
    "ssl",
    "tls",
    "certificate",
    "handshake",
    "cert verify",
    "max retries",
    "connection aborted",
    "connection reset",
    "timed out",
    "timeout",
)


def is_recoverable_fetch_error(error: str) -> bool:
    low = (error or "").lower()
    if not low:
        return False
    if any(s in low for s in ("not allowed", "enter a website", "missing a hostname", "only http")):
        return False
    return any(s in low for s in _FETCH_HINTS)


def _header_block(headers) -> str:
    if not headers:
        return "None (HTTPS GET did not complete)"
    lines = []
    for name in INTERESTING_HEADERS:
        value = headers.get(name)
        if value and value != "N/A":
            lines.append(f"{name}: {value}")
    return "\n".join(lines) or "None (HTTPS GET did not complete)"


def _try_http(domain: str):
    url = f"http://{domain}"
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    try:
        assert_url_allowed(url)
        resp = session.get(url, timeout=8, allow_redirects=False, stream=True)
        info = {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "url": resp.url,
            "location": resp.headers.get("Location") or "",
        }
        resp.close()
        return info
    except (ScanError, requests.RequestException, OSError):
        return None
    finally:
        session.close()


def continue_partial_scan(report: dict) -> dict:
    """If HTTPS failed, fill DNS and anything else that does not need TLS."""
    if not isinstance(report, dict) or report.get("partial"):
        return report
    if not is_recoverable_fetch_error(report.get("error") or ""):
        return report
    domain = (report.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return report

    tls_error = str(report.get("error") or "HTTPS request failed")
    report["error"] = None
    report["partial"] = True
    report["tls_failed"] = True
    report["tls_error"] = tls_error

    try:
        dns_full, dns_records, a_records = collect_dns(domain)
    except Exception as exc:
        dns_full, dns_records, a_records = f"DNS lookup failed: {exc}", {}, []
    report["dns_full"] = dns_full
    report["dns_records"] = dns_records
    if a_records:
        try:
            report["ip_info"] = "\n\n".join(get_ip_info(ip) for ip in a_records[:8])
        except Exception as exc:
            report["ip_info"] = f"IP lookup failed: {exc}"
    else:
        report["ip_info"] = report.get("ip_info") or "No A records"

    whois_text = "Unavailable"
    try:
        w = whois.whois(domain)
        whois_text = (
            f"Registrar : {getattr(w, 'registrar', None) or 'N/A'}\n"
            f"Created   : {clean_date(getattr(w, 'creation_date', None))}\n"
            f"Expires   : {clean_date(getattr(w, 'expiration_date', None))}"
        )
        nameservers = getattr(w, "name_servers", None)
        if nameservers:
            ns = nameservers if isinstance(nameservers, (list, tuple)) else [nameservers]
            whois_text += "\nNS        : " + ", ".join(str(n) for n in ns[:8])
    except Exception as exc:
        whois_text = f"WHOIS unavailable: {exc}"
    report["whois"] = whois_text

    cert = None
    try:
        cert = get_ssl_info(domain)
    except Exception:
        cert = None
    ssl_text = format_ssl(cert) if cert else "Could not retrieve a certificate"
    report["ssl"] = (
        f"TLS handshake failed: {tls_error}\n\n{ssl_text}"
    )

    headers = {}
    http_note = "HTTPS GET failed; HTTP GET not attempted or failed"
    http_info = _try_http(domain)
    if http_info is not None:
        headers = http_info.get("headers") or {}
        loc = http_info.get("location") or ""
        http_note = f"HTTP {http_info.get('status')}" + (f" redirect -> {loc}" if loc else "")
        report["status"] = str(http_info.get("status") or "")
        report["headers"] = _header_block(headers)
        parsed = urlparse(http_info.get("url") or "")
        if parsed.scheme == "http":
            report.setdefault("url", f"http://{domain}")
    else:
        report["headers"] = report.get("headers") or "None (HTTPS GET did not complete)"

    report["performance"] = (
        f"HTTPS GET   : failed (TLS/SSL)\n"
        f"HTTP GET    : {http_note}\n"
        f"Host        : {domain}"
    )
    try:
        report["cdn"] = detect_cdn(headers)
        report["load_balancer"] = detect_load_balancer_and_proxy(headers)
        waf_text, cloudguard = detect_waf(headers, dns_records)
        report["waf"] = waf_text
        report["cloudguard"] = cloudguard
        report["smart"] = make_smart_guesses(dns_records, headers)
        from website_detective import audit_security_headers

        report["security"] = audit_security_headers(headers) if headers else "No HTTPS response to audit"
    except Exception:
        report.setdefault("cdn", "No specific CDN detected")
        report.setdefault("waf", "No WAF detected")

    bits = [
        "HTTPS/TLS failed; this report is partial",
        "DNS, IP, and WHOIS were still collected",
        "Check Point WAF auto-detected if i2.checkpoint.com CNAME is present"
        if report.get("cloudguard")
        else "No Check Point WAF CNAME (i2.checkpoint.com) observed",
    ]
    report["summary"] = "\n".join(f"• {b}" for b in bits)
    report["tech"] = report.get("tech") or "Skipped (HTTPS GET failed)"
    report["third_party"] = report.get("third_party") or "Skipped (no HTTPS body)"
    return report
