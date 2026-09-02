"""Website Detective — passive recon for CloudGuard / WAF / CDN / DNS."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import subprocess
import platform
from datetime import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup

try:
    import builtwith
except ImportError:  # pragma: no cover
    builtwith = None

USER_AGENT = "WebDetective/1.0 (+https://detective.csadocs.com)"
REQUEST_TIMEOUT = 15
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
ALLOWED_PORTS = {None, 80, 443}
BLOCKED_HOST_SUFFIXES = (".internal", ".localhost", ".local", ".lan")
BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "ip6-localhost",
    "ip6-loopback",
}
INTERESTING_HEADERS = [
    "Server",
    "X-Powered-By",
    "Content-Type",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Via",
    "CF-RAY",
    "CF-Cache-Status",
    "X-Amz-Cf-Id",
    "X-Amz-Cf-Pop",
]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class ScanError(ValueError):
    """Invalid or disallowed scan target."""


def normalize_url(raw: str) -> tuple[str, str]:
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("Enter a website to analyze.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("Only http and https URLs are allowed.")
    if parsed.username or parsed.password:
        raise ScanError("URLs with credentials are not allowed.")
    if parsed.port not in ALLOWED_PORTS:
        raise ScanError("Only ports 80 and 443 are allowed.")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ScanError("URL is missing a hostname.")
    if host in BLOCKED_HOSTS or any(host.endswith(s) for s in BLOCKED_HOST_SUFFIXES):
        raise ScanError("That hostname is not allowed.")
    domain = host
    url = parsed._replace(fragment="").geturl()
    return url, domain


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global)


def _resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanError(f"Could not resolve hostname: {host}") from exc
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise ScanError(f"Could not resolve hostname: {host}")
    return addresses


def assert_url_allowed(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanError("Redirects must stay on http or https.")
    if parsed.username or parsed.password:
        raise ScanError("URLs with credentials are not allowed.")
    if parsed.port not in ALLOWED_PORTS:
        raise ScanError("Only ports 80 and 443 are allowed.")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ScanError("Redirect is missing a hostname.")
    if host in BLOCKED_HOSTS or any(host.endswith(s) for s in BLOCKED_HOST_SUFFIXES):
        raise ScanError("That hostname is not allowed.")
    try:
        as_ip = ipaddress.ip_address(host)
        if not as_ip.is_global:
            raise ScanError("Private or reserved IP addresses are not allowed.")
        return
    except ValueError:
        pass
    for addr in _resolve_host(host):
        if not _is_public_ip(addr):
            raise ScanError("Target resolves to a private or reserved address.")


def _read_capped_body(resp: requests.Response) -> str:
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            resp.close()
            raise ScanError("Response body is larger than 2 MB.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    encoding = resp.encoding or "utf-8"
    return raw.decode(encoding, errors="replace")


def fetch_url(url: str) -> tuple[requests.Response, str, str]:
    """GET url following redirects, validating every hop. Returns (resp, body, final_url)."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    current = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            assert_url_allowed(current)
            resp = session.get(
                current,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise ScanError("Redirect was missing a Location header.")
                current = urljoin(current, location)
                continue
            body = _read_capped_body(resp)
            return resp, body, current
        raise ScanError("Too many redirects.")
    except ScanError:
        raise
    except requests.RequestException as exc:
        raise ScanError(f"Request failed: {exc}") from exc
    finally:
        session.close()


def clean_date(date_field) -> str:
    if not date_field:
        return "N/A"
    if isinstance(date_field, list):
        dt = date_field[0] if date_field else None
        return dt.strftime("%Y-%m-%d") if hasattr(dt, "strftime") else str(dt)
    if hasattr(date_field, "strftime"):
        return date_field.strftime("%Y-%m-%d")
    return str(date_field)


def get_ssl_info(domain: str) -> dict | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except (OSError, ssl.SSLError, TimeoutError, ValueError):
        return None


def format_ssl(cert: dict | None) -> str:
    if not cert:
        return "Could not retrieve"

    def _name(entries) -> str:
        try:
            return ", ".join(f"{k}={v}" for rdn in entries for k, v in rdn)
        except (TypeError, ValueError):
            return str(entries)

    sans = []
    for kind, value in cert.get("subjectAltName") or []:
        sans.append(f"{kind}: {value}")
    lines = [
        f"Subject     : {_name(cert.get('subject') or [])}",
        f"Issuer      : {_name(cert.get('issuer') or [])}",
        f"Not before  : {cert.get('notBefore', 'N/A')}",
        f"Not after   : {cert.get('notAfter', 'N/A')}",
        f"Serial      : {cert.get('serialNumber', 'N/A')}",
    ]
    if sans:
        lines.append("SAN         :\n  " + "\n  ".join(sans[:12]))
        if len(sans) > 12:
            lines.append(f"  ... and {len(sans) - 12} more")
    return "\n".join(lines)


def get_ip_info(ip: str) -> str:
    lines = [f"IP: {ip}"]
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=8,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 200:
            data = resp.json()
            org = data.get("org", "N/A")
            location = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
            hostname = data.get("hostname", "N/A")
            lines += [
                f"      Org      : {org}",
                f"      Location : {location}",
                f"      Hostname : {hostname}",
            ]
        else:
            lines.append(f"      ipinfo.io returned HTTP {resp.status_code}")
    except (requests.RequestException, ValueError) as exc:
        lines.append(f"      Could not fetch detailed info: {exc}")
    return "\n".join(lines)


def print_tech_stack(tech: dict | None) -> str:
    if not tech:
        return "None detected"
    output_lines = []
    for category, items in sorted(tech.items()):
        if items:
            items_str = ", ".join(items[:8]) + (" ..." if len(items) > 8 else "")
            output_lines.append(f"{category.capitalize()}: {items_str}")
    return "\n".join(output_lines) or "None detected"


def detect_cdn(headers: dict) -> str:
    hints = []
    header_text = " ".join(str(v).lower() for v in headers.values())
    keys = {k.lower(): v for k, v in headers.items()}
    if "cloudfront" in header_text or "x-amz-cf" in header_text:
        hints.append("AWS CloudFront")
    if "cf-ray" in keys or "cloudflare" in header_text:
        hints.append("Cloudflare CDN")
    if "akamai" in header_text:
        hints.append("Akamai CDN")
    if "fastly" in header_text:
        hints.append("Fastly CDN")
    if any(word in header_text for word in ["google", "gcp"]):
        hints.append("Google Cloud CDN")
    if any(word in header_text for word in ["azure", "microsoft-cdn"]):
        hints.append("Azure CDN")
    return "\n".join(hints) if hints else "No specific CDN detected"


def detect_load_balancer_and_proxy(headers: dict) -> str:
    hints = []
    header_text = " ".join(str(v).lower() for v in headers.values())
    if "awselb" in header_text or "elasticloadbalancing" in header_text:
        hints.append("AWS Application Load Balancer (ALB/NLB)")
    if "f5" in header_text or "big-ip" in header_text:
        hints.append("F5 BIG-IP")
    if "netscaler" in header_text or "citrix" in header_text:
        hints.append("Citrix NetScaler / ADC")
    if "nginx" in header_text:
        hints.append("Nginx Reverse Proxy / LB")
    if "haproxy" in header_text:
        hints.append("HAProxy")
    return "\n".join(hints) if hints else "No specific load balancer detected"


def detect_waf(headers: dict, dns_records: dict) -> tuple[str, bool]:
    wafs = []
    header_text = " ".join(str(v).lower() for v in headers.values())
    keys = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" in keys or "cloudflare" in header_text:
        wafs.append("Cloudflare WAF")
    if "x-amz-waf" in header_text or "awswaf" in header_text:
        wafs.append("AWS WAF")
    if "akamai" in header_text:
        wafs.append("Akamai Kona Site Defender")
    if "incap" in header_text or "imperva" in header_text:
        wafs.append("Imperva / Incapsula")
    if "f5" in header_text or "big-ip" in header_text:
        wafs.append("F5 BIG-IP ASM")
    if "sucuri" in header_text:
        wafs.append("Sucuri WAF")
    cloudguard = False
    cname_records = dns_records.get("CNAME", [])
    if any("i2.checkpoint.com" in str(c).lower() for c in cname_records):
        wafs.append("Check Point CloudGuard WAF (Confirmed via i2.checkpoint.com CNAME)")
        cloudguard = True
    text = "\n".join(wafs) if wafs else "No WAF detected"
    return text, cloudguard


def make_smart_guesses(dns_records: dict, headers: dict) -> str:
    guesses = []
    ns_list = [str(r).lower() for r in dns_records.get("NS", [])]
    mx_list = [str(r).lower() for r in dns_records.get("MX", [])]
    txt_list = [str(r).lower() for r in dns_records.get("TXT", [])]
    header_text = " ".join(str(v).lower() for v in headers.values())
    if any("cloudfront" in header_text or "x-amz-cf" in header_text or "aws" in n or "amazon" in n for n in ns_list):
        guesses.append("Cloud Provider: Amazon Web Services (AWS)")
    elif any("cloudflare" in n for n in ns_list):
        guesses.append("Cloud Provider / Protection: Cloudflare")
    elif any("azure" in n or "microsoft" in header_text for n in ns_list):
        guesses.append("Cloud Provider: Microsoft Azure")
    if any("microsoft" in m or "outlook" in m for m in mx_list) or any("ms=" in t or "protection.outlook.com" in t for t in txt_list):
        guesses.append("Email: Microsoft 365")
    if any("google" in m or "aspmx.l.google.com" in m for m in mx_list):
        guesses.append("Email: Google Workspace")
    if any("docusign" in t for t in txt_list):
        guesses.append("Service: DocuSign")
    return "\n".join(guesses) or "None detected"


def detect_third_party_connections(html: str, main_domain: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        external = set()
        for tag in soup.find_all(["script", "link", "img", "iframe", "form"]):
            for attr in ["src", "href", "action", "data-src"]:
                value = tag.get(attr)
                if value and (value.startswith("http://") or value.startswith("https://")):
                    parsed = urlparse(value)
                    if parsed.netloc and not parsed.netloc.rstrip(".").lower().endswith(main_domain):
                        external.add(parsed.netloc)
        if not external:
            return "No third-party connections"
        sorted_external = sorted(external)
        preview = sorted_external[:40]
        lines = [f"Found {len(sorted_external)} external domains:"] + [f"  • {d}" for d in preview]
        if len(sorted_external) > 40:
            lines.append(f"  ... and {len(sorted_external) - 40} more")
        return "\n".join(lines)
    except Exception as exc:
        return f"Third-party parsing failed: {exc}"


def audit_security_headers(headers: dict) -> str:
    lines = []
    lower = {k.lower(): v for k, v in headers.items()}
    for name in SECURITY_HEADERS:
        value = None
        for k, v in lower.items():
            if k == name.lower():
                value = v
                break
        if value and value != "N/A":
            lines.append(f"✅ {name}: {value}")
        else:
            lines.append(f"❌ {name}: Missing")
    return "\n".join(lines)


def collect_dns(domain: str) -> tuple[str, dict, list[str]]:
    dns_records: dict[str, list[str]] = {}
    sections: list[str] = []
    a_records: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8
    resolver.timeout = 5
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]:
        try:
            recs = [a.to_text() for a in resolver.resolve(domain, rtype)]
            dns_records[rtype] = recs
            sections.append(f"{rtype}:\n" + "\n".join(recs))
            if rtype == "A":
                a_records = recs
        except dns.resolver.NoAnswer:
            sections.append(f"{rtype}: No records")
        except dns.resolver.NXDOMAIN:
            sections.append(f"{rtype}: NXDOMAIN")
        except dns.exception.DNSException:
            sections.append(f"{rtype}: Lookup failed")
    return "\n\n".join(sections).strip() or "No records", dns_records, a_records


def _empty_report(url: str, domain: str, error: str | None = None) -> dict:
    return {
        "url": url,
        "domain": domain,
        "error": error,
        "cloudguard": False,
        "status": "",
        "performance": "",
        "headers": "",
        "dns_full": "",
        "dns_records": {},
        "ip_info": "",
        "cdn": "",
        "load_balancer": "",
        "waf": "",
        "third_party": "",
        "whois": "",
        "ssl": "",
        "tech": "",
        "smart": "",
        "security": "",
        "summary": "",
        "scanned_at": datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
    }


def scan(raw_url: str) -> dict:
    """Run a full passive scan. Never raises for target failures; ScanError becomes error text."""
    try:
        url, domain = normalize_url(raw_url)
        assert_url_allowed(url)
    except ScanError as exc:
        return _empty_report(raw_url or "", "", str(exc))
    report = _empty_report(url, domain)
    try:
        response, body, final_url = fetch_url(url)
    except ScanError as exc:
        report["error"] = str(exc)
        return report
    report["url"] = final_url
    report["status"] = str(response.status_code)
    report["performance"] = (
        f"Status Code : {response.status_code}\n"
        f"Final URL   : {final_url}\n"
        f"Total Time  : {response.elapsed.total_seconds():.3f} seconds"
    )
    headers_dict = {h: response.headers.get(h, "N/A") for h in INTERESTING_HEADERS}
    report["headers"] = "\n".join(f"{h}: {v}" for h, v in headers_dict.items() if v != "N/A") or "None"
    dns_full, dns_records, a_records = collect_dns(domain)
    report["dns_full"] = dns_full
    report["dns_records"] = dns_records
    if a_records:
        report["ip_info"] = "\n\n".join(get_ip_info(ip) for ip in a_records)
    else:
        report["ip_info"] = "No A records"
    report["cdn"] = detect_cdn(dict(response.headers))
    report["load_balancer"] = detect_load_balancer_and_proxy(dict(response.headers))
    waf_text, cloudguard = detect_waf(dict(response.headers), dns_records)
    report["waf"] = waf_text
    report["cloudguard"] = cloudguard
    report["third_party"] = detect_third_party_connections(body, domain)
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
    report["ssl"] = format_ssl(get_ssl_info(domain))
    tech = None
    if builtwith is not None:
        try:
            tech = builtwith.parse(f"https://{domain}")
        except Exception as exc:
            report["tech"] = f"Technology fingerprinting failed: {exc}"
    if tech is not None and not report["tech"]:
        report["tech"] = print_tech_stack(tech)
    elif not report["tech"]:
        report["tech"] = "None detected"
    report["smart"] = make_smart_guesses(dns_records, dict(response.headers))
    report["security"] = audit_security_headers(dict(response.headers))
    summary_bits = [
        "Passive GET + DNS + WHOIS + SSL (no active probing)",
        "CloudGuard WAF auto-detected if i2.checkpoint.com CNAME is present"
        if cloudguard
        else "No Check Point CloudGuard CNAME (i2.checkpoint.com) observed",
        "CDN, load balancer, and WAF fingerprinted from headers",
        "Security headers read from the live response",
    ]
    report["summary"] = "\n".join(f"• {b}" for b in summary_bits)
    return report


def save_beautiful_report(domain: str, data: dict) -> str:
    filename = f"{domain.replace('.', '_')}_waf_report.html"
    html = _cli_html(data)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


def _cli_html(data: dict) -> str:
    def safe_str(value) -> str:
        if value is None:
            return "N/A"
        if isinstance(value, (list, tuple)):
            return "\n".join(str(x) for x in value if x is not None)
        return str(value)
    from html import escape
    domain = escape(safe_str(data.get("domain") or data.get("url")))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Website Detective • {domain}</title>
</head>
<body>
<pre>{escape(safe_str(data.get("performance")))}

HEADERS
{escape(safe_str(data.get("headers")))}

DNS
{escape(safe_str(data.get("dns_full")))}

IP
{escape(safe_str(data.get("ip_info")))}

CDN
{escape(safe_str(data.get("cdn")))}

LB
{escape(safe_str(data.get("load_balancer")))}

WAF
{escape(safe_str(data.get("waf")))}

THIRD PARTY
{escape(safe_str(data.get("third_party")))}

WHOIS
{escape(safe_str(data.get("whois")))}

SSL
{escape(safe_str(data.get("ssl")))}

TECH
{escape(safe_str(data.get("tech")))}

SMART
{escape(safe_str(data.get("smart")))}

SECURITY
{escape(safe_str(data.get("security")))}

SUMMARY
{escape(safe_str(data.get("summary")))}
</pre>
</body>
</html>"""


def auto_open_report(filename: str) -> None:
    try:
        if "microsoft" in platform.release().lower():
            subprocess.run(["explorer.exe", filename], check=False)
        else:
            subprocess.run(["xdg-open", filename], check=False)
    except OSError:
        pass


def _print_cli(data: dict) -> None:
    try:
        from termcolor import colored
    except ImportError:
        def colored(text, _color=None):
            return text
    if data.get("error"):
        print(colored(f"Error: {data['error']}", "red"))
        return
    print(colored(f"Investigating: {data['url']}\n", "cyan"))
    sections = [
        ("Connection", "performance"),
        ("Headers", "headers"),
        ("DNS", "dns_full"),
        ("IPs", "ip_info"),
        ("CDN", "cdn"),
        ("Load balancer", "load_balancer"),
        ("WAF", "waf"),
        ("Third-party", "third_party"),
        ("WHOIS", "whois"),
        ("SSL", "ssl"),
        ("Tech", "tech"),
        ("Smart guesses", "smart"),
        ("Security headers", "security"),
        ("Summary", "summary"),
    ]
    for title, key in sections:
        print(colored(f"\n{title}", "yellow"))
        print(data.get(key) or "N/A")
    if data.get("cloudguard"):
        print(colored("\nCheck Point CloudGuard WAF detected.", "red"))


if __name__ == "__main__":
    print("Website Detective — CloudGuard auto-detection")
    site = input("Enter a website (e.g. checkpoint.com): ").strip()
    result = scan(site)
    _print_cli(result)
    if result.get("domain") and not result.get("error"):
        path = save_beautiful_report(result["domain"], result)
        print(f"\nReport saved: {path}")
        auto_open_report(path)
