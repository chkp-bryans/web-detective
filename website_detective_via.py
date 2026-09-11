"""Pre-cutover hosts override: TCP to a WAF CNAME, Host/SNI stay on the site name."""

from __future__ import annotations

import ipaddress
import socket
import threading
from urllib.parse import urlparse

_local = threading.local()
_orig_getaddrinfo = socket.getaddrinfo
_patched = False


def _norm_host(host) -> str:
    if host is None:
        return ""
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("idna", errors="replace")
    return str(host).strip().lower().rstrip(".")


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global)


def _resolve_orig(host: str) -> list[str]:
    try:
        infos = _orig_getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve connect-via hostname: {host}") from exc
    addresses = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise ValueError(f"Could not resolve connect-via hostname: {host}")
    return addresses


def parse_via(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Connect-via must be an http(s) hostname or public IP.")
    if parsed.username or parsed.password:
        raise ValueError("Connect-via URLs with credentials are not allowed.")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("Connect-via is missing a hostname.")
    return host


def prepare_override(scan_url: str, via_raw: str):
    """Return override dict or None. Raises ValueError if via is invalid."""
    via_host = parse_via(via_raw)
    if not via_host:
        return None
    from website_detective import ScanError, assert_url_allowed, normalize_url

    try:
        _url, site_host = normalize_url(scan_url)
        assert_url_allowed("https://" + via_host)
    except ScanError as exc:
        raise ValueError(str(exc)) from exc
    if site_host == via_host:
        raise ValueError("Connect-via is the same hostname as the site — omit it.")
    try:
        as_ip = ipaddress.ip_address(via_host)
        if not as_ip.is_global:
            raise ValueError("Connect-via IP must be public.")
        ips = [via_host]
    except ValueError as exc:
        if "must be public" in str(exc):
            raise
        ips = _resolve_orig(via_host)
        bad = [ip for ip in ips if not _is_public_ip(ip)]
        if bad:
            raise ValueError("Connect-via resolves to a private or reserved address.")
    return {
        "host": site_host,
        "via": via_host,
        "via_ips": ips,
        "checkpoint": "i2.checkpoint.com" in via_host,
    }


def format_override(info: dict) -> str:
    if not info:
        return ""
    ips = ", ".join(info.get("via_ips") or []) or "n/a"
    host = info.get("host") or ""
    via = info.get("via") or ""
    cp = "yes — i2.checkpoint.com" if info.get("checkpoint") else "no"
    port = 443
    curl = f"curl --connect-to {host}:{port}:{via}:{port} -sS -o /dev/null -L -w 'ttfb %{{time_starttransfer}}s | code %{{http_code}}\\n' \"https://{host}/\""
    return "\n".join(
        [
            "Pre-cutover hosts override (Host/TLS name stay on the site; TCP goes to via)",
            "",
            f"Site Host/SNI : {host}",
            f"Connect via   : {via}",
            f"Via IPs       : {ips}",
            f"Check Point   : {cp}",
            "",
            "Public DNS in this report is still the current origin.",
            "HTTP, TLS, and TTFB in this scan used the via path.",
            "",
            "Equivalent curl:",
            curl,
        ]
    )


def current_override():
    return getattr(_local, "override", None)


def install_override(info: dict | None):
    if not info:
        _local.override = None
        _local.mapping = {}
        return
    _local.override = info
    _local.mapping = {_norm_host(info.get("host")): _norm_host(info.get("via"))}


def clear_override():
    _local.override = None
    _local.mapping = {}


def patched_getaddrinfo(host, port, *args, **kwargs):
    mapping = getattr(_local, "mapping", None) or {}
    key = _norm_host(host)
    if key and key in mapping:
        host = mapping[key]
    return _orig_getaddrinfo(host, port, *args, **kwargs)


def patch_getaddrinfo():
    global _patched
    if _patched:
        return
    socket.getaddrinfo = patched_getaddrinfo
    _patched = True
