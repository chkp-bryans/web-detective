"""Conservative CDN / WAF / load-balancer fingerprints.

The compact scanner used to search concatenated header *values* for short
substrings such as "f5". That matches hex in CF-RAY, CSP hashes, and cookies.
These helpers require a header *name*, a cookie *name*, or a token on Server/Via.
"""

from __future__ import annotations

import re

_TOKEN = r"(?<![a-z0-9_-]){}(?![a-z0-9_-])"

# F5 LTM persistence / GTM. Not ASM/WAF by themselves.
_F5_LB_COOKIE = re.compile(
    r"^(BIGipServer|F5_ST$|F5_fullWT$|LastMRH_Session$|MRHSession$)",
    re.I,
)
# F5 ASM / Advanced WAF
_F5_WAF_COOKIE = re.compile(r"^(TS[0-9a-f]{8}|f5avra+)", re.I)
_IMPERVA_COOKIE = re.compile(r"^(visid_incap_|incap_ses_|nlbi_)", re.I)
_AKAMAI_COOKIE = re.compile(r"^(ak_bmsc|_abck|bm_sz|akacd_)", re.I)
_ALB_COOKIE = re.compile(r"^(AWSALB|AWSALBCORS|AWSELB)$", re.I)
_NETSCALER_COOKIE = re.compile(r"^(NSC_|citrix_ns_id|ns_af$)", re.I)


def _token(value: str, *tokens: str) -> bool:
    low = (value or "").lower()
    for tok in tokens:
        if re.search(_TOKEN.format(re.escape(tok.lower())), low):
            return True
    return False


def _pairs(headers) -> list[tuple[str, str]]:
    if not headers:
        return []
    if isinstance(headers, str):
        out = []
        for line in headers.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                out.append((key.strip(), value.strip()))
        return out
    items: list[tuple[str, str]] = []
    getter = getattr(headers, "get_all", None) or getattr(headers, "getlist", None)
    seen = set()
    try:
        for key, value in headers.items():
            key_s = str(key)
            if getter and key_s.lower() not in seen:
                extra = getter(key_s) or getter(key)
                if extra and len(extra) > 1:
                    seen.add(key_s.lower())
                    for one in extra:
                        items.append((key_s, str(one)))
                    continue
            if isinstance(value, (list, tuple)):
                for one in value:
                    items.append((key_s, str(one)))
            else:
                items.append((key_s, str(value)))
    except Exception:
        return items
    return items


def _by_name(pairs, *names: str) -> list[str]:
    want = {n.lower() for n in names}
    return [v for k, v in pairs if k.lower() in want]


def _cookie_names(pairs) -> list[str]:
    names = []
    for raw in _by_name(pairs, "set-cookie"):
        names.append(raw.split("=", 1)[0].strip())
    return names


def _fmt(title: str, reasons: list[str], note: str = "") -> str:
    lines = [title, "  detected because:"]
    for reason in reasons:
        lines.append(f"    • {reason}")
    if note:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


def detect_cdn(headers: dict) -> str:
    pairs = _pairs(headers)
    keys = {k.lower() for k, _ in pairs}
    hits = []

    if "cf-ray" in keys or "cf-cache-status" in keys:
        val = (_by_name(pairs, "cf-ray") or [""])[0]
        hits.append(_fmt("Cloudflare CDN", [f"header CF-RAY = {val or '(present)'}"]))
    elif any(_token(v, "cloudflare") for k, v in pairs if k.lower() == "server"):
        hits.append(_fmt("Cloudflare CDN", ["header Server contains cloudflare"]))

    if any(k.startswith("x-amz-cf") for k in keys) or any(
        _token(v, "cloudfront") for k, v in pairs if k.lower() in {"via", "server", "x-cache"}
    ):
        shown = [f"header {k}" for k, _ in pairs if k.lower().startswith("x-amz-cf")]
        hits.append(_fmt("AWS CloudFront", shown or ["Via/Server/X-Cache token cloudfront"]))

    if any(k.startswith("x-akamai") or k == "akamai-grn" for k in keys) or any(
        _token(v, "akamaighost", "akamai") for k, v in pairs if k.lower() in {"server", "via"}
    ):
        hits.append(_fmt("Akamai CDN", ["AkamaiGHost / x-akamai-* / akamai-grn"]))
    elif any(_AKAMAI_COOKIE.match(n) for n in _cookie_names(pairs)):
        hits.append(_fmt("Akamai CDN", ["Akamai bot-manager cookie (ak_bmsc / _abck)"]))

    if any(_token(v, "fastly") for k, v in pairs if k.lower() in {"server", "via", "x-served-by", "x-fastly-request-id"}):
        hits.append(_fmt("Fastly CDN", ["Server/Via/X-Served-By token fastly"]))
    elif "x-timer" in keys and "x-served-by" in keys:
        hits.append(_fmt("Fastly CDN", ["headers X-Timer + X-Served-By (Fastly cache shape)"]))

    if any(k.startswith("x-goog-") or k.startswith("x-guploader") for k in keys) or any(
        _token(v, "gws", "gfe", "sffe") for k, v in pairs if k.lower() == "server"
    ):
        hits.append(_fmt("Google Cloud CDN", ["x-goog-* or Server gws/gfe"]))
    elif any(_token(v, "google") for k, v in pairs if k.lower() == "via"):
        hits.append(_fmt("Google Cloud CDN", ["Via token google"]))

    if any(k.startswith("x-azure-") or k == "x-ms-request-id" for k in keys) or any(
        _token(v, "microsoft-azure-application-gateway", "azure")
        for k, v in pairs
        if k.lower() == "server"
    ):
        hits.append(_fmt("Azure CDN / Front Door", ["x-azure-* / x-ms-request-id / Azure Server"]))

    return "\n\n".join(hits) if hits else "No specific CDN detected"


def detect_load_balancer_and_proxy(headers: dict) -> str:
    pairs = _pairs(headers)
    keys = {k.lower() for k, _ in pairs}
    cookies = _cookie_names(pairs)
    hits = []

    server = " ".join(_by_name(pairs, "server"))
    via = " ".join(_by_name(pairs, "via"))

    f5_lb = []
    if _token(server, "bigip", "big-ip", "big ip") or re.search(r"\bf5\b", server, re.I):
        f5_lb.append(f"header Server = {server}")
    if _token(via, "bigip", "big-ip"):
        f5_lb.append(f"header Via = {via}")
    if "x-wa-info" in keys or "x-cnection" in keys:
        f5_lb.append("header X-WA-Info or X-Cnection (F5 quirk)")
    for name in cookies:
        if _F5_LB_COOKIE.match(name):
            f5_lb.append(f"Set-Cookie {name}")
    if f5_lb:
        hits.append(
            _fmt(
                "F5 BIG-IP",
                f5_lb,
                "LTM/APM persistence or Server BigIP — not the same as F5 ASM/WAF",
            )
        )

    alb = []
    if "x-amzn-trace-id" in keys:
        alb.append("header X-Amzn-Trace-Id")
    if _token(via, "awselb", "awselb/2.0") or _token(server, "awselb"):
        alb.append("Server/Via awselb")
    for name in cookies:
        if _ALB_COOKIE.match(name):
            alb.append(f"Set-Cookie {name}")
    if alb:
        hits.append(_fmt("AWS Application Load Balancer (ALB/NLB)", alb))

    ns = []
    if _token(server, "netscaler", "citrix") or _token(via, "netscaler", "citrix"):
        ns.append("Server/Via NetScaler or Citrix")
    for name in cookies:
        if _NETSCALER_COOKIE.match(name):
            ns.append(f"Set-Cookie {name}")
    if ns:
        hits.append(_fmt("Citrix NetScaler / ADC", ns))

    if _token(server, "nginx") or _token(via, "nginx"):
        hits.append(_fmt("Nginx reverse proxy", ["Server/Via token nginx"]))

    if _token(server, "haproxy") or _token(via, "haproxy"):
        hits.append(_fmt("HAProxy", ["Server/Via token haproxy"]))

    return "\n\n".join(hits) if hits else "No specific load balancer detected"


def detect_waf(headers: dict, dns_records: dict | None = None) -> tuple[str, bool]:
    pairs = _pairs(headers)
    keys = {k.lower() for k, _ in pairs}
    cookies = _cookie_names(pairs)
    server = " ".join(_by_name(pairs, "server"))
    wafs = []

    if "cf-ray" in keys or _token(server, "cloudflare"):
        why = []
        if "cf-ray" in keys:
            why.append("header CF-RAY")
        if _token(server, "cloudflare"):
            why.append("header Server = cloudflare")
        if "cf-mitigated" in keys:
            why.append("header CF-Mitigated (challenge/block)")
        note = (
            "CF-RAY is present on Cloudflare CDN and WAF; "
            "it does not prove the WAF feature is enabled"
            if "cf-mitigated" not in keys
            else ""
        )
        title = "Cloudflare WAF" if "cf-mitigated" in keys else "Cloudflare (CDN and/or WAF)"
        wafs.append(_fmt(title, why or ["Cloudflare edge header"], note))

    if any("x-amz-waf" in k or k == "x-amzn-waf-action" for k in keys) or any(
        "awswaf" in v.lower() for _, v in pairs
    ):
        wafs.append(_fmt("AWS WAF", ["x-amz-waf / x-amzn-waf-action / awswaf"]))

    if any(k.startswith("x-akamai") or k == "akamai-grn" for k in keys) or any(
        _AKAMAI_COOKIE.match(n) for n in cookies
    ):
        wafs.append(
            _fmt(
                "Akamai (CDN / Bot Manager)",
                ["x-akamai-* or ak_bmsc/_abck cookie"],
                "Akamai cookies are often bot-manager, not proof of Kona WAF",
            )
        )

    if "x-iinfo" in keys or any(_token(v, "incapsula", "imperva") for k, v in pairs if k.lower() in {"x-cdn", "server", "via"}):
        wafs.append(_fmt("Imperva / Incapsula", ["X-Iinfo / X-CDN Incapsula"]))
    elif any(_IMPERVA_COOKIE.match(n) for n in cookies):
        wafs.append(_fmt("Imperva / Incapsula", ["incap_ses_ / visid_incap_ cookie"]))

    f5_waf = []
    for name in cookies:
        if _F5_WAF_COOKIE.match(name):
            f5_waf.append(f"Set-Cookie {name} (ASM/AWAF)")
    if f5_waf:
        wafs.append(_fmt("F5 BIG-IP ASM / Advanced WAF", f5_waf))

    if any(_token(v, "sucuri") for k, v in pairs) or any(k.lower().startswith("x-sucuri") for k in keys):
        wafs.append(_fmt("Sucuri WAF", ["x-sucuri-* or sucuri token"]))

    cloudguard = False
    dns_records = dns_records or {}
    cnames = [str(c) for c in dns_records.get("CNAME", [])]
    if any("i2.checkpoint.com" in c.lower() for c in cnames):
        shown = next(c for c in cnames if "i2.checkpoint.com" in c.lower())
        wafs.append(
            _fmt(
                "Check Point WAF",
                [f"DNS CNAME = {shown}"],
                "i2.checkpoint.com CNAME is a Check Point WAF confirmation",
            )
        )
        cloudguard = True

    text = "\n\n".join(wafs) if wafs else "No WAF detected"
    return text, cloudguard
