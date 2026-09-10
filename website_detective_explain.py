"""Performance grades and per-scan CDN/WAF/LB evidence."""


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


def _grade_ms(ms, good, ok):
    if ms is None:
        return "n/a", "no sample from this scanner"
    if ms < good:
        return "good", f"under {good} ms from this scanner"
    if ms <= ok:
        return "ok", f"{good}–{ok} ms is typical from this scanner"
    return "slow", f"over {ok} ms from this scanner"


def _grade_hops(count):
    if count <= 0:
        return "good", "direct — no extra round trip"
    if count == 1:
        return "ok", "one extra hop (www / http→https) is normal"
    return "slow", f"{count} extra hops — each hop adds a round trip"


def _rated(label, value, grade, why):
    return f"{label:13} : {value:<22} {grade:<5} {why}"


def format_performance(report: dict) -> str:
    hops = report.get("perf_redirects") or []
    hop_count = max(0, len(hops) - 1)
    samples = report.get("perf_ttfb_samples") or []
    sample_note = "n/a"
    if report.get("perf_ttfb_ms") is not None:
        sample_note = _fmt_ms(report["perf_ttfb_ms"])
        if len(samples) > 1:
            sample_note += (
                f"  (median of {len(samples)}; "
                f"min {_fmt_ms(report.get('perf_ttfb_min_ms'))} / "
                f"max {_fmt_ms(report.get('perf_ttfb_max_ms'))})"
            )
        elif len(samples) == 1:
            sample_note += "  (1 sample)"
    body_line = _fmt_ms(report.get("perf_body_ms"))
    if report.get("perf_body_bytes") is not None:
        body_line += f"   ({_fmt_bytes(report['perf_body_bytes'])})"
    dns_g, dns_w = _grade_ms(report.get("perf_dns_ms"), 50, 150)
    tls_g, tls_w = _grade_ms(report.get("perf_connect_ms"), 150, 400)
    ttfb_g, ttfb_w = _grade_ms(report.get("perf_ttfb_ms"), 400, 1000)
    hop_g, hop_w = _grade_hops(hop_count)
    lines = [
        "From this scanner host — not the customer's browsers.",
        "good / ok / slow is for this vantage point. Compare before/after here, not vs CrUX.",
        "",
        _rated("DNS", _fmt_ms(report.get("perf_dns_ms")), dns_g, dns_w),
        _rated("Connect+TLS", _fmt_ms(report.get("perf_connect_ms")), tls_g, tls_w),
        _rated("TTFB", sample_note, ttfb_g, ttfb_w),
        f"{'Body':13} : {body_line:<22} {'—':<5} download after TTFB; not graded",
        _rated("Redirects", f"{hop_count} hop" + ("s" if hop_count != 1 else ""), hop_g, hop_w),
    ]
    for hop in hops:
        status = hop.get("status", "")
        src = hop.get("url", "")
        location = hop.get("location")
        ttfb = _fmt_ms(hop.get("ttfb_ms"))
        if location:
            lines.append(f"  {status}  {src}  → {location}   {ttfb}")
        else:
            lines.append(f"  {status}  {src}   {ttfb}")
    lines.extend([
        "",
        "Scale (this scanner):",
        "  DNS          good <50 ms     ok 50–150 ms      slow >150 ms",
        "  Connect+TLS  good <150 ms    ok 150–400 ms     slow >400 ms",
        "  TTFB         good <400 ms    ok 400–1000 ms    slow >1000 ms",
        "  Redirects    good 0 hops     ok 1 hop          slow 2+ hops",
        "End users are usually slower. Treat TTFB deltas under ~50 ms or ~15% as noise.",
    ])
    return "\n".join(lines)


def _clip(text, n=88):
    text = " ".join(str(text).split())
    if len(text) <= n:
        return text
    return text[: n - 3] + "..."


def _header_pairs(headers_text):
    pairs = []
    for line in (headers_text or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            pairs.append((key.strip(), value.strip()))
    return pairs


def _dns_map(report):
    recs = report.get("dns_records")
    if isinstance(recs, dict) and recs:
        return {str(k).upper(): [str(x) for x in (v or [])] for k, v in recs.items()}
    out = {}
    current = None
    for line in (report.get("dns_full") or "").splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and " " not in stripped[:-1]:
            current = stripped[:-1].upper()
            out.setdefault(current, [])
            continue
        if current and stripped and not stripped.startswith("No ") and "NXDOMAIN" not in stripped:
            if "Lookup failed" not in stripped:
                out[current].append(stripped)
    return out


def _collect_edge_signals(report):
    """Signals still present in this report (headers / DNS / IP org)."""
    signals = []

    def add(keys, detail, confidence="likely"):
        signals.append({"keys": keys, "detail": detail, "confidence": confidence})

    for key, value in _header_pairs(report.get("headers") or ""):
        low_k, low_v = key.lower(), value.lower()
        shown = f"header {key} = {_clip(value)}"
        if low_k in {"cf-ray", "cf-cache-status"} or "cloudflare" in low_v:
            add(("cloudflare",), shown)
        if "cloudfront" in low_k or "cloudfront" in low_v or low_k.startswith("x-amz-cf"):
            add(("cloudfront",), shown)
        if "akamai" in low_k or "akamai" in low_v:
            add(("akamai",), shown)
        if "fastly" in low_k or "fastly" in low_v:
            add(("fastly",), shown)
        if any(token in low_v for token in ("google", "gws", "gfe", "gcp")) or "x-google" in low_k:
            add(("google",), shown)
        if "azure" in low_v or "microsoft-azure" in low_v or low_k.startswith("x-ms-"):
            add(("azure",), shown)
        if "awselb" in low_v or "elasticloadbalancing" in low_v or "x-amzn-trace" in low_k:
            add(("alb",), shown)
        if "big-ip" in low_v or low_k.startswith("x-wa-") or (low_k == "server" and "f5" in low_v):
            add(("f5",), shown)
        if "netscaler" in low_v or "citrix" in low_v:
            add(("netscaler",), shown)
        if low_k == "server" and "nginx" in low_v:
            add(("nginx",), shown)
        if "haproxy" in low_v:
            add(("haproxy",), shown)
        if "incap" in low_v or "imperva" in low_v or low_k in {"x-iinfo", "x-cdn"}:
            add(("imperva",), shown)
        if "sucuri" in low_k or "sucuri" in low_v:
            add(("sucuri",), shown)
        if "awswaf" in low_v or "x-amz-waf" in low_k:
            add(("aws_waf",), shown)
        if low_k == "via":
            if "cloudfront" in low_v:
                add(("cloudfront",), shown)
            if "akamai" in low_v:
                add(("akamai",), shown)

    dns = _dns_map(report)
    for rtype in ("CNAME", "NS", "MX", "TXT", "A"):
        for rec in dns.get(rtype, []):
            low = rec.lower()
            shown = f"DNS {rtype} = {_clip(rec)}"
            if "i2.checkpoint.com" in low:
                add(("checkpoint",), shown, "confirmed")
            if "cloudflare" in low:
                add(("cloudflare",), shown)
            if "cloudfront" in low or "amazonaws.com" in low:
                add(("cloudfront",), shown)
            if "akamai" in low or "akam.net" in low:
                add(("akamai",), shown)
            if "fastly" in low:
                add(("fastly",), shown)
            if "azure" in low or "trafficmanager" in low:
                add(("azure",), shown)
            if "google" in low or "googlehosted" in low:
                add(("google",), shown)
            if "incap" in low or "imperva" in low:
                add(("imperva",), shown)

    for line in (report.get("ip_info") or "").splitlines():
        if "org" in line.lower() and ":" in line:
            org = line.split(":", 1)[1].strip()
            low = org.lower()
            shown = f"IP org = {_clip(org)}"
            if "cloudflare" in low:
                add(("cloudflare",), shown)
            if "amazon" in low or "aws" in low:
                add(("cloudfront", "alb", "aws_waf"), shown)
            if "akamai" in low:
                add(("akamai",), shown)
            if "fastly" in low:
                add(("fastly",), shown)
            if "google" in low:
                add(("google",), shown)
            if "microsoft" in low or "azure" in low:
                add(("azure",), shown)
            if "incapsula" in low or "imperva" in low:
                add(("imperva",), shown)
            if "sucuri" in low:
                add(("sucuri",), shown)
            break

    if report.get("cloudguard"):
        add(("checkpoint",), "scan flag cloudguard=true (i2.checkpoint.com CNAME)", "confirmed")
    return signals


_KIND_KEYS = {
    "cdn": {
        "cloudflare": ("cloudflare",),
        "cloudfront": ("cloudfront", "aws cloudfront"),
        "akamai": ("akamai",),
        "fastly": ("fastly",),
        "google": ("google cloud", "google"),
        "azure": ("azure",),
    },
    "waf": {
        "cloudflare": ("cloudflare",),
        "aws_waf": ("aws waf",),
        "akamai": ("akamai", "kona"),
        "imperva": ("imperva", "incapsula", "incap"),
        "f5": ("f5", "big-ip", "asm"),
        "sucuri": ("sucuri",),
        "checkpoint": ("check point", "cloudguard", "i2.checkpoint"),
    },
    "lb": {
        "alb": ("application load balancer", "alb/nlb", "awselb"),
        "f5": ("f5", "big-ip"),
        "netscaler": ("netscaler", "citrix"),
        "nginx": ("nginx",),
        "haproxy": ("haproxy",),
    },
}

_KIND_NOTES = {
    ("waf", "cloudflare"): (
        "CF-RAY / Server: cloudflare is shared by Cloudflare CDN and WAF; "
        "it does not prove the WAF feature is enabled"
    ),
    ("cdn", "cloudflare"): (
        "CF-RAY is a Cloudflare edge token (CDN and/or WAF on the same anycast)"
    ),
    ("waf", "checkpoint"): "i2.checkpoint.com CNAME is a Check Point WAF confirmation",
}


def explain_vendors(report, text, kind):
    """Rewrite a CDN / WAF / LB block with per-scan evidence."""
    raw = (text or "").strip() or "None detected"
    if "detected because" in raw:
        return raw
    signals = _collect_edge_signals(report)
    aliases = _KIND_KEYS.get(kind) or {}
    lines_out = []
    for original in raw.splitlines():
        line = original.strip()
        if not line:
            continue
        lines_out.append(line)
        low = line.lower()
        if low.startswith("no ") or low == "none detected":
            continue
        matched_keys = [key for key, needles in aliases.items() if any(n in low for n in needles)]
        hits = []
        seen = set()
        for key in matched_keys:
            for signal in signals:
                if key not in signal["keys"]:
                    continue
                if signal["detail"] in seen:
                    continue
                seen.add(signal["detail"])
                hits.append(signal)
        if hits:
            lines_out.append("  detected because:")
            for signal in hits:
                lines_out.append(f"    • {signal['detail']}")
            conf = "confirmed" if any(s["confidence"] == "confirmed" for s in hits) else "likely"
            lines_out.append(f"  confidence: {conf}")
        else:
            lines_out.append("  detected because: the live response matched this vendor")
            lines_out.append(
                "  evidence: matching header/DNS was not copied into this report "
                "(only a subset of headers is stored)"
            )
        for key in matched_keys:
            note = _KIND_NOTES.get((kind, key))
            if note:
                lines_out.append(f"  note: {note}")
    return "\n".join(lines_out) if lines_out else raw
