"""Unit tests for Website Detective markdown, SSL expiry, and performance formatting."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from unittest.mock import MagicMock, patch

import requests

from website_detective import (
    REPORT_SECTIONS,
    _empty_report,
    _fmt_ms,
    _median,
    curl_timing_command,
    format_performance,
    parse_ssl_expiry,
    sample_ttfb,
    to_markdown,
)


def _sample_report(**overrides) -> dict:
    report = _empty_report("https://example.com", "example.com")
    report.update(
        {
            "cloudguard": True,
            "status": "200",
            "performance": "Status Code : 200\nFinal URL   : https://example.com",
            "perf_dns_ms": 22.0,
            "perf_connect_ms": 85.0,
            "perf_ttfb_ms": 180.0,
            "perf_ttfb_min_ms": 165.0,
            "perf_ttfb_max_ms": 210.0,
            "perf_ttfb_samples": [165.0, 180.0, 210.0],
            "perf_body_ms": 40.0,
            "perf_body_bytes": 186368,
            "perf_redirects": [
                {
                    "url": "https://example.com",
                    "status": 301,
                    "location": "https://www.example.com",
                    "ttfb_ms": 90.0,
                },
                {
                    "url": "https://www.example.com",
                    "status": 200,
                    "location": None,
                    "ttfb_ms": 180.0,
                },
            ],
            "curl_timing": curl_timing_command("https://www.example.com"),
            "headers": "Server: nginx",
            "dns_full": "A:\n93.184.216.34",
            "dns_records": {"A": ["93.184.216.34"], "CNAME": ["edge.i2.checkpoint.com"]},
            "ip_info": "IP: 93.184.216.34",
            "cdn": "No specific CDN detected",
            "load_balancer": "No specific load balancer detected",
            "waf": "Check Point CloudGuard WAF (Confirmed via i2.checkpoint.com CNAME)",
            "third_party": "No third-party connections",
            "whois": "Registrar : Example",
            "ssl": "Issuer      : Example CA",
            "tech": "None detected",
            "smart": "None detected",
            "security": "✅ Strict-Transport-Security: max-age=31536000\n❌ Content-Security-Policy: Missing",
            "security_flags": {
                "Strict-Transport-Security": True,
                "Content-Security-Policy": False,
            },
            "summary": "• Passive GET",
            "scanned_at": "September 9, 2026 at 14:32:00",
        }
    )
    report["perf"] = format_performance(report)
    report.update(overrides)
    return report


class MedianTests(unittest.TestCase):
    def test_odd_and_even(self):
        self.assertEqual(_median([3, 1, 2]), 2)
        self.assertEqual(_median([4, 1, 2, 3]), 2.5)
        self.assertIsNone(_median([]))


class SslExpiryTests(unittest.TestCase):
    def test_expiring_within_30_days(self):
        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        soon = now + timedelta(days=10)
        cert = {"notAfter": soon.strftime("%b %d %H:%M:%S %Y GMT")}
        expiring, day = parse_ssl_expiry(cert, now=now)
        self.assertTrue(expiring)
        self.assertEqual(day, "2026-09-19")

    def test_not_expiring_when_far_out(self):
        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        later = now + timedelta(days=90)
        cert = {"notAfter": later.strftime("%b %d %H:%M:%S %Y GMT")}
        expiring, day = parse_ssl_expiry(cert, now=now)
        self.assertFalse(expiring)
        self.assertEqual(day, "2026-12-08")

    def test_missing_cert(self):
        self.assertEqual(parse_ssl_expiry(None), (False, None))
        self.assertEqual(parse_ssl_expiry({}), (False, None))


class PerformanceFormatTests(unittest.TestCase):
    def test_median_and_redirects(self):
        text = format_performance(_sample_report())
        self.assertIn("From scanner host (not end-user)", text)
        self.assertIn("DNS           : 22 ms", text)
        self.assertIn("Connect+TLS   : 85 ms", text)
        self.assertIn("median of 3", text)
        self.assertIn("min 165 ms", text)
        self.assertIn("max 210 ms", text)
        self.assertIn("1 hop", text)
        self.assertIn("301  https://example.com  → https://www.example.com", text)
        self.assertIn("182.0 KB", text)

    def test_single_sample_and_failed_extras(self):
        report = _sample_report(
            perf_ttfb_samples=[180.0],
            perf_ttfb_ms=180.0,
            perf_ttfb_min_ms=180.0,
            perf_ttfb_max_ms=180.0,
            perf_redirects=[
                {"url": "https://example.com", "status": 200, "location": None, "ttfb_ms": 180.0}
            ],
        )
        text = format_performance(report)
        self.assertIn("1 sample", text)
        self.assertIn("0 hops", text)
        self.assertNotIn("median of", text)

    def test_fmt_ms_na(self):
        self.assertEqual(_fmt_ms(None), "n/a")
        self.assertEqual(_fmt_ms(1.4), "1.4 ms")


class SampleTtfbTests(unittest.TestCase):
    @patch("website_detective.requests.Session")
    @patch("website_detective.assert_url_allowed")
    def test_failures_are_skipped(self, _allowed, session_cls):
        session = MagicMock()
        session_cls.return_value = session
        session.get.side_effect = requests.RequestException("timeout")
        self.assertEqual(sample_ttfb("https://example.com", extra=2), [])


class MarkdownTests(unittest.TestCase):
    def test_includes_domain_cloudguard_and_sections(self):
        md = to_markdown(_sample_report())
        self.assertIn("# Website Detective — example.com", md)
        self.assertIn("**CloudGuard:** Yes — i2.checkpoint.com CNAME", md)
        self.assertIn("**TTFB:** 180 ms (median of 3, from scanner host)", md)
        self.assertIn("## Performance", md)
        for title, _key in REPORT_SECTIONS:
            self.assertIn(f"## {title}", md)
        self.assertIn("## Next step", md)
        self.assertIn("WAFBuddy", md)

    def test_meta_fields(self):
        md = to_markdown(
            _sample_report(),
            meta={"ticket": "INC123", "customer": "Acme", "notes": "Cutover night"},
        )
        self.assertIn("**Ticket:** INC123", md)
        self.assertIn("**Customer:** Acme", md)
        self.assertIn("> Cutover night", md)

    def test_error_without_domain(self):
        md = to_markdown(_empty_report("", "", "Enter a website to analyze."))
        self.assertTrue(md.startswith("# Website Detective"))
        self.assertIn("Scan failed: Enter a website to analyze.", md)
        self.assertNotIn("## DNS records", md)

    def test_error_with_domain(self):
        md = to_markdown(_empty_report("https://example.com", "example.com", "Request failed"))
        self.assertIn("# Website Detective — example.com", md)
        self.assertIn("Scan failed: Request failed", md)

    def test_curl_contains_final_url(self):
        cmd = curl_timing_command("https://www.example.com/path")
        self.assertIn("https://www.example.com/path", cmd)
        self.assertIn("time_starttransfer", cmd)
        md = to_markdown(_sample_report())
        self.assertIn("https://www.example.com", md)


if __name__ == "__main__":
    unittest.main()
