"""Flask UI tests for copy/export toolbar and WAFBuddy link."""

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

os.environ["DETECTIVE_ALLOW_UNAUTHENTICATED"] = "1"

from app import app
from test_website_detective import _sample_report
from website_detective import to_markdown


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_and_wafbuddy_link(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Website Detective", resp.data)
        self.assertIn(b"WAFBuddy", resp.data)
        self.assertIn(b"wafbuddy.csadocs.com", resp.data)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json["status"], "ok")
        self.assertEqual(resp.json["release"], "1.2.0")

    def test_home_shows_release(self):
        resp = self.client.get("/")
        self.assertIn(b"Release 1.2.0", resp.data)

    @patch("app.scan")
    def test_results_toolbar(self, mock_scan):
        report = _sample_report()
        report["markdown"] = to_markdown(report)
        mock_scan.return_value = report
        resp = self.client.post("/", data={"url": "example.com"})
        self.assertEqual(resp.status_code, 200)
        body = resp.data
        self.assertIn(b"Copy markdown", body)
        self.assertIn(b"Download .md", body)
        self.assertIn(b"Print / Save PDF", body)
        self.assertIn(b"Save as baseline", body)
        self.assertIn(b"Open WAFBuddy", body)
        self.assertIn(b"Copy curl", body)
        self.assertIn(b"From scanner host", body)
        self.assertIn(b"id=\"report-md\"", body)
        self.assertIn(b"Check Point WAF detected", body)

    @patch("app.scan")
    def test_ssl_expiry_banner(self, mock_scan):
        report = _sample_report(ssl_expiring=True, ssl_expires_on="2026-09-19")
        report["markdown"] = to_markdown(report)
        mock_scan.return_value = report
        resp = self.client.post("/", data={"url": "example.com"})
        self.assertIn(b"TLS certificate expires 2026-09-19", resp.data)

    def test_empty_url_error(self):
        resp = self.client.post("/", data={"url": "   "})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Enter a website to analyze.", resp.data)

    def test_home_has_scan_overlay(self):
        resp = self.client.get("/")
        self.assertIn(b"id=\"scan-overlay\"", resp.data)
        self.assertIn(b"SCAN_BUDGET", resp.data)
        self.assertIn(b"id=\"scan-cancel\"", resp.data)

    @patch("app.scan")
    def test_get_url_query_scans_and_titles(self, mock_scan):
        mock_scan.return_value = {"error": "nope", "url": "https://example.com", "domain": "example.com"}
        resp = self.client.get("/?url=example.com")
        mock_scan.assert_called()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Website Detective • example.com".encode("utf-8"), resp.data)

    def test_builtwith_is_skipped(self):
        import builtwith

        started = time.perf_counter()
        self.assertEqual(builtwith.parse("https://ifaw.org"), {})
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_cancel_endpoint(self):
        resp = self.client.post("/cancel", data={"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json["ok"])

    @patch("app._run_job")
    def test_scan_start_and_status(self, mock_run):
        mock_run.side_effect = lambda *a, **k: None
        resp = self.client.post("/scan/start", data={"url": "example.com"})
        self.assertEqual(resp.status_code, 200)
        job_id = resp.json["id"]
        self.assertTrue(job_id)
        status = self.client.get("/scan/status/" + job_id)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json["status"], "running")
        self.assertIn("Queued", " ".join(status.json.get("logs") or []))

    @patch("app.threading.Thread")
    def test_budget_returns_html_not_gateway(self, mock_thread_cls):
        class FakeThread:
            def __init__(self, target=None, daemon=None):
                pass

            def start(self):
                pass

            def join(self, timeout=None):
                pass

            def is_alive(self):
                return False

        mock_thread_cls.side_effect = FakeThread
        resp = self.client.post("/", data={"url": "example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Scan stopped", resp.data)
        self.assertIn(b"class=\"error\"", resp.data)

    @patch("app.scan")
    def test_rate_limit_banner(self, mock_scan):
        report = _sample_report()
        report["rate_limited"] = True
        report["rate_limit_reason"] = "HTTP 429"
        report["markdown"] = to_markdown(report)
        mock_scan.return_value = report
        resp = self.client.post("/", data={"url": "example.com"})
        self.assertIn(b"rate-limited or challenged", resp.data)
        self.assertIn(b"HTTP 429", resp.data)
