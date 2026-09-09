"""Flask UI tests for copy/export toolbar and WAFBuddy link."""

from __future__ import annotations

import os
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
        self.assertEqual(resp.json["release"], "1.1.0")

    def test_home_shows_release(self):
        resp = self.client.get("/")
        self.assertIn(b"Release 1.1.0", resp.data)

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
