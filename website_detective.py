"""Website Detective — passive recon for CloudGuard / WAF / CDN / DNS."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import subprocess
import platform
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup

try:
    import builtwith
except ImportError:
    builtwith = None

USER_AGENT = "WebDetective/1.0 (+https://detective.csadocs.com)"
REQUEST_TIMEOUT = 15
SAMPLE_TIMEOUT = 8
SKIP_SAMPLES_AFTER_S = 60
SSL_EXPIRY_DAYS = 30
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
DEFAULT_WAFBUDDY_URL = "https://github.com/chkp-bryans/wafbuddy_v2"
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
    "Server", "X-Powered-By", "Content-Type", "Strict-Transport-Security",
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Via", "CF-RAY", "CF-Cache-Status", "X-Amz-Cf-Id", "X-Amz-Cf-Pop",
]
SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]
REPORT_SECTIONS = [
    ("Performance", "perf"), ("Connection", "performance"), ("Important headers", "headers"),
    ("DNS records", "dns_full"), ("IP investigations", "ip_info"), ("CDN", "cdn"),
    ("Load balancer / proxy", "load_balancer"), ("WAF", "waf"),
    ("Third-party connections", "third_party"), ("WHOIS", "whois"),
    ("SSL certificate", "ssl"), ("Technology stack", "tech"), ("Smart detective", "smart"),
    ("Security headers", "security"), ("CloudGuard WAF summary", "summary"),
]

class ScanError(ValueError):
    """Invalid or disallowed scan target."""
