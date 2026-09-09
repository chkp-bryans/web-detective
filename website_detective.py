"""Website Detective — passive recon for CloudGuard / WAF / CDN / DNS."""

from __future__ import annotations

DEFAULT_WAFBUDDY_URL = "https://github.com/chkp-bryans/wafbuddy_v2"


def scan(raw_url: str) -> dict:
    """Temporary stub while the full scanner is restored."""
    return {
        "error": "Scanner is being updated. Please retry in a minute.",
        "url": raw_url or "",
        "domain": "",
    }
