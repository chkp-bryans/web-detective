import hmac
import os
import threading
import time

import requests
from flask import Flask, Response, jsonify, render_template, request

from website_detective import scan as _core_scan

SCAN_BUDGET_S = int(os.environ.get("DETECTIVE_SCAN_BUDGET") or "55")
_local = threading.local()


def _remaining():
    deadline = getattr(_local, "deadline", None)
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _call_with_timeout(fn, seconds):
    def wrapped(*args, **kwargs):
        box = {}

        def run():
            try:
                box["r"] = fn(*args, **kwargs)
            except Exception as exc:
                box["e"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(seconds)
        if thread.is_alive():
            raise TimeoutError(f"{getattr(fn, '__name__', 'call')} timed out after {seconds}s")
        if "e" in box:
            raise box["e"]
        return box.get("r")

    return wrapped


def _patch_slow_lookups():
    try:
        import whois as whois_mod
        if not getattr(whois_mod, "_wd_timed", False):
            orig = whois_mod.whois

            def whois_budget(domain, *args, **kwargs):
                rem = _remaining()
                if rem is not None and rem <= 0.5:
                    raise TimeoutError("scan time budget exceeded")
                limit = 15 if rem is None else min(15, rem)
                return _call_with_timeout(orig, limit)(domain, *args, **kwargs)

            whois_mod.whois = whois_budget
            whois_mod._wd_timed = True
    except Exception:
        pass
    try:
        import builtwith as builtwith_mod
        if not getattr(builtwith_mod, "_wd_timed", False):
            orig = builtwith_mod.parse

            def parse_budget(url, *args, **kwargs):
                rem = _remaining()
                if rem is not None and rem < 3:
                    return {}
                limit = 8 if rem is None else min(8, rem)
                return _call_with_timeout(orig, limit)(url, *args, **kwargs)

            builtwith_mod.parse = parse_budget
            builtwith_mod._wd_timed = True
    except Exception:
        pass


def _patch_requests_budget():
    orig = requests.sessions.Session.request
    if getattr(orig, "_wd_budget", False):
        return

    def request(self, method, url, **kwargs):
        rem = _remaining()
        if rem is not None:
            if rem <= 0.4:
                raise requests.exceptions.Timeout("scan time budget exceeded")
            cap = max(0.5, rem)
            existing = kwargs.get("timeout")
            if existing is None:
                kwargs["timeout"] = cap
            elif isinstance(existing, (int, float)):
                kwargs["timeout"] = min(float(existing), cap)
            elif isinstance(existing, tuple) and len(existing) == 2:
                kwargs["timeout"] = (min(float(existing[0]), cap), min(float(existing[1]), cap))
        return orig(self, method, url, **kwargs)

    request._wd_budget = True
    requests.sessions.Session.request = request


_patch_slow_lookups()
_patch_requests_budget()

try:
    from website_detective_ext import enhance
except ImportError:
    def enhance(report):
        return report


def _stopped_report(url: str) -> dict:
    return {
        "error": (
            f"Scan stopped after {SCAN_BUDGET_S}s so this page could load instead of a Bad Gateway. "
            "The site was slow, blocking this scanner IP, or rate-limiting extra lookups. "
            "Wait a minute and retry, or raise Traefik/Dokploy read timeout if scans need longer."
        ),
        "url": url,
        "truncated": True,
        "budget_s": SCAN_BUDGET_S,
    }


def scan(url: str):
    box = {}

    def run():
        _local.deadline = time.monotonic() + SCAN_BUDGET_S
        try:
            result = _core_scan(url)
            if isinstance(result, dict) and not result.get("markdown"):
                if (_remaining() or 0) > 1:
                    result = enhance(result)
                else:
                    result["truncated"] = True
            box["r"] = result
        except Exception as exc:
            box["e"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(SCAN_BUDGET_S + 2)
    if thread.is_alive() or "r" not in box:
        return _stopped_report(url)
    result = box["r"]
    if isinstance(result, dict):
        result.setdefault("budget_s", SCAN_BUDGET_S)
    return result

app = Flask(__name__)

AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")
ALLOW_UNAUTHENTICATED = os.environ.get("DETECTIVE_ALLOW_UNAUTHENTICATED", "") == "1"
WAFBUDDY_URL = os.environ.get("WAFBUDDY_URL", "https://wafbuddy.csadocs.com")
APP_RELEASE = os.environ.get("RELEASE") or os.environ.get("APP_RELEASE") or "1.1.0"


def _authorized() -> bool:
    auth = request.authorization
    if not auth or auth.username is None or auth.password is None:
        return False
    user_ok = hmac.compare_digest(auth.username, AUTH_USER)
    pass_ok = hmac.compare_digest(auth.password, AUTH_PASSWORD)
    return user_ok and pass_ok


@app.before_request
def require_basic_auth():
    if request.path == "/health":
        return None
    if ALLOW_UNAUTHENTICATED:
        return None
    if not AUTH_USER or not AUTH_PASSWORD:
        return Response(
            "Scanner is locked. Set BASIC_AUTH_USER and BASIC_AUTH_PASSWORD in Dokploy, then redeploy.\n",
            status=503,
            mimetype="text/plain",
        )
    if _authorized():
        return None
    return Response(
        "Authentication required.\n",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="Website Detective"'},
        mimetype="text/plain",
    )


@app.get("/health")
def health():
    return jsonify(status="ok", release=APP_RELEASE)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        if not url:
            result = {"error": "Enter a website to analyze.", "url": ""}
        else:
            result = scan(url)
    return render_template(
        "index.html",
        result=result,
        url=url,
        wafbuddy_url=WAFBUDDY_URL,
        release=APP_RELEASE,
        scan_budget=SCAN_BUDGET_S,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
