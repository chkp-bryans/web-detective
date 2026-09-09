import hmac
import os
import threading

from flask import Flask, Response, jsonify, render_template, request

from website_detective import scan as _core_scan


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
            whois_mod.whois = _call_with_timeout(whois_mod.whois, 15)
            whois_mod._wd_timed = True
    except Exception:
        pass
    try:
        import builtwith as builtwith_mod
        if not getattr(builtwith_mod, "_wd_timed", False):
            builtwith_mod.parse = _call_with_timeout(builtwith_mod.parse, 12)
            builtwith_mod._wd_timed = True
    except Exception:
        pass


_patch_slow_lookups()

try:
    from website_detective_ext import enhance
except ImportError:
    def enhance(report):
        return report


def scan(url: str):
    result = _core_scan(url)
    if isinstance(result, dict) and not result.get("markdown"):
        result = enhance(result)
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
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
