import hmac
import json
import os
import re
import socket
import threading
import time
import uuid
from pathlib import Path

import requests
from flask import Flask, Response, jsonify, render_template, request

from website_detective import scan as _core_scan

SCAN_BUDGET_S = int(os.environ.get("DETECTIVE_SCAN_BUDGET") or "55")
JOB_DIR = Path(os.environ.get("DETECTIVE_JOB_DIR") or "/tmp/wd-jobs")
_local = threading.local()
_cancel_flags = {}
_cancel_lock = threading.Lock()
_JOB_ID_RE = re.compile(r"^[a-fA-F0-9-]{8,64}$")


def _remaining():
    deadline = getattr(_local, "deadline", None)
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _is_cancelled(cancel_id=None):
    cid = cancel_id or getattr(_local, "cancel_id", None)
    if not cid:
        return False
    with _cancel_lock:
        return bool(_cancel_flags.get(cid))


def _mark_cancelled(cancel_id: str):
    if not cancel_id:
        return
    with _cancel_lock:
        _cancel_flags[cancel_id] = True


def _clear_cancel(cancel_id: str):
    if not cancel_id:
        return
    with _cancel_lock:
        _cancel_flags.pop(cancel_id, None)


def _safe_job_id(raw: str | None):
    value = (raw or "").strip()
    if not _JOB_ID_RE.match(value):
        return None
    return value


def _job_path(jid: str) -> Path:
    return JOB_DIR / f"{jid}.json"


def _read_job(jid: str):
    path = _job_path(jid)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_job(jid: str, data: dict):
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    path = _job_path(jid)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
    tmp.replace(path)


def _job_log(message: str):
    jid = getattr(_local, "job_id", None)
    if not jid:
        return
    data = _read_job(jid) or {"id": jid, "logs": [], "status": "running"}
    logs = data.setdefault("logs", [])
    logs.append(message)
    if len(logs) > 80:
        del logs[:-80]
    data["step"] = message
    _write_job(jid, data)


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
                if _is_cancelled() or (rem is not None and rem <= 0.5):
                    raise TimeoutError("scan cancelled" if _is_cancelled() else "scan time budget exceeded")
                _job_log(f"WHOIS {domain}")
                limit = 12 if rem is None else min(12, rem)
                return _call_with_timeout(orig, limit)(domain, *args, **kwargs)

            whois_mod.whois = whois_budget
            whois_mod._wd_timed = True
    except Exception:
        pass
    try:
        import builtwith as builtwith_mod
        if not getattr(builtwith_mod, "_wd_timed", False):

            def parse_budget(url, *args, **kwargs):
                # urllib + huge regex DB; hangs on 30x/WAF sites (e.g. ifaw.org). Skip.
                _job_log("Skipping BuiltWith (hangs on some redirects/WAF)")
                return {}

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
        if _is_cancelled():
            raise requests.exceptions.Timeout("scan cancelled")
        if rem is not None:
            if rem <= 0.4:
                raise requests.exceptions.Timeout("scan time budget exceeded")
            cap = max(0.5, min(8.0, rem))
            existing = kwargs.get("timeout")
            if existing is None:
                kwargs["timeout"] = cap
            elif isinstance(existing, (int, float)):
                kwargs["timeout"] = min(float(existing), cap)
            elif isinstance(existing, tuple) and len(existing) == 2:
                kwargs["timeout"] = (min(float(existing[0]), cap), min(float(existing[1]), cap))
        _job_log(f"{method.upper()} {url}")
        resp = orig(self, method, url, **kwargs)
        code = getattr(resp, "status_code", None)
        loc = ""
        try:
            loc = resp.headers.get("Location") or ""
        except Exception:
            pass
        if loc:
            _job_log(f"HTTP {code} redirect -> {loc}")
        else:
            _job_log(f"HTTP {code}")
        if code in (304, 204, 205):
            try:
                resp._content = b""
                resp._content_consumed = True
                resp.close()
            except Exception:
                pass
        return resp

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


def _scan_inner(url: str, cancel_id: str | None = None) -> dict:
    _local.deadline = time.monotonic() + SCAN_BUDGET_S
    _local.cancel_id = cancel_id
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(8)
    try:
        if _is_cancelled():
            return {"error": "Scan cancelled.", "url": url, "cancelled": True}
        _job_log(f"Starting {url}")
        result = _core_scan(url)
        if _is_cancelled():
            return {"error": "Scan cancelled.", "url": url, "cancelled": True}
        if isinstance(result, dict) and not result.get("markdown"):
            if (_remaining() or 0) > 1:
                _job_log("Building extras (timing, markdown)")
                result = enhance(result)
            else:
                result["truncated"] = True
                _job_log("Stopped extras to stay under the time budget")
        _job_log("Done")
        if isinstance(result, dict):
            result.setdefault("budget_s", SCAN_BUDGET_S)
        return result
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _run_job(jid: str, url: str):
    box = {}

    def run():
        _local.job_id = jid
        try:
            box["r"] = _scan_inner(url, cancel_id=jid)
        except Exception as exc:
            box["e"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(SCAN_BUDGET_S + 2)
    data = _read_job(jid) or {"id": jid, "url": url, "logs": []}
    if thread.is_alive():
        _mark_cancelled(jid)
        _local.job_id = jid
        _job_log("Giving up — a step hung (often redirects or fingerprinting)")
        data = _read_job(jid) or data
        data["status"] = "done"
        data["result"] = _stopped_report(url)
        _write_job(jid, data)
        _clear_cancel(jid)
        return
    if "e" in box:
        data["status"] = "error"
        data["result"] = {"error": str(box["e"]), "url": url}
    else:
        result = box.get("r") or _stopped_report(url)
        data["status"] = "cancelled" if result.get("cancelled") else "done"
        data["result"] = result
    _write_job(jid, data)
    _clear_cancel(jid)


def scan(url: str, cancel_id: str | None = None):
    box = {}

    def run():
        try:
            box["r"] = _scan_inner(url, cancel_id=cancel_id)
        except Exception as exc:
            box["e"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.monotonic() + SCAN_BUDGET_S + 2
    while thread.is_alive() and time.monotonic() < deadline:
        if _is_cancelled(cancel_id):
            return {"error": "Scan cancelled.", "url": url, "cancelled": True}
        thread.join(0.25)
    if thread.is_alive() or "r" not in box:
        return _stopped_report(url)
    return box["r"]

app = Flask(__name__)

AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")
ALLOW_UNAUTHENTICATED = os.environ.get("DETECTIVE_ALLOW_UNAUTHENTICATED", "") == "1"
WAFBUDDY_URL = os.environ.get("WAFBUDDY_URL", "https://wafbuddy.csadocs.com")
APP_RELEASE = os.environ.get("RELEASE") or os.environ.get("APP_RELEASE") or "1.2.1"


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


@app.post("/cancel")
def cancel_scan():
    cid = _safe_job_id(request.form.get("id") or request.values.get("id"))
    _mark_cancelled(cid or "")
    if cid:
        data = _read_job(cid)
        if data and data.get("status") == "running":
            data["status"] = "cancelled"
            _write_job(cid, data)
    return jsonify(ok=True)


@app.post("/scan/start")
def scan_start():
    url = (request.form.get("url") or "").strip()
    if not url:
        return jsonify(error="Enter a website to analyze."), 400
    jid = str(uuid.uuid4())
    _write_job(jid, {"id": jid, "url": url, "status": "running", "logs": [f"Queued {url}"]})
    threading.Thread(target=_run_job, args=(jid, url), daemon=True).start()
    return jsonify(id=jid, url=url, budget=SCAN_BUDGET_S)


@app.get("/scan/status/<jid>")
def scan_status(jid):
    safe = _safe_job_id(jid)
    data = _read_job(safe) if safe else None
    if not data:
        return jsonify(error="unknown job"), 404
    return jsonify(
        id=data.get("id"),
        url=data.get("url"),
        status=data.get("status"),
        logs=data.get("logs") or [],
        step=data.get("step") or "",
        done=data.get("status") in {"done", "error", "cancelled"},
    )


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = (request.values.get("url") or "").strip()
    cancel_id = _safe_job_id(request.values.get("cancel"))
    job_id = _safe_job_id(request.values.get("job"))
    if job_id:
        data = _read_job(job_id) or {}
        url = data.get("url") or url
        if data.get("status") in {"done", "error", "cancelled"} and data.get("result"):
            result = data["result"]
    elif request.method == "POST" or url:
        if not url:
            result = {"error": "Enter a website to analyze.", "url": ""}
        else:
            try:
                result = scan(url, cancel_id=cancel_id)
            finally:
                _clear_cancel(cancel_id or "")
    return render_template(
        "index.html",
        result=result,
        url=url,
        wafbuddy_url=WAFBUDDY_URL,
        release=APP_RELEASE,
        scan_budget=SCAN_BUDGET_S,
        job_id=job_id,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
