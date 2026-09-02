import hmac
import os

from flask import Flask, Response, jsonify, render_template, request

from website_detective import scan

app = Flask(__name__)

AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")
ALLOW_UNAUTHENTICATED = os.environ.get("DETECTIVE_ALLOW_UNAUTHENTICATED", "") == "1"


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
    return jsonify(status="ok")


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
    return render_template("index.html", result=result, url=url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
