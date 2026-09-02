from flask import Flask, jsonify, render_template, request

from website_detective import scan

app = Flask(__name__)


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
