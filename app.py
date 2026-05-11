from flask import Flask, request, render_template_string
import requests
import dns.resolver
import whois
import builtwith
import ssl
import socket
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>🌐 Website Detective</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8fafc; margin: 40px; }
        .container { max-width: 1100px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        input { padding: 12px; width: 400px; font-size: 16px; }
        button { padding: 12px 24px; background: #1e40af; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; }
        pre { background: #0f172a; color: #e0f2fe; padding: 15px; border-radius: 8px; overflow: auto; }
        .section { margin: 25px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Website Detective</h1>
        <p>Enter domain for technical analysis (CloudGuard WAF ready)</p>
        <form method="post">
            <input type="text" name="url" placeholder="checkpoint.com" required>
            <button type="submit">Analyze Website</button>
        </form>
        {{ result|safe }}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        result = f"<h2>🔍 Analyzing: {url}</h2>"

        try:
            response = requests.get(url, timeout=15)
            result += f"<p>✅ Connected! Status: {response.status_code}</p>"

            # DNS Records
            result += "<div class='section'><h3>📋 DNS Records</h3><pre>"
            dns_records = {}
            for rtype in ['A', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']:
                try:
                    recs = [a.to_text() for a in dns.resolver.resolve(domain, rtype)]
                    dns_records[rtype] = recs
                    result += f"{rtype}:\n" + "\n".join(recs) + "\n\n"
                except:
                    result += f"{rtype}: No records\n\n"
            result += "</pre></div>"

            # CloudGuard Detection
            cname_list = dns_records.get('CNAME', [])
            if any('i2.checkpoint.com' in str(c).lower() for c in cname_list):
                result += "<h3 style='color:red'>🔥 Check Point CloudGuard WAF Detected!</h3>"

            result += "<p><strong>Full CLI version is more detailed. This web version is for quick checks.</strong></p>"

        except Exception as e:
            result += f"<p style='color:red'>❌ Error: {str(e)}</p>"

        return render_template_string(HTML, result=result)

    return render_template_string(HTML, result="")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)