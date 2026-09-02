# Website Detective

Passive reconnaissance for a domain: HTTP headers, DNS (including CloudGuard `i2.checkpoint.com` CNAMEs), CDN / load balancer / WAF fingerprints, third-party links, WHOIS, SSL, BuiltWith, and a live security-header audit.

Intended for authorized CloudGuard / WAF reviews. It does **not** probe or exploit targets.

Live instance (private, basic auth): `https://detective.csadocs.com`

## Local (venv)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:8000 --timeout 120 app:app
```

Open http://127.0.0.1:8000

CLI (same scanner):

```bash
python website_detective.py
```

## Docker

```bash
docker build -t web-detective .
docker run --rm -p 8000:8000 web-detective
```

## Dokploy (Azure)

1. DNS: `detective.csadocs.com` **A** → `20.98.217.111`
2. Create an **Application** from this GitHub repo, branch `main`
3. Build type: **Dockerfile** (`./Dockerfile`)
4. Container port: **8000**
5. Domain: `detective.csadocs.com` with HTTPS / Let’s Encrypt
6. Enable Traefik **basic auth** in the Dokploy UI (do not put passwords in git)
7. Deploy. Auto-deploy on push to `main` if the GitHub provider is connected.

Health check: `GET /health` → `{"status":"ok"}`.

Scans can take up to ~90s (WHOIS / BuiltWith). Gunicorn timeout is 120s; keep Traefik’s read timeout at least that high.
