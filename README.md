# Website Detective

Passive reconnaissance for a domain: HTTP headers, DNS (including Check Point WAF `i2.checkpoint.com` CNAMEs), CDN / load balancer / WAF fingerprints, third-party links, WHOIS, SSL, BuiltWith, a live security-header audit, and basic timing from the scanner host.

Intended for authorized Check Point WAF reviews. It does **not** probe or exploit targets.

Live instance (private, basic auth): `https://detective.csadocs.com`

## Notes, before/after, and timing

After a scan:

- **Copy markdown** / **Download .md** — paste-ready report for tickets and notes. Optional ticket, customer, and notes fields are prepended locally and never sent back to the server.
- **Print / Save PDF** — browser print dialog; the form and toolbar are hidden.
- **Save as baseline** — stores this hostname’s report in *this browser only*. Scan again later and **Compare** for a Check Point WAF / CNAME / IP / header / TTFB diff. Replace or clear when you want. Clearing site data removes baselines.
- **Performance** — DNS, Connect+TLS, TTFB (median of up to 3 samples), body size, and redirect hops. These numbers are from the **scanner host**, not from the customer’s users. Treat TTFB deltas under ~50 ms or ~15% as directional noise.
- **Copy curl** — a `curl -w` timing probe the customer can run. Paste that output into [WAFBuddy](https://wafbuddy.csadocs.com) when the question is browser-path (cache, 403/429, login, p95). Detective does not ingest HARs.

Optional env:

- `WAFBUDDY_URL` (default `https://wafbuddy.csadocs.com`) if you need to override the WAFBuddy link.
- `RELEASE` (default `1.1.0`) shown in the footer, copied markdown, and `GET /health`.

CLI markdown:

```bash
python website_detective.py --markdown example.com
```

## Local (venv)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export BASIC_AUTH_USER=detective
export BASIC_AUTH_PASSWORD=changeme
gunicorn --bind 0.0.0.0:8000 --timeout 120 app:app
```

Open http://127.0.0.1:8000 (browser will prompt for login). For local-only with no prompt, set `DETECTIVE_ALLOW_UNAUTHENTICATED=1`.

CLI (same scanner):

```bash
python website_detective.py
```

## Docker

```bash
docker build -t web-detective .
docker run --rm -p 8000:8000 \
  -e BASIC_AUTH_USER=detective \
  -e BASIC_AUTH_PASSWORD=changeme \
  web-detective
```

## Dokploy (Azure)

1. DNS: `detective.csadocs.com` **A** → `20.98.217.111`
2. Create an **Application** from this GitHub repo, branch `main`
3. Build type: **Dockerfile** (`./Dockerfile`)
4. Container port: **8000**
5. Domain: `detective.csadocs.com`, HTTPS on, certificate **Let's Encrypt** (not “none”). If the browser still shows a Traefik default cert, delete/re-add the domain after DNS is live, or restart Traefik in Dokploy settings.
6. **Environment** (required — Traefik UI auth is easy to miss; the app enforces this):

   ```
   BASIC_AUTH_USER=detective
   BASIC_AUTH_PASSWORD=<strong password>
   WAFBUDDY_URL=https://wafbuddy.csadocs.com
   RELEASE=1.1.0
   ```

   Do not commit the password. `WAFBUDDY_URL` is optional (`https://wafbuddy.csadocs.com` is the default). If Dokploy still has the old GitHub URL set, change or remove it, then redeploy.
7. Optional extra layer: Application **Advanced → Security** (Dokploy Traefik basic auth).
8. Deploy. Auto-deploy on push to `main` if the GitHub provider is connected.

Without `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` the scanner returns **503** (locked). `/health` stays open for Dokploy.

Health check: `GET /health` → `{"status":"ok","release":"1.1.0"}`.

Scans can take up to ~90s (WHOIS / BuiltWith), plus two short TTFB samples. Gunicorn timeout is 120s; keep Traefik’s read timeout at least that high.

Tests:

```bash
python -m unittest test_website_detective.py test_app.py
```
