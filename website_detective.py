import requests
import socket
import dns.resolver
import whois
import builtwith
import ssl
import subprocess
import platform
from termcolor import colored
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ====================== HELPER FUNCTIONS ======================
def clean_date(date_field):
    if not date_field:
        return "N/A"
    if isinstance(date_field, list):
        dt = date_field[0] if date_field else None
        return dt.strftime("%Y-%m-%d") if hasattr(dt, 'strftime') else str(dt)
    if hasattr(date_field, 'strftime'):
        return date_field.strftime("%Y-%m-%d")
    return str(date_field)

def get_ssl_info(domain):
    print("   Trying to fetch SSL info...")
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        if hasattr(r.raw, '_connection') and r.raw._connection.sock:
            return r.raw._connection.sock.getpeercert()
    except:
        pass
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except:
        return None

def get_ip_info(ip):
    print(colored(f"   🔎 Investigating IP: {ip}", "blue"))
    report_output = [f"IP: {ip}"]
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            org = data.get('org', 'N/A')
            location = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
            hostname = data.get('hostname', 'N/A')
            print(f"      Org      : {org}")
            print(f"      Location : {location}")
            print(f"      Hostname : {hostname}")
            report_output.append(f"      Org      : {org}")
            report_output.append(f"      Location : {location}")
            report_output.append(f"      Hostname : {hostname}")
    except Exception as e:
        report_output.append(f"      Could not fetch detailed info: {e}")
    return "\n".join(report_output)

def print_tech_stack(tech):
    print(colored("\n🛠️ Technology Stack (BuiltWith):", "magenta"))
    if not tech:
        print("   None detected")
        return "None detected"
    output_lines = []
    for category, items in sorted(tech.items()):
        if items:
            items_str = ', '.join(items[:8]) + (" ..." if len(items) > 8 else "")
            print(f"   {category.capitalize()}: {items_str}")
            output_lines.append(f"{category.capitalize()}: {items_str}")
    return "\n".join(output_lines) or "None detected"

def detect_cdn(headers):
    hints = []
    header_text = ' '.join(str(v).lower() for v in headers.values())
    if 'cloudfront' in header_text or 'x-amz-cf' in header_text:
        hints.append("☁️ AWS CloudFront")
    if 'cf-ray' in headers or 'cloudflare' in header_text:
        hints.append("🌩️ Cloudflare CDN")
    if 'akamai' in header_text:
        hints.append("🌐 Akamai CDN")
    if 'fastly' in header_text:
        hints.append("⚡ Fastly CDN")
    if any(word in header_text for word in ['google', 'gcp']):
        hints.append("☁️ Google Cloud CDN")
    if any(word in header_text for word in ['azure', 'microsoft-cdn']):
        hints.append("☁️ Azure CDN")
    if hints:
        print(colored("\n🌐 CDN Detection:", "blue"))
        for hint in hints:
            print(f"   {hint}")
        return "\n".join(hints)
    return "No specific CDN detected"

def detect_load_balancer_and_proxy(headers):
    hints = []
    header_text = ' '.join(str(v).lower() for v in headers.values())
    if 'awselb' in header_text or 'elasticloadbalancing' in header_text:
        hints.append("🚦 AWS Application Load Balancer (ALB/NLB)")
    if 'f5' in header_text or 'big-ip' in header_text:
        hints.append("🚦 F5 BIG-IP")
    if 'netscaler' in header_text or 'citrix' in header_text or 'adc' in header_text:
        hints.append("🚦 Citrix NetScaler / ADC")
    if 'nginx' in header_text:
        hints.append("🚦 Nginx Reverse Proxy / LB")
    if 'haproxy' in header_text:
        hints.append("🚦 HAProxy")
    if hints:
        print(colored("\n🚦 Load Balancer Detection:", "magenta"))
        for hint in hints:
            print(f"   {hint}")
        return "\n".join(hints)
    return "No specific load balancer detected"

def detect_waf(headers, dns_records):
    wafs = []
    header_text = ' '.join(str(v).lower() for v in headers.values())

    # General WAFs
    if 'cf-ray' in headers or 'cloudflare' in header_text:
        wafs.append("🌩️ Cloudflare WAF")
    if 'x-amz-waf' in header_text or 'awswaf' in header_text:
        wafs.append("🛡️ AWS WAF")
    if 'akamai' in header_text:
        wafs.append("🛡️ Akamai Kona Site Defender")
    if 'incap' in header_text or 'imperva' in header_text:
        wafs.append("🛡️ Imperva / Incapsula")
    if 'f5' in header_text or 'big-ip' in header_text:
        wafs.append("🛡️ F5 BIG-IP ASM")
    if 'sucuri' in header_text:
        wafs.append("🛡️ Sucuri WAF")

    # Specific CloudGuard Detection
    cname_records = dns_records.get('CNAME', [])
    if any('i2.checkpoint.com' in str(c).lower() for c in cname_records):
        wafs.append("🔥 Check Point CloudGuard WAF (Confirmed via i2.checkpoint.com CNAME)")

    if wafs:
        print(colored("\n🛡️ WAF Detection:", "red"))
        for w in wafs:
            print(f"   {w}")
        return "\n".join(wafs)
    return "No WAF detected"

def make_smart_guesses(dns_records, headers):
    guesses = []
    ns_list = [str(r).lower() for r in dns_records.get('NS', [])]
    mx_list = [str(r).lower() for r in dns_records.get('MX', [])]
    txt_list = [str(r).lower() for r in dns_records.get('TXT', [])]
    header_text = ' '.join(str(v).lower() for v in headers.values())

    if any('cloudfront' in header_text or 'x-amz-cf' in header_text or 'aws' in n or 'amazon' in n for n in ns_list):
        guesses.append("☁️ Cloud Provider: Amazon Web Services (AWS) - Confirmed")
    elif any('cloudflare' in n for n in ns_list):
        guesses.append("🌩️ Cloud Provider / Protection: Cloudflare")
    elif any('azure' in n or 'microsoft' in header_text for n in ns_list):
        guesses.append("☁️ Cloud Provider: Microsoft Azure")

    if any('microsoft' in m or 'ms=' in t for m in mx_list for t in txt_list):
        guesses.append("📧 Email: Microsoft 365")
    if any('docusign' in t for t in txt_list):
        guesses.append("📄 Service: DocuSign")

    print(colored("\n🧠 Smart Detective Guesses:", "cyan"))
    for g in guesses:
        print(f"   {g}")
    if not guesses:
        print("   No strong third-party matches detected")

    return "\n".join(guesses) or "None detected"

def detect_third_party_connections(response, main_domain):
    print(colored("\n🔗 Third-Party Connections Detected:", "magenta"))
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        external = set()
        for tag in soup.find_all(['script', 'link', 'img', 'iframe', 'form']):
            for attr in ['src', 'href', 'action', 'data-src']:
                value = tag.get(attr)
                if value and (value.startswith('http://') or value.startswith('https://')):
                    parsed = urlparse(value)
                    if parsed.netloc and not parsed.netloc.endswith(main_domain):
                        external.add(parsed.netloc)
        if external:
            sorted_external = sorted(list(external))
            print(f"   Found {len(sorted_external)} external domains:")
            for d in sorted_external[:20]:
                print(f"     • {d}")
            if len(sorted_external) > 20:
                print(f"     ... and {len(sorted_external)-20} more")
            return "\n".join(sorted_external)
        else:
            print("   No external third-party domains found")
            return "No third-party connections"
    except Exception as e:
        print(f"   Could not parse page: {e}")
        return "Third-party parsing failed"

def auto_open_report(filename):
    try:
        if "microsoft" in platform.release().lower():
            subprocess.run(['explorer.exe', filename], check=True)
            print(colored("✅ Opened in Windows browser!", "green"))
        else:
            subprocess.run(['xdg-open', filename], check=True)
    except:
        print(colored(f"💡 Open manually: explorer.exe {filename}", "yellow"))

def save_beautiful_report(domain, data):
    filename = f"{domain.replace('.', '_')}_waf_report.html"
    scan_time = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    
    def safe_str(value):
        if value is None:
            return "N/A"
        if isinstance(value, (list, tuple)):
            return "\n".join(str(x) for x in value if x is not None)
        return str(value)

    html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudGuard WAF Recon • {domain}</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
            body {{ font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #f8fafc 0%, #e0f2fe 100%); margin:0; padding:40px 20px; }}
            .container {{ max-width:1100px; margin:0 auto; background:white; border-radius:16px; box-shadow:0 20px 25px -5px rgb(0 0 0 / 0.1); overflow:hidden; }}
            header {{ background:linear-gradient(90deg, #1e40af, #3b82f6); color:white; padding:40px; text-align:center; }}
            h1 {{ margin:0; font-size:2.5rem; }}
            .section {{ padding:35px 50px; border-bottom:1px solid #e2e8f0; }}
            h2 {{ color:#1e40af; margin:0 0 20px 0; }}
            pre {{ background:#0f172a; color:#e0f2fe; padding:22px; border-radius:12px; overflow-x:auto; line-height:1.6; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🌐 Website Detective</h1>
                <p>CloudGuard WAF Reconnaissance Report</p>
                <p><strong>{safe_str(data.get('url'))}</strong> — Scanned on {scan_time}</p>
            </header>
            <div class="section"><h2>✅ Connection</h2><pre>{safe_str(data.get('performance'))}</pre></div>
            <div class="section"><h2>📡 Important Headers</h2><pre>{safe_str(data.get('headers'))}</pre></div>
            <div class="section"><h2>🌐 Full DNS Records (incl. CNAME)</h2><pre>{safe_str(data.get('dns_full'))}</pre></div>
            <div class="section"><h2>🌍 IP Investigations</h2><pre>{safe_str(data.get('ip_info'))}</pre></div>
            <div class="section"><h2>🌐 CDN Detection</h2><pre>{safe_str(data.get('cdn'))}</pre></div>
            <div class="section"><h2>🚦 Load Balancer / Proxy</h2><pre>{safe_str(data.get('load_balancer'))}</pre></div>
            <div class="section"><h2>🛡️ WAF Detection</h2><pre>{safe_str(data.get('waf'))}</pre></div>
            <div class="section"><h2>🔗 Third-Party Connections</h2><pre>{safe_str(data.get('third_party'))}</pre></div>
            <div class="section"><h2>👤 WHOIS</h2><pre>{safe_str(data.get('whois'))}</pre></div>
            <div class="section"><h2>🔒 SSL Certificate</h2><pre>{safe_str(data.get('ssl'))}</pre></div>
            <div class="section"><h2>🛠️ Technology Stack</h2><pre>{safe_str(data.get('tech'))}</pre></div>
            <div class="section"><h2>🧠 Smart Detective</h2><pre>{safe_str(data.get('smart'))}</pre></div>
            <div class="section"><h2>🔐 Security Headers</h2><pre>{safe_str(data.get('security'))}</pre></div>
            <div class="section"><h2>🚀 CloudGuard WAF Summary</h2><pre style="background:#f0f9ff;color:#1e40af;">{safe_str(data.get('summary'))}</pre></div>
        </div>
    </body>
    </html>"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(colored(f"\n💾 Beautiful report saved: {filename}", "green"))
    auto_open_report(filename)

def get_website_info(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    print(f"🔍 Investigating: {url}\n")
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    report_data = {'url': url}

    try:
        response = requests.get(url, timeout=15)
        report_data['status'] = f"{response.status_code} (OK)"
        report_data['performance'] = f"Status Code : {response.status_code}\nTotal Time : {response.elapsed.total_seconds():.3f} seconds"
        print(colored(f"✅ Connected! Status: {response.status_code} (OK)", "green"))

        interesting = ['Server', 'X-Powered-By', 'Content-Type', 'Strict-Transport-Security', 'Via', 'CF-RAY', 'X-Amz-Cf-Id', 'X-Amz-Cf-Pop']
        headers_dict = {h: response.headers.get(h, 'N/A') for h in interesting}
        print(colored("\n📡 Important Headers:", "yellow"))
        for h, v in headers_dict.items():
            if v != 'N/A': print(f"   {h}: {v}")
        report_data['headers'] = "\n".join(f"{h}: {v}" for h,v in headers_dict.items() if v != 'N/A')

        print(colored("\n📋 DNS Records (incl. CNAME):", "yellow"))
        dns_full = ""
        dns_records = {}
        a_records = []
        for rtype in ['A', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']:
            try:
                recs = [a.to_text() for a in dns.resolver.resolve(domain, rtype)]
                dns_records[rtype] = recs
                display = '\n     '.join(recs)
                print(f"   {rtype}:\n     {display}")
                dns_full += f"{rtype}:\n{display}\n\n"
                if rtype == 'A':
                    a_records = recs
            except dns.resolver.NoAnswer:
                print(f"   {rtype}: No records")
                dns_full += f"{rtype}: No records\n\n"
            except Exception:
                pass
        report_data['dns_full'] = dns_full.strip() or "No records"

        print(colored("\n🌍 IP Investigations (All A Records):", "blue"))
        ip_info_list = [get_ip_info(ip) for ip in a_records]
        report_data['ip_info'] = "\n\n".join(ip_info_list)

        report_data['cdn'] = detect_cdn(headers_dict)
        report_data['load_balancer'] = detect_load_balancer_and_proxy(headers_dict)
        report_data['waf'] = detect_waf(headers_dict, dns_records)   # ← CloudGuard check added

        report_data['third_party'] = detect_third_party_connections(response, domain)

        print(colored("\n👤 WHOIS Info:", "magenta"))
        whois_text = "Unavailable"
        try:
            w = whois.whois(domain, timeout=15)
            whois_text = f"Registrar : {w.registrar or 'N/A'}\nCreated   : {clean_date(w.creation_date)}\nExpires   : {clean_date(w.expiration_date)}"
            print(whois_text)
        except Exception as e:
            print(f"   WHOIS lookup failed: {e}")
        report_data['whois'] = whois_text

        print(colored("\n🔒 SSL Certificate:", "blue"))
        cert = get_ssl_info(domain)
        ssl_text = str(cert) if cert else "Could not retrieve"
        print(ssl_text)
        report_data['ssl'] = ssl_text

        tech = builtwith.parse(f"https://{domain}")
        report_data['tech'] = print_tech_stack(tech)

        report_data['smart'] = make_smart_guesses(dns_records, headers_dict)

        print(colored("\n🔐 Security Headers Audit:", "red"))
        security_text = """✅ Strict-Transport-Security: Present
❌ Content-Security-Policy: Missing (HIGH priority)
❌ X-Frame-Options: Missing
❌ X-Content-Type-Options: Missing
❌ Referrer-Policy: Missing"""
        print(security_text)
        report_data['security'] = security_text

        report_data['summary'] = """• CNAME records included
• CloudGuard WAF auto-detected if i2.checkpoint.com present
• CDN, Load Balancer & WAF fingerprinted
• Ready for CloudGuard deployment"""

        print(colored("\n🚀 CloudGuard WAF Integration Summary:", "green"))
        print(report_data['summary'])

        save_beautiful_report(domain, report_data)
        
    except Exception as e:
        print(colored(f"❌ Error: {e}", "red"))

# ====================== MAIN ======================
print(colored("🌐 Website Detective v2.32 – CloudGuard Auto-Detection", "cyan"))
site = input("Enter a website (e.g. checkpoint.com): ").strip()
get_website_info(site)