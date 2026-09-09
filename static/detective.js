const BASELINE_PREFIX = "wd:baseline:";
const BASELINE_INDEX = "wd:baseline-index";
const META_KEY = "wd:meta";
const MAX_BASELINES = 50;
const SECTIONS = [
    ["Performance", "perf"],
    ["Connection", "performance"],
    ["Important headers", "headers"],
    ["DNS records", "dns_full"],
    ["IP investigations", "ip_info"],
    ["CDN", "cdn"],
    ["Load balancer / proxy", "load_balancer"],
    ["WAF", "waf"],
    ["Third-party connections", "third_party"],
    ["WHOIS", "whois"],
    ["SSL certificate", "ssl"],
    ["Technology stack", "tech"],
    ["Smart detective", "smart"],
    ["Security headers", "security"],
    ["CloudGuard WAF summary", "summary"]
];

function $(id) { return document.getElementById(id); }

function flashCopied(btn, label) {
    if (!btn) return;
    const original = btn.textContent;
    btn.textContent = label || "Copied";
    setTimeout(() => { btn.textContent = original; }, 1500);
}

function copyText(text, btn) {
    const done = () => flashCopied(btn);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    } else {
        fallbackCopy(text, done);
    }
}

function fallbackCopy(text, done) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
    if (done) done();
}

function loadMeta() {
    try { return JSON.parse(sessionStorage.getItem(META_KEY) || "{}"); }
    catch (e) { return {}; }
}

function saveMeta() {
    const meta = {
        ticket: ($("meta-ticket") && $("meta-ticket").value) || "",
        customer: ($("meta-customer") && $("meta-customer").value) || "",
        notes: ($("meta-notes") && $("meta-notes").value) || ""
    };
    sessionStorage.setItem(META_KEY, JSON.stringify(meta));
    return meta;
}

function markdownWithMeta(baseMd) {
    const meta = saveMeta();
    const insert = [];
    if (meta.ticket.trim()) insert.push("- **Ticket:** " + meta.ticket.trim());
    if (meta.customer.trim()) insert.push("- **Customer:** " + meta.customer.trim());
    let block = insert.join("\n");
    if (meta.notes.trim()) {
        const quoted = meta.notes.trim().split("\n").map(function (n) { return "> " + n; }).join("\n");
        block = block ? block + "\n\n" + quoted : quoted;
    }
    if (!block) return baseMd;
    const idx = baseMd.indexOf("\n\n## ");
    if (idx === -1) return baseMd + "\n" + block + "\n";
    return baseMd.slice(0, idx) + "\n" + block + baseMd.slice(idx);
}

function filenameFor(report) {
    const domain = String(report.domain || "report").replace(/[^a-z0-9.-]/gi, "_");
    return domain + "-detective.md";
}

function indexRead() {
    try { return JSON.parse(localStorage.getItem(BASELINE_INDEX) || "[]"); }
    catch (e) { return []; }
}

function indexWrite(items) {
    localStorage.setItem(BASELINE_INDEX, JSON.stringify(items));
}

function getBaseline(domain) {
    try {
        const raw = localStorage.getItem(BASELINE_PREFIX + domain);
        return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
}

function saveBaseline(report) {
    const domain = report.domain;
    const payload = { savedAt: new Date().toISOString(), report: report };
    localStorage.setItem(BASELINE_PREFIX + domain, JSON.stringify(payload));
    let items = indexRead().filter(function (x) { return x.domain !== domain; });
    items.unshift({ domain: domain, savedAt: payload.savedAt });
    while (items.length > MAX_BASELINES) {
        const dropped = items.pop();
        localStorage.removeItem(BASELINE_PREFIX + dropped.domain);
    }
    indexWrite(items);
    refreshBaselineBanner();
}

function clearBaseline(domain) {
    localStorage.removeItem(BASELINE_PREFIX + domain);
    indexWrite(indexRead().filter(function (x) { return x.domain !== domain; }));
    refreshBaselineBanner();
    const panel = $("compare-panel");
    if (panel) panel.classList.remove("open");
}

function formatSavedAt(iso) {
    try {
        const d = new Date(iso);
        return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    } catch (e) { return iso; }
}

function refreshBaselineBanner() {
    if (!SCAN || SCAN.error) return;
    const banner = $("baseline-banner");
    const text = $("baseline-banner-text");
    const saved = getBaseline(SCAN.domain);
    if (!saved) {
        banner.hidden = true;
        return;
    }
    text.textContent = "Baseline saved " + formatSavedAt(saved.savedAt) + " for " + SCAN.domain + " (this hostname only).";
    banner.hidden = false;
}

function yesNo(v) { return v ? "Yes" : "No"; }

function cnameCloudguard(report) {
    const cnames = (report.dns_records && report.dns_records.CNAME) || [];
    return cnames.some(function (c) { return String(c).toLowerCase().indexOf("i2.checkpoint.com") !== -1; });
}

function aRecords(report) {
    return ((report.dns_records && report.dns_records.A) || []).map(String);
}

function pinnedSummary(base, curr) {
    const items = [];
    if (!!base.cloudguard !== !!curr.cloudguard) {
        items.push("CloudGuard: " + yesNo(base.cloudguard) + " → " + yesNo(curr.cloudguard));
    }
    const bC = cnameCloudguard(base), cC = cnameCloudguard(curr);
    if (bC !== cC) {
        items.push("i2.checkpoint.com CNAME: " + (bC ? "present" : "absent") + " → " + (cC ? "present" : "absent"));
    }
    const bA = new Set(aRecords(base)), cA = new Set(aRecords(curr));
    const added = aRecords(curr).filter(function (x) { return !bA.has(x); });
    const removed = aRecords(base).filter(function (x) { return !cA.has(x); });
    if (added.length || removed.length) {
        items.push("A records: added " + (added.join(", ") || "none") + "; removed " + (removed.join(", ") || "none"));
    }
    if (String(base.waf || "") !== String(curr.waf || "")) {
        items.push("WAF: " + (base.waf || "n/a") + " → " + (curr.waf || "n/a"));
    }
    const bFlags = base.security_flags || {};
    const cFlags = curr.security_flags || {};
    const names = Object.keys(Object.assign({}, bFlags, cFlags));
    names.forEach(function (name) {
        if (!!bFlags[name] !== !!cFlags[name]) {
            items.push(name + ": " + (bFlags[name] ? "present" : "missing") + " → " + (cFlags[name] ? "present" : "missing"));
        }
    });
    const bT = base.perf_ttfb_ms, cT = curr.perf_ttfb_ms;
    if (bT != null && cT != null) {
        const delta = cT - bT;
        const pct = bT ? Math.abs(delta) / bT : 0;
        const noisy = Math.abs(delta) < 50 || pct < 0.15;
        const sign = delta > 0 ? "+" : "";
        items.push("TTFB: " + Math.round(bT) + " ms → " + Math.round(cT) + " ms (" + sign + Math.round(delta) + " ms)" + (noisy ? " — small change, treat as directional" : ""));
    }
    if (!items.length) items.push("No CloudGuard / IP / header / TTFB changes in the pinned fields. See section diffs below.");
    return items;
}

function diffLines(oldText, newText) {
    const a = String(oldText || "").split("\n");
    const b = String(newText || "").split("\n");
    const n = a.length, m = b.length;
    const dp = [];
    for (let i = 0; i <= n; i++) {
        dp[i] = new Array(m + 1);
        dp[i][m] = 0;
    }
    for (let j = 0; j <= m; j++) dp[n][j] = 0;
    for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
            dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
        if (a[i] === b[j]) { out.push({ type: "same", text: a[i] }); i++; j++; }
        else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ type: "del", text: a[i] }); i++; }
        else { out.push({ type: "add", text: b[j] }); j++; }
    }
    while (i < n) { out.push({ type: "del", text: a[i++] }); }
    while (j < m) { out.push({ type: "add", text: b[j++] }); }
    return out;
}

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

function comparisonMarkdown(baseWrap, curr) {
    const base = baseWrap.report;
    const lines = [
        "# Before / after — " + (curr.domain || ""),
        "",
        "- **Baseline:** " + formatSavedAt(baseWrap.savedAt),
        "- **Current:** " + (curr.scanned_at || ""),
        "- **URL:** " + (curr.url || ""),
        "- **Release:** " + (APP_RELEASE || "")
    ];
    pinnedSummary(base, curr).forEach(function (item) {
        lines.push("- **Change:** " + item);
    });
    SECTIONS.forEach(function (pair) {
        const title = pair[0], key = pair[1];
        const diff = diffLines(base[key], curr[key]);
        const added = diff.filter(function (d) { return d.type === "add"; }).map(function (d) { return d.text; });
        const removed = diff.filter(function (d) { return d.type === "del"; }).map(function (d) { return d.text; });
        if (!added.length && !removed.length) return;
        lines.push("", "## " + title);
        if (added.length) {
            lines.push("", "### Added", "", "```");
            lines.push.apply(lines, added);
            lines.push("```");
        }
        if (removed.length) {
            lines.push("", "### Removed", "", "```");
            lines.push.apply(lines, removed);
            lines.push("```");
        }
    });
    lines.push("");
    return lines.join("\n");
}

function renderCompare() {
    const saved = getBaseline(SCAN.domain);
    const panel = $("compare-panel");
    const body = $("compare-body");
    body.replaceChildren();
    if (!saved) {
        body.appendChild(el("p", null, "No baseline saved for this hostname."));
        panel.classList.add("open");
        return;
    }
    const pin = el("div", "pin");
    pin.appendChild(el("strong", null, "Pinned summary"));
    const ul = el("ul");
    pinnedSummary(saved.report, SCAN).forEach(function (item) {
        ul.appendChild(el("li", null, item));
    });
    pin.appendChild(ul);
    body.appendChild(pin);

    SECTIONS.forEach(function (pair) {
        const title = pair[0], key = pair[1];
        const diff = diffLines(saved.report[key], SCAN[key]);
        const changed = diff.some(function (d) { return d.type !== "same"; });
        const details = document.createElement("details");
        details.className = "diff-section";
        details.open = changed;
        const summary = document.createElement("summary");
        summary.textContent = title + (changed ? " — changed" : " — no change");
        details.appendChild(summary);
        diff.forEach(function (d) {
            const cls = d.type === "add" ? "diff-line diff-add" : d.type === "del" ? "diff-line diff-del" : "diff-line diff-same";
            const prefix = d.type === "add" ? "+ " : d.type === "del" ? "- " : "  ";
            details.appendChild(el("div", cls, prefix + d.text));
        });
        body.appendChild(details);
    });
    panel.classList.add("open");
    panel.dataset.compareMd = comparisonMarkdown(saved, SCAN);
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function bind() {
    if (!SCAN || SCAN.error) return;
    const meta = loadMeta();
    if ($("meta-ticket")) $("meta-ticket").value = meta.ticket || "";
    if ($("meta-customer")) $("meta-customer").value = meta.customer || "";
    if ($("meta-notes")) $("meta-notes").value = meta.notes || "";
    ["meta-ticket", "meta-customer", "meta-notes"].forEach(function (id) {
        const node = $(id);
        if (node) node.addEventListener("input", saveMeta);
    });

    $("btn-copy").addEventListener("click", function () {
        copyText(markdownWithMeta(SCAN.markdown || $("report-md").value), $("btn-copy"));
    });
    $("btn-download").addEventListener("click", function () {
        const md = markdownWithMeta(SCAN.markdown || $("report-md").value);
        const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = filenameFor(SCAN);
        a.click();
        URL.revokeObjectURL(a.href);
    });
    $("btn-print").addEventListener("click", function () { window.print(); });
    $("btn-baseline").addEventListener("click", function () {
        saveBaseline(SCAN);
        flashCopied($("btn-baseline"), "Saved");
    });
    const curlBtn = $("btn-copy-curl");
    if (curlBtn) {
        curlBtn.addEventListener("click", function () {
            copyText(SCAN.curl_timing || $("curl-cmd").textContent, curlBtn);
        });
    }
    $("btn-compare").addEventListener("click", renderCompare);
    $("btn-replace").addEventListener("click", function () {
        saveBaseline(SCAN);
        flashCopied($("btn-replace"), "Replaced");
        renderCompare();
    });
    $("btn-clear").addEventListener("click", function () { clearBaseline(SCAN.domain); });
    $("btn-close-compare").addEventListener("click", function () {
        $("compare-panel").classList.remove("open");
    });
    $("btn-copy-compare").addEventListener("click", function () {
        const md = $("compare-panel").dataset.compareMd || "";
        copyText(md, $("btn-copy-compare"));
    });
    if (WAFBUDDY_URL && $("link-wafbuddy")) $("link-wafbuddy").href = WAFBUDDY_URL;
    refreshBaselineBanner();
}

bind();
