function bindForm() {
    const form = document.querySelector("form");
    const input = form && form.querySelector("input[name='url']");
    if (!form || !input || !window.fetch) return;
    let overlay = document.getElementById("scan-overlay");
    let pollTimer = null;
    let clockTimer = null;

    function ensureOverlay() {
        if (!document.getElementById("scan-overlay-style")) {
            const st = document.createElement("style");
            st.id = "scan-overlay-style";
            st.textContent = "#scan-overlay{display:none;position:fixed;inset:0;background:rgb(15 23 42 / .45);z-index:50;align-items:center;justify-content:center;padding:20px}#scan-overlay.open{display:flex}.scan-card{background:#fff;border-radius:12px;padding:24px 28px;width:min(440px,92vw);text-align:center}.scan-bar{height:8px;background:#e2e8f0;border-radius:99px;overflow:hidden;margin:16px 0 8px}.scan-bar>span{display:block;height:100%;width:35%;background:#1e40af;animation:scan-slide 1.2s ease-in-out infinite}@keyframes scan-slide{0%{transform:translateX(-120%)}100%{transform:translateX(350%)}}#scan-overlay-log{text-align:left;max-height:180px;overflow:auto;font-size:12px;background:#0f172a;color:#e0f2fe;padding:10px;border-radius:8px;margin:8px 0 12px;white-space:pre-wrap}";
            document.head.appendChild(st);
        }
        if (overlay) return overlay;
        overlay = document.getElementById("scan-overlay");
        if (overlay) return overlay;
        overlay = document.createElement("div");
        overlay.id = "scan-overlay";
        overlay.innerHTML = '<div class="scan-card"><h2 id="scan-overlay-title">Scanning…</h2><p>Live lookup log</p><div class="scan-bar"><span></span></div><p class="hint" id="scan-overlay-time">0s</p><pre id="scan-overlay-log"></pre><button type="button" class="btn-secondary" id="scan-cancel">Cancel scan</button></div>';
        document.body.appendChild(overlay);
        return overlay;
    }

    function showOverlay(target) {
        overlay = ensureOverlay();
        overlay.hidden = false;
        overlay.classList.add("open");
        const titleEl = document.getElementById("scan-overlay-title");
        if (titleEl) titleEl.textContent = "Scanning " + target;
        document.title = "Scanning " + target;
        const btn = form.querySelector("button[type='submit']");
        if (btn) {
            btn.disabled = true;
            btn.textContent = "Scanning…";
        }
        const started = Date.now();
        const timeEl = document.getElementById("scan-overlay-time");
        const budget = Number(typeof SCAN_BUDGET !== "undefined" ? SCAN_BUDGET : 55);
        if (clockTimer) clearInterval(clockTimer);
        clockTimer = setInterval(function () {
            if (timeEl) timeEl.textContent = Math.round((Date.now() - started) / 1000) + "s elapsed · budget " + budget + "s";
        }, 250);
    }

    function hideOverlay() {
        if (overlay) {
            overlay.hidden = true;
            overlay.classList.remove("open");
        }
        const btn = form.querySelector("button[type='submit']");
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Analyze website";
        }
        if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    function renderLogs(logs) {
        const logEl = document.getElementById("scan-overlay-log");
        if (!logEl || !logs) return;
        logEl.textContent = logs.join("\n");
        logEl.scrollTop = logEl.scrollHeight;
    }

    function finishJob(id, target) {
        hideOverlay();
        window.location = "/?url=" + encodeURIComponent(target) + "&job=" + encodeURIComponent(id);
    }

    function pollJob(id, target) {
        fetch("/scan/status/" + encodeURIComponent(id), { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderLogs(data.logs || []);
                if (data.done) finishJob(id, target || data.url || "");
            })
            .catch(function () {});
    }

    function startJob(target, via) {
        const body = new URLSearchParams();
        body.set("url", target);
        if (via) body.set("via", via);
        fetch("/scan/start", { method: "POST", body: body, credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.id) throw new Error(data.error || "start failed");
                let loc = "/?url=" + encodeURIComponent(target) + "&job=" + encodeURIComponent(data.id);
                if (via) loc += "&via=" + encodeURIComponent(via);
                history.replaceState({}, "", loc);
                const cancelBtn = document.getElementById("scan-cancel");
                if (cancelBtn) {
                    cancelBtn.onclick = function () {
                        const payload = new URLSearchParams();
                        payload.set("id", data.id);
                        fetch("/cancel", { method: "POST", body: payload, credentials: "same-origin", keepalive: true });
                        hideOverlay();
                        document.title = "Website Detective";
                        history.pushState({}, "", "/");
                    };
                }
                pollJob(data.id, target);
                pollTimer = setInterval(function () { pollJob(data.id, target); }, 400);
            })
            .catch(function () { hideOverlay(); });
    }

    form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        const target = (input.value || "").trim();
        if (!target) return;
        const viaEl = form.querySelector("input[name='via']");
        const via = viaEl ? (viaEl.value || "").trim() : "";
        showOverlay(target);
        startJob(target, via);
    });

    const hasResult = typeof SCAN !== "undefined" && SCAN && (SCAN.domain || SCAN.error);
    if (typeof SCAN_JOB === "string" && SCAN_JOB && !hasResult) {
        const target = (input.value || "").trim() || "site";
        showOverlay(target);
        pollJob(SCAN_JOB, target);
        pollTimer = setInterval(function () { pollJob(SCAN_JOB, target); }, 400);
    }
}

bindForm();
