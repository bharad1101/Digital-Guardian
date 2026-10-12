/* =========================================================
   DIGITAL GUARDIAN - shared client helpers
   ========================================================= */
(function () {
    "use strict";

    const meta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = meta ? meta.getAttribute("content") : "";

    const LEVEL_CLASS = {
        SAFE: "lvl-safe",
        LOW_RISK: "lvl-low",
        SUSPICIOUS: "lvl-suspicious",
        HIGH_RISK: "lvl-high",
        CRITICAL: "lvl-critical",
    };

    const LEVEL_LABEL = {
        SAFE: "Safe",
        LOW_RISK: "Low Risk",
        SUSPICIOUS: "Suspicious",
        HIGH_RISK: "High Risk",
        CRITICAL: "Critical",
    };

    const RISK_COLOR = {
        SAFE: "#22c55e",
        LOW_RISK: "#84cc16",
        SUSPICIOUS: "#f59e0b",
        HIGH_RISK: "#f97316",
        CRITICAL: "#ef4444",
    };

    function levelClass(level) {
        return LEVEL_CLASS[level] || "lvl-unknown";
    }
    function levelLabel(level) {
        return LEVEL_LABEL[level] || level || "Unknown";
    }
    function riskColor(level) {
        return RISK_COLOR[level] || "#38bdf8";
    }

    function escapeHtml(value) {
        if (value === null || value === undefined) return "";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async function api(url, options) {
        options = options || {};
        const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
        if (options.json !== undefined) {
            headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(options.json);
        }
        if (options.method && options.method.toUpperCase() !== "GET") {
            headers["X-CSRFToken"] = csrfToken;
        }
        const response = await fetch(url, Object.assign({}, options, { headers: headers }));
        let data = null;
        try {
            data = await response.json();
        } catch (e) {
            data = { success: false, error: "Unexpected server response." };
        }
        if (!response.ok) {
            const message = (data && (data.error || data.message)) || ("Request failed (" + response.status + ")");
            const err = new Error(message);
            err.status = response.status;
            err.data = data;
            throw err;
        }
        return data;
    }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = text;
        return node;
    }

    function buildResult(data) {
        const wrap = el("div", "result-panel");

        // Header
        const head = el("div", "result-head");
        const ring = el("div", "score-ring");
        ring.style.setProperty("--score", String(data.risk_score || 0));
        ring.style.setProperty("--ring-color", riskColor(data.threat_level));
        ring.appendChild(el("div", "score-num", String(data.risk_score || 0)));
        const sub = el("div", "score-sub", "/ 100 RISK");
        ring.appendChild(sub);
        head.appendChild(ring);

        const meta = el("div", "result-meta");
        const badge = el("span", "risk-badge " + levelClass(data.threat_level),
            levelLabel(data.threat_level));
        meta.appendChild(badge);
        meta.appendChild(el("div", "threat-type", data.threat_type || "Analysis"));
        if (data.scam_category && data.scam_category !== "None") {
            meta.appendChild(el("div", "muted", "Category: " + data.scam_category));
        }
        if (data.created_at) {
            meta.appendChild(el("div", "muted", "Analysed: " + data.created_at));
        }
        head.appendChild(meta);
        wrap.appendChild(head);

        // KV grid
        const kv = el("div", "kv mt-2");
        kv.appendChild(kvItem("Threat level", levelLabel(data.threat_level)));
        kv.appendChild(kvItem("Rule score", (data.rule_score != null ? data.rule_score : "-") + " / 100"));
        kv.appendChild(kvItem("ML prediction", data.ml_available ? (data.ml_prediction || "Unknown")
            : "Unavailable"));
        kv.appendChild(kvItem("ML spam probability", data.ml_available
            ? (Number(data.ml_spam_probability || 0).toFixed(1) + "%") : "n/a"));
        wrap.appendChild(kv);

        // Explanation
        if (data.explanation) {
            const callout = el("div", "callout mt-2");
            callout.appendChild(el("strong", null, "Why this result: "));
            callout.appendChild(document.createTextNode(data.explanation));
            wrap.appendChild(callout);
        }

        // Indicators
        if (data.indicators && data.indicators.length) {
            wrap.appendChild(sectionTitle("Security indicators"));
            const ul = el("ul", "indicator-list warn");
            data.indicators.forEach(function (item) { ul.appendChild(el("li", null, item)); });
            wrap.appendChild(ul);
        }

        // Manipulation
        if (data.manipulation && data.manipulation.length) {
            wrap.appendChild(sectionTitle("Social-engineering techniques"));
            const chips = el("div", "chips");
            data.manipulation.forEach(function (m) { chips.appendChild(el("span", "chip", m)); });
            wrap.appendChild(chips);
        }

        // URLs
        if (data.urls && data.urls.length) {
            wrap.appendChild(sectionTitle("Links detected"));
            data.urls.forEach(function (u) {
                wrap.appendChild(el("code", "detected-url", u));
            });
        }

        // Embedding context (image)
        if (data.image) {
            const img = data.image;
            wrap.appendChild(sectionTitle("Image analysis"));
            const kv2 = el("div", "kv");
            kv2.appendChild(kvItem("Dimensions", (img.width || "?") + " × " + (img.height || "?")));
            const src = img.sources || {};
            kv2.appendChild(kvItem("QR decode", src.qr ? src.qr.status : "not run"));
            kv2.appendChild(kvItem("OCR", src.ocr ? src.ocr.status : "not run"));
            kv2.appendChild(kvItem("Findings based on", "Automatic analysis (advisory)"));
            wrap.appendChild(kv2);
            if (img.qr_payload) {
                wrap.appendChild(el("code", "detected-url", "QR: " + img.qr_payload));
            }
        }

        // Recommendations
        if (data.recommendations && data.recommendations.length) {
            const rec = el("div", "callout mt-2");
            rec.appendChild(el("strong", null, "Recommended actions"));
            const ul = el("ul", "indicator-list safe");
            data.recommendations.forEach(function (r) { ul.appendChild(el("li", null, r)); });
            rec.appendChild(ul);
            wrap.appendChild(rec);
        }

        // Uncertainty
        if (data.uncertainty) {
            const note = el("p", "muted mt-2");
            note.appendChild(el("strong", null, "Limitations: "));
            note.appendChild(document.createTextNode(data.uncertainty));
            wrap.appendChild(note);
        }

        // Actions
        const actions = el("div", "flex gap-1 wrap mt-2");
        const copyBtn = el("button", "btn btn-sm", "Copy summary");
        copyBtn.type = "button";
        copyBtn.addEventListener("click", function () {
            copySummary(data);
            copyBtn.textContent = "Copied";
            setTimeout(function () { copyBtn.textContent = "Copy summary"; }, 1500);
        });
        actions.appendChild(copyBtn);
        wrap.appendChild(actions);

        return wrap;
    }

    function kvItem(key, value) {
        const box = el("div", "kv-item");
        box.appendChild(el("div", "k", key));
        box.appendChild(el("div", "v", value === null || value === undefined ? "-" : String(value)));
        return box;
    }

    function sectionTitle(text) {
        const h = el("h3", "mt-2 mb-0", text);
        return h;
    }

    function summaryText(data) {
        const lines = [];
        lines.push("Digital Guardian analysis " + (data.analysis_id || ""));
        lines.push("Input: " + (data.input_type || "-") + " / " + (data.channel || "-"));
        lines.push("Risk: " + (data.risk_score || 0) + "/100 (" + levelLabel(data.threat_level) + ")");
        if (data.threat_type) lines.push("Threat: " + data.threat_type);
        if (data.scam_category && data.scam_category !== "None") lines.push("Category: " + data.scam_category);
        if (data.ml_available) lines.push("ML: " + data.ml_prediction + " (" + Number(data.ml_spam_probability || 0).toFixed(1) + "%)");
        if (data.indicators && data.indicators.length) {
            lines.push("Indicators:");
            data.indicators.forEach(function (i) { lines.push("  - " + i); });
        }
        if (data.recommendations && data.recommendations.length) {
            lines.push("Recommendations:");
            data.recommendations.forEach(function (r) { lines.push("  - " + r); });
        }
        lines.push("Advisory only - not a guarantee of safety.");
        return lines.join("\n");
    }

    function copySummary(data) {
        const text = summaryText(data);
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "absolute";
        area.style.left = "-9999px";
        document.body.appendChild(area);
        area.select();
        try { document.execCommand("copy"); } catch (e) { /* ignore */ }
        document.body.removeChild(area);
    }

    function initNav() {
        const toggle = document.querySelector("[data-nav-toggle]");
        const links = document.querySelector(".nav-links");
        if (!toggle || !links) return;
        toggle.addEventListener("click", function () {
            const open = links.classList.toggle("open");
            toggle.setAttribute("aria-expanded", open ? "true" : "false");
        });
    }

    function initCopyButtons() {
        document.querySelectorAll("[data-copy-summary]").forEach(function (btn) {
            const panel = btn.closest(".result-panel");
            if (!panel) return;
            const script = panel.querySelector(".dg-result-json");
            if (!script) return;
            let data;
            try { data = JSON.parse(script.textContent); } catch (e) { return; }
            btn.addEventListener("click", function () {
                copySummary(data);
                const original = btn.textContent;
                btn.textContent = "Copied";
                setTimeout(function () { btn.textContent = original; }, 1500);
            });
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        initNav();
        initCopyButtons();
    });

    window.DG = {
        api: api,
        csrfToken: csrfToken,
        escapeHtml: escapeHtml,
        levelClass: levelClass,
        levelLabel: levelLabel,
        riskColor: riskColor,
        buildResult: buildResult,
        copySummary: copySummary,
        summaryText: summaryText,
        el: el,
    };
})();
