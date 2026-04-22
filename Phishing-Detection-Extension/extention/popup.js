const SKIP_SCHEMES = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "file://"];
const API_BASE = "http://127.0.0.1:5000";
let currentIsVerified = false;

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function normalizeStatus(status, verified) {
    if (verified) return "verified";
    if (status === "Phishing") return "phishing";
    if (status === "Safe") return "safe";
    return "suspicious";
}

function shouldSkip(url) {
    return !url || SKIP_SCHEMES.some(s => url.startsWith(s));
}

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0]?.url;

    const urlEl = document.getElementById("url-text");
    urlEl.textContent = currentUrl?.length > 60
        ? currentUrl.slice(0, 60) + "…"
        : currentUrl || "(no URL)";

    if (shouldSkip(currentUrl)) {
        showResult({
            domain: "(internal)",
            community_verdict: "Internal browser page",
            report_count: 0,
            verified_business: false
        });
        return;
    }

    fetch(`${API_BASE}/api/public/domain-status?url=${encodeURIComponent(currentUrl)}`, {
        signal: AbortSignal.timeout(8000)
    })
        .then(res => res.json())
        .then(data => {
            if (data.error) showError();
            else showResult(data);
        })
        .catch(() => showError());
});

function showResult(data) {
    document.getElementById("loading").style.display = "none";
    document.getElementById("result").style.display = "block";

    const status = data.status ?? "Unknown";
    const verified = !!data.verified_business;
    currentIsVerified = verified;
    const reportCount = data.report_count ?? 0;
    const verdict = data.community_verdict ?? "Undecided";
    const scoreNum = document.getElementById("score-num");
    const scoreLabel = document.getElementById("score-label");

    const scoreSection = document.getElementById("score-section");
    scoreSection.className = "score-ring " + normalizeStatus(status, verified);
    scoreNum.textContent = verified ? "VERIFIED" : `${reportCount}`;
    scoreLabel.textContent = verified ? "Trusted Business Domain" : "Community Reports";

    const badge = document.getElementById("status-badge");
    badge.textContent = verified ? "✅  Verified" :
                        status === "Phishing" ? "🚨  Likely Phishing" :
                        status === "Suspicious" ? "⚠️  Under Watch" :
                        "ℹ️  Community Status";
    badge.className = "status-badge";

    const detailsEl = document.getElementById("details");
    const items = verified
        ? [
            { key: "Domain", value: data.domain || "-" },
            { key: "Reports", value: `${reportCount}` },
            { key: "Verdict", value: "Verified" }
          ]
        : [
            { key: "Domain", value: data.domain || "-" },
            { key: "Phishing Votes", value: `${data.phishing_votes ?? 0}` },
            { key: "Non-Phishing Votes", value: `${data.non_phishing_votes ?? 0}` },
            { key: "Verdict", value: verdict }
          ];
    detailsEl.innerHTML = items.map(i => `
        <div class="detail-item">
            <div class="detail-value">${escapeHtml(i.value)}</div>
            <div class="detail-key">${escapeHtml(i.key)}</div>
        </div>
    `).join("");

    showReportButton(verified);
}

function showError() {
    document.getElementById("loading").style.display = "none";
    document.getElementById("error-box").style.display = "block";
}

/* =========================
   🔥 COMMUNITY REPORT FEATURE
========================= */

function showReportButton(isVerified) {
    const section = document.getElementById("report-section");
    const button = document.getElementById("report-btn");
    const msg = document.getElementById("report-msg");
    if (!section || !button || !msg) return;

    section.style.display = "block";
    if (isVerified) {
        button.style.display = "none";
        msg.style.display = "block";
        msg.textContent = "Quick report is disabled for verified businesses.";
        return;
    }

    button.style.display = "block";
    msg.style.display = "none";
}

document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("report-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        if (currentIsVerified) return;
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            const url = tabs[0]?.url;
            if (!url || shouldSkip(url)) return;

            btn.disabled = true;
            btn.textContent = "Reporting...";
            try {
                const res = await fetch(`${API_BASE}/api/extension/report`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        url,
                        title: "Extension quick report",
                        details: "Reported from browser extension"
                    })
                });
                const data = await res.json();
                if (!res.ok || data.error) {
                    throw new Error(data.error || "Failed to submit report");
                }
                btn.style.display = "none";
                const msg = document.getElementById("report-msg");
                msg.style.display = "block";
                msg.textContent = "Reported to community. It will appear in the Community tab immediately.";
            } catch (e) {
                btn.disabled = false;
                btn.textContent = "👎 Report as Phishing";
            }
        });
    });
});