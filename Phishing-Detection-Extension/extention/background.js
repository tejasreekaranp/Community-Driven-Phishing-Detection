const SKIP_SCHEMES = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "file://"];
const API_BASE = "http://127.0.0.1:5000";

const resultCache = {};

function shouldSkip(url) {
    if (!url) return true;
    return SKIP_SCHEMES.some(s => url.startsWith(s));
}

async function analyzeUrl(tabId, url) {
    if (shouldSkip(url)) return;

    if (resultCache[url]) {
        applyResult(tabId, resultCache[url]);
        return;
    }

    try {
        const response = await fetch(
            `${API_BASE}/api/public/domain-status?url=${encodeURIComponent(url)}`,
            { signal: AbortSignal.timeout(8000) }
        );

        if (!response.ok) return;

        const data = await response.json();

        if (data.error) {
            console.warn("[PhishDetect] API error:", data.error);
            return;
        }

        resultCache[url] = data;
        applyResult(tabId, data);

    } catch (err) {
        console.warn("[PhishDetect] Backend unreachable:", err.message);
    }
}

function applyResult(tabId, data) {
    const status = data.status || "Unknown";
    const verified = !!data.verified_business;

    let color = "#4CAF50";
    let badgeText = "i";

    if (verified) {
        color = "#2563eb";
        badgeText = "V";
    } else if (status === "Suspicious") {
        color = "#FF9800";
        badgeText = "?";
    } else if (status === "Phishing") {
        color = "#F44336";
        badgeText = "!";
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });

    if (!verified && status === "Phishing") {
        chrome.scripting.executeScript({
            target: { tabId },
            func: (url) => {
                const proceed = confirm(
                    `⚠️ PHISHING WARNING\n\n` +
                    `URL: ${url}\n\n` +
                    `This site has been flagged by community reports as likely phishing.\n` +
                    `Click CANCEL to go back, or OK to proceed at your own risk.`
                );
                if (!proceed) {
                    history.back();
                }
            },
            args: [data.url]
        }).catch(() => {});
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        analyzeUrl(tabId, tab.url);
    }
});

setInterval(() => {
    const keys = Object.keys(resultCache);
    if (keys.length > 200) {
        keys.slice(0, 100).forEach(k => delete resultCache[k]);
    }
}, 10 * 60 * 1000);