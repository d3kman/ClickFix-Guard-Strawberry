// popup.js
document.addEventListener("DOMContentLoaded", init);

function init() {
    document.getElementById("saveKeywords").addEventListener("click", saveKeywords);
    document.getElementById("resetKeywords").addEventListener("click", resetKeywords);
    document.getElementById("clearLogs").addEventListener("click", clearLogs);
    document.getElementById("refresh").addEventListener("click", renderAll);
    document.getElementById("addWhitelistBtn").addEventListener("click", addWhitelist);
    document.getElementById("clearWhitelist").addEventListener("click", clearWhitelist);
    document.getElementById("onScreenToggle").addEventListener("change", toggleOnScreen);

    renderAll();
}

function renderAll() {
    chrome.storage.local.get({
        keywords: [],
        logs: [],
        whitelist: [],
        onScreenAlerts: true
    }, (data) => {
        // keywords (user-defined only)
        const ta = document.getElementById("keywordsArea");
        ta.value = (data.keywords && data.keywords.length) ? data.keywords.join("\n") : "";

        // on-screen toggle
        document.getElementById("onScreenToggle").checked = !!data.onScreenAlerts;

        // logs
        const logsContainer = document.getElementById("logsContainer");
        logsContainer.innerHTML = "";
        if (!data.logs || data.logs.length === 0) {
            logsContainer.textContent = "No suspicious events logged.";
        } else {
            data.logs.forEach(log => {
                const div = document.createElement("div");
                div.className = "log";
                div.innerHTML = `<div class="origin">${escapeHtml(log.origin)}</div>
                                 <div class="small">${escapeHtml(truncate(log.text, 300))}</div>
                                 <div class="time">${new Date(log.time).toLocaleString()}</div>
                                 <div style="margin-top:6px;">
                                    <button data-origin="${escapeHtml(log.origin)}" class="whBtn">Whitelist</button>
                                 </div>`;
                logsContainer.appendChild(div);
            });

            // attach whitelist button handlers
            logsContainer.querySelectorAll(".whBtn").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    const origin = e.target.getAttribute("data-origin");
                    addWhitelist(origin);
                });
            });
        }

        // whitelist
        const wlDiv = document.getElementById("whitelistList");
        wlDiv.innerHTML = "";
        if (!data.whitelist || data.whitelist.length === 0) {
            wlDiv.textContent = "No sites whitelisted.";
        } else {
            data.whitelist.forEach(h => {
                const span = document.createElement("div");
                span.innerHTML = `<span>${escapeHtml(h)}</span> <button data-host="${escapeHtml(h)}">Remove</button>`;
                wlDiv.appendChild(span);
            });
            wlDiv.querySelectorAll("button").forEach(b => {
                b.addEventListener("click", (e) => {
                    const host = e.target.getAttribute("data-host");
                    removeWhitelist(host);
                });
            });
        }
    });
}

function saveKeywords() {
    const raw = document.getElementById("keywordsArea").value;
    const arr = raw.split("\n").map(s => s.trim()).filter(Boolean);
    chrome.storage.local.set({ keywords: arr }, () => {
        alert("Custom keywords saved.");
    });
}

function resetKeywords() {
    // Clear only user-defined keywords
    chrome.storage.local.set({ keywords: [] }, () => {
        document.getElementById("keywordsArea").value = "";
        alert("Custom keywords cleared. Built-in protections remain active.");
    });
}

function clearLogs() {
    chrome.storage.local.set({ logs: [] }, () => {
        renderAll();
    });
}

function addWhitelist(arg) {
    if (typeof arg === "string" && arg.includes(".")) {
        // called from button or programmatically with host
        const host = arg;
        chrome.storage.local.get({ whitelist: [] }, data => {
            const list = data.whitelist || [];
            if (!list.includes(host)) {
                list.push(host);
                chrome.storage.local.set({ whitelist: list }, () => {
                    renderAll();
                });
            } else {
                alert(`${host} is already whitelisted.`);
            }
        });
    } else {
        const input = document.getElementById("addWhitelistInput").value.trim();
        if (!input) return alert("Enter a hostname (e.g. example.com).");
        addWhitelist(input);
        document.getElementById("addWhitelistInput").value = "";
    }
}

function removeWhitelist(host) {
    chrome.storage.local.get({ whitelist: [] }, data => {
        let list = data.whitelist || [];
        list = list.filter(h => h !== host);
        chrome.storage.local.set({ whitelist: list }, () => {
            renderAll();
        });
    });
}

function clearWhitelist() {
    if (!confirm("Clear all whitelist entries?")) return;
    chrome.storage.local.set({ whitelist: [] }, () => {
        renderAll();
    });
}

function toggleOnScreen(e) {
    chrome.storage.local.set({ onScreenAlerts: !!e.target.checked });
}

// helpers
function truncate(s, n) {
    if (!s) return "";
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function escapeHtml(unsafe) {
    if (unsafe === undefined || unsafe === null) return "";
    return String(unsafe)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

