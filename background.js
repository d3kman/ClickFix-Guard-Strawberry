// background.js
// Handles suspiciousClipboard messages, notifications, log storage and default settings.

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(null, (items) => {
    const defaults = {
      whitelist: [],
      logs: [],
      keywords: [],
      onScreenAlerts: true
    };
    const toSet = {};
    for (const k in defaults) {
      if (!(k in items)) toSet[k] = defaults[k];
    }
    if (Object.keys(toSet).length > 0) {
      chrome.storage.local.set(toSet);
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "suspiciousClipboard") {
    const origin = msg.origin || (sender && sender.url) || "unknown";

    let host = origin;
    try {
      if (origin && origin.includes("://")) {
        host = new URL(origin).hostname;
      } else if (sender?.url) {
        host = new URL(sender.url).hostname;
      }
    } catch (e) {
      host = origin;
    }

    chrome.storage.local.get({ whitelist: [], logs: [] }, (data) => {
      if (data.whitelist.includes(host)) return;

      const newLog = {
        text: msg.payload,
        origin: host,
        time: new Date().toISOString()
      };

      const updatedLogs = [newLog, ...(data.logs || [])].slice(0, 50);
      chrome.storage.local.set({ logs: updatedLogs });

      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "⚠ Suspicious Clipboard Activity",
        message: `From: ${host}\n\n${truncate(msg.payload, 200)}`
      });
    });
  }

  // 🔹 Handle report download request
  if (msg && msg.type === "downloadReport") {
    try {
      chrome.downloads.download({
        url: msg.url,
        filename: msg.filename || "ClickFix-ThreatReport.json",
        saveAs: true
      }, (downloadId) => {
        if (chrome.runtime.lastError) {
          console.error("Download failed:", chrome.runtime.lastError.message);
        } else {
          console.log("Download started, ID:", downloadId);
        }
      });
    } catch (e) {
      console.error("Download error:", e);
    }
  }
});

function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
