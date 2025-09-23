// background.js
// Handles suspiciousClipboard messages, notifications, log storage and default settings.

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(null, (items) => {
    const defaults = {
      whitelist: [],
      logs: [],
      keywords: []
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
    const origin = msg.origin || sender?.url || "unknown";

    let host = origin;
    try {
      if (origin.includes("://")) {
        host = new URL(origin).hostname;
      } else if (sender?.url) {
        host = new URL(sender.url).hostname;
      }
    } catch (e) {
      host = origin || "unknown";
    }

    chrome.storage.local.get({ whitelist: [], logs: [] }, (data) => {
      if (Array.isArray(data.whitelist) && data.whitelist.includes(host)) return;

      // ✅ Detailed log entry (kept in full JSON form)
      const newLog = {
        reportType: "ClickFix Threat Log",
        time: new Date().toISOString(),
        url: sender?.url || origin || "unknown",
        sourceHost: host,
        detectedClipboardPayload: msg.payload || ""
      };

      const logs = Array.isArray(data.logs) ? data.logs : [];
      const updatedLogs = [newLog, ...logs].slice(0, 50);

      chrome.storage.local.set({ logs: updatedLogs }, () => {
        try {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "⚠ Suspicious Clipboard Activity",
            message: `From: ${host}\n\nClipboard contents flagged.`
          });
        } catch (e) {
          console.error("Notification failed:", e);
        }
      });
    });
  }

if (msg && msg.type === "downloadReport") {
  try {
    const json = JSON.stringify(msg.data, null, 2);
    const blobUrl = "data:application/json;base64," + btoa(unescape(encodeURIComponent(json)));

    chrome.downloads.download({
      url: blobUrl,
      filename: msg.filename || "ClickFix-ThreatReport.json",
      saveAs: true
    });
  } catch (e) {
    console.error("Download error:", e);
  }
}

});

function truncate(s, n) {
  if (!s) return "";
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}
