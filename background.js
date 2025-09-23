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

      const now = new Date();

      // ✅ Detailed log entry
      const newLog = {
        reportType: "ClickFix Threat Log",
        timeUTC: now.toISOString(),
        timeLocal: now.toLocaleString("sv-SE", { timeZone: "Europe/Stockholm" }),
        url: sender?.url || origin || "unknown",
        sourceHost: host,
        detectedClipboardPayload: msg.payload || "",
        environment: {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language
        }
      };

      const logs = Array.isArray(data.logs) ? data.logs : [];
      const updatedLogs = [newLog, ...logs].slice(0, 50);

      chrome.storage.local.set({ logs: updatedLogs }, () => {
        try {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "⚠ Suspicious Clipboard Activity",
            message: `From: ${host}\n\n${truncate(msg.payload, 200)}`
          });
        } catch (e) {
          console.error("Notification failed:", e);
        }
      });
    });
  }

  if (msg && msg.type === "downloadReport") {
  try {
    const reportData = msg.data || msg; // fallback
    const json = JSON.stringify(reportData, null, 2);
    const blobUrl = "data:application/json;base64," + btoa(unescape(encodeURIComponent(json)));

    const filename = msg.filename || `ClickFix-ThreatReport-${Date.now()}.json`;

    chrome.downloads.download({
      url: blobUrl,
      filename,
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
