// background.js
// Handles suspiciousClipboard messages, notifications, log storage.

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(null, (items) => {
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
      chrome.storage.sync.set(toSet);
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "suspiciousClipboard") {
    (async () => {
      let origin = msg.origin || (sender && sender.url) || "unknown";
      let host = origin;
      try {
        if (origin && origin.includes("://")) host = new URL(origin).hostname || origin;
        else if (sender && sender.url) host = new URL(sender.url).hostname || origin;
      } catch (e) {
        host = origin || "unknown";
      }

      chrome.storage.sync.get({ whitelist: [], logs: [] }, (data) => {
        const whitelist = Array.isArray(data.whitelist) ? data.whitelist : [];
        if (whitelist.includes(host)) return;

        const now = new Date().toISOString();
        const newLog = {
          reportType: "ClickFix Threat Log",
          time: now,
          url: sender?.url || origin || "unknown",
          sourceHost: host,
          detectedClipboardPayload: msg.payload || ""
        };

        const logs = Array.isArray(data.logs) ? data.logs : [];
        const updatedLogs = [newLog, ...logs].slice(0, 50);
        chrome.storage.sync.set({ logs: updatedLogs }, () => {
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
    })();
  }

  if (msg && msg.type === "downloadReport") {
    try {
      chrome.downloads.download({
        url: msg.url,
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

