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
    const origin = msg.origin || (sender && sender.url) || "unknown";

    let host = origin || "unknown";
    try {
      if (origin && origin.includes("://")) {
        host = new URL(origin).hostname || "unknown";
      } else if (sender?.url) {
        host = new URL(sender.url).hostname || "unknown";
      }
    } catch (e) {
      host = origin || "unknown";
    }

    chrome.storage.local.get({ whitelist: [], logs: [] }, (data) => {
      const whitelist = Array.isArray(data.whitelist) ? data.whitelist : [];
      if (whitelist.includes(host)) return;

      const newLog = {
        reportType: "ClickFix Threat Log",
        time: new Date().toISOString(),
        url: sender?.url || origin || "unknown",
        sourceHost: host,
        detectedClipboardPayload: msg.payload || "",
        environment: {
          userAgent: navigator.userAgent,
          platform: navigator.platform
        }
      };

      const logs = Array.isArray(data.logs) ? data.logs : [];
      const updatedLogs = [newLog, ...logs].slice(0, 50);

      chrome.storage.local.set({ logs: updatedLogs });

      try {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "⚠ Suspicious Clipboard Activity",
          message: `From: ${host}\n\n${truncate(msg.payload, 200)}`
        });
      } catch (e) {
        console.error("Notification error:", e);
      }
    });
  }

  // 🔹 Handle report download request
  if (msg && msg.type === "downloadReport") {
    try {
      chrome.downloads.download(
        {
          url: msg.url,
          filename: msg.filename || "ClickFix-ThreatReport.json",
          saveAs: true
        },
        (downloadId) => {
          if (chrome.runtime.lastError) {
            console.error("Download failed:", chrome.runtime.lastError.message);
          } else {
            console.log("Download started, ID:", downloadId);
          }
        }
      );
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
