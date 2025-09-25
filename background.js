// background.js
// Handles suspiciousClipboard messages, notifications, log storage and default settings.

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(null, (items) => {
    try {
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
    } catch (err) {
      console.warn("Clipboard Guard init error:", err);
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender) => {
  try {
    if (msg?.type === "suspiciousClipboard") {
      handleSuspiciousClipboard(msg, sender);
    }

    if (msg?.type === "downloadReport") {
      handleDownloadReport(msg);
    }
  } catch (err) {
    console.warn("Clipboard Guard background error:", err, msg);
  }
});

function handleSuspiciousClipboard(msg, sender) {
  const origin = msg.origin || sender?.url || "unknown";

  let host = origin;
  try {
    if (origin.includes("://")) {
      host = new URL(origin).hostname;
    } else if (sender?.url) {
      host = new URL(sender.url).hostname;
    }
  } catch {
    host = origin || "unknown";
  }

  chrome.storage.local.get({ whitelist: [], logs: [] }, (data) => {
    try {
      if (Array.isArray(data.whitelist) && data.whitelist.includes(host)) return;

      const now = new Date();
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
          console.debug("Clipboard Guard notification skipped:", e);
        }
      });
    } catch (err) {
      console.warn("Clipboard Guard handleSuspiciousClipboard error:", err);
    }
  });
}

function handleDownloadReport(msg) {
  try {
    const reportData = msg.data || msg;
    const json = JSON.stringify(reportData, null, 2);
    const blobUrl = "data:application/json;base64," + btoa(unescape(encodeURIComponent(json)));

    const filename = msg.filename || `ClickFix-ThreatReport-${Date.now()}.json`;

    chrome.downloads.download({
      url: blobUrl,
      filename,
      saveAs: true
    });
  } catch (e) {
    console.warn("Clipboard Guard downloadReport error:", e);
  }
}

function truncate(s, n) {
  if (!s) return "";
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

