// background.js
// Handles suspiciousClipboard messages, notifications, log storage and default settings.

const MAPPING_WEBHOOK_KEY = "mappingWebhookUrl"; // set this in storage.sync for your webhook URL

// helper: generate a random 12-character ID (alphanumeric, lowercase)
function generateShortId(len = 12) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < len; i++) {
    out += alphabet[arr[i] % alphabet.length];
  }
  return out;
}

// Format CET/CEST date/time for logs (Stockholm/Paris)
function getCETTimeString() {
  try {
    const now = new Date();
    return new Intl.DateTimeFormat("sv-SE", {
      timeZone: "Europe/Stockholm",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }).format(now);
  } catch (e) {
    return new Date().toISOString();
  }
}

chrome.runtime.onInstalled.addListener(() => {
  // Ensure defaults in storage.sync
  chrome.storage.sync.get(null, (items) => {
    const defaults = {
      whitelist: [],
      logs: [],
      keywords: []
      // mappingWebhookUrl is optional - set via admin
    };
    const toSet = {};
    for (const k in defaults) {
      if (!(k in items)) toSet[k] = defaults[k];
    }
    // ensure we have instanceId persisted in sync (per user)
    if (!items.instanceId) {
      toSet.instanceId = generateShortId(12); // 12 char id
      toSet.instanceCreated = new Date().toISOString();
    }
    if (Object.keys(toSet).length > 0) {
      chrome.storage.sync.set(toSet, () => {
        // If we just created instanceId, try to collect identity + post mapping
        if (toSet.instanceId) {
          collectIdentityAndPostMapping(toSet.instanceId);
        }
      });
    } else {
      // instanceId might already exist; still attempt to collect identity if email missing
      chrome.storage.sync.get(["instanceId", "userEmail", "userId"], (s) => {
        if (s.instanceId && !s.userEmail) collectIdentityAndPostMapping(s.instanceId);
      });
    }
  });
});

// Collect identity (if available on managed Chrome) and optionally POST mapping
function collectIdentityAndPostMapping(instanceId) {
  try {
    chrome.identity.getProfileUserInfo((info) => {
      const email = info && info.email ? info.email : null;
      const userId = info && info.id ? info.id : null;
      chrome.storage.sync.set({ userEmail: email, userId: userId }, () => {
        // If a mapping webhook is configured, POST the mapping (server should be internal and secure)
        chrome.storage.sync.get([MAPPING_WEBHOOK_KEY], (r) => {
          const url = r && r[MAPPING_WEBHOOK_KEY];
          if (url) {
            const payload = {
              instanceId,
              email,
              userId,
              timestamp: new Date().toISOString()
            };
            // POST mapping - best effort, do not block startup
            fetch(url, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload)
            }).then(res => {
              if (!res.ok) console.warn("Mapping webhook returned non-OK:", res.status);
            }).catch(err => {
              console.error("Mapping webhook error:", err);
            });
          }
        });
      });
    });
  } catch (e) {
    console.error("collectIdentityAndPostMapping error:", e);
  }
}

chrome.runtime.onMessage.addListener((msg, sender) => {
  // suspiciousClipboard from content script -> log + notify
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

      // read instanceId and store a richer log
      chrome.storage.sync.get({ whitelist: [], logs: [], instanceId: null }, (data) => {
        const whitelist = Array.isArray(data.whitelist) ? data.whitelist : [];
        if (whitelist.includes(host)) return;

        const instanceId = data.instanceId || "unknown";
        const now = getCETTimeString();

        const newLog = {
          reportType: "ClickFix Threat Log",
          time: now,
          url: sender?.url || origin || "unknown",
          sourceHost: host,
          detectedClipboardPayload: msg.payload || "",
          instanceId,
          environment: {
            userAgent: navigator.userAgent,
            platform: navigator.platform
          }
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

  // downloadReport -> start download (URL will be a blob: URL created by content script)
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
      console.error("Download initiation error:", e);
    }
  }

  // (you can add other message handlers here)
});

// small helper
function truncate(s, n) {
  if (!s) return "";
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}
