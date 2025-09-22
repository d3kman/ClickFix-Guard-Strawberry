// background.js
chrome.runtime.onInstalled.addListener(() => {
  // Initialize defaults
  chrome.storage.local.get(null, (items) => {
    const defaults = {
      whitelist: [],
      logs: [],
      keywords: [],
      onScreenAlerts: true,
      userEmail: "unknown@example.com" // fallback
    };

    const toSet = {};
    for (const k in defaults) {
      if (!(k in items)) toSet[k] = defaults[k];
    }

    // Try to fetch signed-in Chrome/Workspace email
    chrome.identity.getProfileUserInfo((info) => {
      if (info && info.email) {
        toSet.userEmail = info.email;
      }
      if (Object.keys(toSet).length > 0) {
        chrome.storage.local.set(toSet);
      }
    });
  });
});


chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg && msg.type === "suspiciousClipboard") {
    const origin = msg.origin || (sender && sender.url) || "unknown";

    // Normalize origin to hostname if possible
    let host = origin;
    try {
      if (origin && origin.includes("://")) {
        host = new URL(origin).hostname;
      } else if (sender?.url) {
        host = new URL(sender.url).hostname;
      }
    } catch (e) {
      host = origin; // fallback
    }

    chrome.storage.local.get({ whitelist: [], logs: [] }, (data) => {
      if (data.whitelist.includes(host)) {
        // whitelisted - ignore
        return;
      }

      const newLog = {
        text: msg.payload,
        origin: host,
        time: new Date().toISOString()
      };

      const updatedLogs = [newLog, ...(data.logs || [])].slice(0, 50);
      chrome.storage.local.set({ logs: updatedLogs });

      // Desktop notification
      chrome.notifications.create({
        type: "basic",
        iconUrl: "warning.png",
        title: "⚠ Suspicious Clipboard Activity",
        message: `From: ${host}\n\n${truncate(msg.payload, 200)}`
      });
    });
  }
});

// small helper
function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
