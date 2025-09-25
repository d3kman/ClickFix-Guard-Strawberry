// popup.js
document.addEventListener("DOMContentLoaded", init);

function init() {
  try {
    document.getElementById("saveKeywords").addEventListener("click", saveKeywords);
    document.getElementById("resetKeywords").addEventListener("click", resetKeywords);
    document.getElementById("clearLogs").addEventListener("click", clearLogs);
    document.getElementById("refresh").addEventListener("click", renderAll);
    document.getElementById("addWhitelistBtn").addEventListener("click", addWhitelist);
    document.getElementById("clearWhitelist").addEventListener("click", clearWhitelist);

    renderAll();
  } catch (err) {
    console.warn("Clipboard Guard popup init error:", err);
  }
}

function renderAll() {
  chrome.storage.local.get({
    keywords: [],
    logs: [],
    whitelist: []
  }, (data) => {
    try {
      // keywords
      const ta = document.getElementById("keywordsArea");
      ta.value = (data.keywords && data.keywords.length) ? data.keywords.join("\n") : "";

      // logs
      const logsContainer = document.getElementById("logsContainer");
      logsContainer.innerHTML = "";
      if (!data.logs || data.logs.length === 0) {
        logsContainer.textContent = "No suspicious events logged.";
      } else {
        data.logs.forEach((log, index) => {
          const origin = log.sourceHost || log.origin || "unknown";
          const text = log.detectedClipboardPayload || log.text || "";
          const time = log.timeUTC || new Date().toISOString();

          const div = document.createElement("div");
          div.className = "log";
          div.innerHTML = `
            <div class="origin">${escapeHtml(origin)}</div>
            <div class="small">${escapeHtml(truncate(text, 300))}</div>
            <div class="time">${new Date(time).toLocaleString()}</div>
            <div style="margin-top:6px;">
              <button data-index="${index}" class="dlBtn">Download Report</button>
            </div>`;
          logsContainer.appendChild(div);
        });

        logsContainer.querySelectorAll(".dlBtn").forEach(btn => {
          btn.addEventListener("click", (e) => {
            try {
              const idx = e.target.getAttribute("data-index");
              chrome.storage.local.get({ logs: [] }, (d) => {
                try {
                  const entry = d.logs[idx];
                  if (entry) {
                    chrome.runtime.sendMessage({
                      type: "downloadReport",
                      data: entry,
                      filename: `ClickFix-ThreatReport-${Date.now()}.json`
                    });
                  }
                } catch (err) {
                  console.warn("Clipboard Guard popup log download error:", err);
                }
              });
            } catch (err) {
              console.warn("Clipboard Guard popup dlBtn error:", err);
            }
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
            try {
              const host = e.target.getAttribute("data-host");
              removeWhitelist(host);
            } catch (err) {
              console.warn("Clipboard Guard popup removeWhitelist btn error:", err);
            }
          });
        });
      }
    } catch (err) {
      console.warn("Clipboard Guard popup renderAll error:", err);
    }
  });
}

function saveKeywords() {
  try {
    const raw = document.getElementById("keywordsArea").value;
    const arr = raw.split("\n").map(s => s.trim()).filter(Boolean);
    chrome.storage.local.set({ keywords: arr }, () => {
      alert("Custom keywords saved.");
    });
  } catch (err) {
    console.warn("Clipboard Guard saveKeywords error:", err);
  }
}

function resetKeywords() {
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
  try {
    if (typeof arg === "string" && arg.includes(".")) {
      const host = arg;
      chrome.storage.local.get({ whitelist: [] }, data => {
        try {
          const list = data.whitelist || [];
          if (!list.includes(host)) {
            list.push(host);
            chrome.storage.local.set({ whitelist: list }, () => {
              renderAll();
            });
          } else {
            alert(`${host} is already whitelisted.`);
          }
        } catch (err) {
          console.warn("Clipboard Guard addWhitelist error:", err);
        }
      });
    } else {
      const input = document.getElementById("addWhitelistInput").value.trim();
      if (!input) return alert("Enter a hostname (e.g. example.com).");
      addWhitelist(input);
      document.getElementById("addWhitelistInput").value = "";
    }
  } catch (err) {
    console.warn("Clipboard Guard addWhitelist wrapper error:", err);
  }
}

function removeWhitelist(host) {
  chrome.storage.local.get({ whitelist: [] }, data => {
    try {
      let list = data.whitelist || [];
      list = list.filter(h => h !== host);
      chrome.storage.local.set({ whitelist: list }, () => {
        renderAll();
      });
    } catch (err) {
      console.warn("Clipboard Guard removeWhitelist error:", err);
    }
  });
}

function clearWhitelist() {
  if (!confirm("Clear all whitelist entries?")) return;
  chrome.storage.local.set({ whitelist: [] }, () => {
    renderAll();
  });
}

// helpers
function truncate(s, n) {
  if (!s) return "";
  return String(s).length > n ? s.slice(0, n - 1) + "…" : s;
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


// --- Safe wrapper for sendMessage ---
function safeSendMessage(msg) {
  try {
    chrome.runtime.sendMessage(msg);
  } catch (err) {
    console.warn("Popup safeSendMessage error:", err, msg);
  }
}

