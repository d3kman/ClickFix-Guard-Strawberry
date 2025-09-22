// content_script.js
// Injects page-context hooks to intercept clipboard writes,
// detects suspicious payloads, and alerts the user.
// Runs in all frames (all_frames:true, match_about_blank:true).

(function () {
  // --- Inject a hook script into the page context ---
  const pageHookCode = `(() => {
    const origWrite = navigator.clipboard?.write?.bind(navigator.clipboard) || null;
    const origWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard) || null;
    const origExec = document.execCommand?.bind(document) || null;

    function notify(obj) {
      try {
        window.postMessage({ __clipboardGuardFromPage: true, data: obj }, "*");
      } catch (_) {}
    }

    if (origWrite) {
      navigator.clipboard.write = async function (items) {
        try {
          let text = "";
          if (Array.isArray(items)) {
            for (const it of items) {
              try {
                if (it?.getType) {
                  const blob = await it.getType("text/plain").catch(() => null);
                  if (blob) text = text || await blob.text().catch(() => "");
                }
              } catch (_) {}
            }
          }
          notify({ type: "write", text });
        } catch (_) {}
        return origWrite.apply(this, arguments);
      };
    }

    if (origWriteText) {
      navigator.clipboard.writeText = async function (text) {
        try { notify({ type: "writeText", text: String(text) }); } catch(_) {}
        return origWriteText.apply(this, arguments);
      };
    }

    if (origExec) {
      document.execCommand = function (cmd, ...args) {
        try {
          if (String(cmd).toLowerCase() === "copy") {
            let captured = "";
            try {
              const sel = document.getSelection();
              if (sel?.toString()) captured = sel.toString();
              else if (document.activeElement) {
                const ae = document.activeElement;
                if (ae.value) captured = ae.value;
                else if (ae.innerText) captured = ae.innerText;
              }
            } catch (_) {}
            notify({ type: "execCopy", text: String(captured) });
          }
        } catch (_) {}
        return origExec.apply(this, [cmd, ...args]);
      };
    }

    try {
      document.addEventListener("copy", (ev) => {
        try {
          let text = "";
          if (ev?.clipboardData?.getData) {
            text = ev.clipboardData.getData("text/plain") || "";
          } else {
            const sel = document.getSelection();
            if (sel) text = sel.toString();
          }
          notify({ type: "copyEvent", text: String(text) });
        } catch (_) {}
      }, true);
    } catch (_) {}

    // NEW: Hook DataTransfer.prototype.setData (clipboardData.setData)
    try {
      const origSetData = DataTransfer.prototype.setData;
      DataTransfer.prototype.setData = function(format, data) {
        try {
          if (format && format.toLowerCase() === "text/plain" && data) {
            notify({ type: "setData", text: String(data) });
          }
        } catch (_) {}
        return origSetData.apply(this, arguments);
      };
    } catch (_) {}

    window.__clipboardGuardInjected = true;
  })();`;

  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("pageHook.js");
  (document.head || document.documentElement).appendChild(script);
  script.remove();


  // --- Listen for events posted from page ---
  window.addEventListener("message", (evt) => {
    if (!evt.data || !evt.data.__clipboardGuardFromPage) return;
    const payload = evt.data.data || {};
    const text = String(payload.text || "").trim();
    forwardCandidate({ method: payload.type || "unknown", text });
  });

  // --- Detection regexes & hardcoded heuristics ---
  const MALICIOUS_RE = /\b(powershell|invoke-webrequest|start-process|mshta(\.exe)?|cmd(\.exe)?|wget|curl|bitsadmin|certutil|rundll32|iex|invoke-expression|downloadstring)\b/i;
  const POWERSHELL_FLAGS_RE = /-(?:noprofile|executionpolicy|encodedcommand|enc|command)\b/i;
  const HTA_APPDATA_RE = /(%appdata%|\\appdata\\|%APPDATA%|\.hta)/i;
  const URL_THEN_CMD_RE = /https?:\/\/\S+.*(?:;|&&|\||\`|\$\(.*\)|start-process)\b/i;

  // Hardcoded suspicious terms
  const HARDCODED_KEYWORDS = [
    "verification",
    "id",
    "#",
    "powershell",
    "mshta.exe",
    "-noprofile",
    "-executionpolicy",
    "-enc",
    "invoke-expression",
    "iex"
  ];

  // Suspicious token list for chaining detection
  const TOKENS = [
    "powershell",
    "invoke-webrequest",
    "start-process",
    "mshta",
    "cmd",
    "wget",
    "curl",
    "bitsadmin",
    "certutil",
    "rundll32",
    "iex",
    "invoke-expression"
  ];

  function forwardCandidate({ method, text }) {
    try {
      if (!text) {
        // Still forward empty events for logging
        chrome.runtime.sendMessage({
          type: "clipboardCandidateRaw",
          origin: location.hostname || location.host || location.href,
          method,
          text: ""
        });
        return;
      }

      const normalized = text.replace(/[\u2011\u2013\u2014]/g, "-");
      const s = normalized.toLowerCase();

      chrome.storage.local.get({ whitelist: [], keywords: [], onScreenAlerts: true }, (cfg) => {
        const host = location.hostname || location.host || "unknown";
        if (cfg.whitelist.includes(host)) return;

        // Apply detection heuristics
        if (
          MALICIOUS_RE.test(s) ||
          POWERSHELL_FLAGS_RE.test(s) ||
          HTA_APPDATA_RE.test(s) ||
          URL_THEN_CMD_RE.test(s)
        ) {
          handleSuspicious(text, host);
          return;
        }

        // Suspicious token chaining: 2+ dangerous tokens together
        const matches = TOKENS.filter(t => s.includes(t));
        if (matches.length >= 2) {
          handleSuspicious(text, host);
          return;
        }

        // Hardcoded suspicious terms
        if (HARDCODED_KEYWORDS.some(k => k && s.includes(k.toLowerCase()))) {
          handleSuspicious(text, host);
          return;
        }

        // User-provided keywords
        if (Array.isArray(cfg.keywords) && cfg.keywords.some(k => k && s.includes(String(k).toLowerCase()))) {
          handleSuspicious(text, host);
          return;
        }
      });

      // Always forward raw candidate for background logging
      chrome.runtime.sendMessage({
        type: "clipboardCandidateRaw",
        origin: location.hostname || location.host || location.href,
        method,
        text
      });
    } catch (e) {
      console.error("Clipboard Guard forwardCandidate error", e);
    }
  }

  function handleSuspicious(text, host) {
    chrome.runtime.sendMessage({
      type: "suspiciousClipboard",
      payload: text,
      origin: host
    });

    chrome.storage.local.get({ onScreenAlerts: true }, (cfg) => {
      if (cfg.onScreenAlerts) showCenterAlert(text, host);
    });
  }

  // --- Inject CSS for modal once ---
  function injectModalCss() {
    if (document.getElementById("clipboard-guard-style")) return;
    const link = document.createElement("link");
    link.id = "clipboard-guard-style";
    link.rel = "stylesheet";
    link.href = chrome.runtime.getURL("modal.css");
    document.head.appendChild(link);
  }

  // --- On-screen alert modal (uses modal.css) ---
  function showCenterAlert(text, host) {
    if (document.getElementById("clipboard-guard-alert")) return;

    injectModalCss();

    const overlay = document.createElement("div");
    overlay.id = "clipboard-guard-alert";

    const box = document.createElement("div");
    box.className = "cg-box";

    const title = document.createElement("div");
    title.className = "cg-title";
    title.textContent = "⚠ Suspicious Clipboard Detected";
    box.appendChild(title);

    const info = document.createElement("div");
    info.className = "cg-info";
info.innerHTML = `
  <div class="cg-source"><strong>Source:</strong> ${escapeHtml(host)}</div>
  <div><strong>Detected payload:</strong></div>
  <pre>${escapeHtml(text)}</pre>`;
    box.appendChild(info);

    const btnRow = document.createElement("div");
    btnRow.className = "cg-btn-row";

    const whitelistBtn = document.createElement("button");
    whitelistBtn.className = "cg-btn-whitelist";
    whitelistBtn.textContent = "Whitelist this site";
    whitelistBtn.onclick = () => {
    // Prevent duplicates
      if (document.querySelector(".cg-confirm-overlay")) return;

      const confirmBox = document.createElement("div");
      confirmBox.className = "cg-confirm-overlay";

        confirmBox.innerHTML = `
          <div class="cg-confirm-box">
              <div class="cg-confirm-title">⚠️ Confirm Whitelisting</div>
              <div class="cg-confirm-text">
                  Do you really want to whitelist <strong>${escapeHtml(host)}</strong>?<br>
                  This site may attempt to inject malicious clipboard payloads that could infect your computer.
              </div>
              <div class="cg-confirm-btns">
              <button class="cg-btn-yes">Yes, continue</button>
              <button class="cg-btn-no">Cancel</button>
              </div>
          </div>`;

        document.body.appendChild(confirmBox);

          // Yes → whitelist + close both
        confirmBox.querySelector(".cg-btn-yes").onclick = () => {
        chrome.storage.local.get({ whitelist: [] }, (d) => {
          const wl = d.whitelist || [];
          if (!wl.includes(host)) {
        wl.push(host);
        chrome.storage.local.set({ whitelist: wl }, () => {
          whitelistBtn.textContent = "Whitelisted ✓";
          whitelistBtn.disabled = true;
        });
      }
    });

    confirmBox.remove();
    const mainAlert = document.querySelector(".cg-center-overlay");
    if (mainAlert) mainAlert.remove();
  };

  // No → just close confirm, keep warning open
  confirmBox.querySelector(".cg-btn-no").onclick = () => {
    confirmBox.remove();
  };
};



    const dismiss = document.createElement("button");
    dismiss.className = "cg-btn-dismiss";
    dismiss.textContent = "Dismiss";
    dismiss.onclick = () => overlay.remove();

    btnRow.appendChild(whitelistBtn);
    btnRow.appendChild(dismiss);
    box.appendChild(btnRow);

    overlay.appendChild(box);
    document.documentElement.appendChild(overlay);

    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") overlay.remove();
    }, { once: true });
  }

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }
})();
