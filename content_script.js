// content_script.js
// Injects page-context hooks to intercept clipboard writes,
// detects suspicious payloads, and alerts the user.
// Runs in all frames (all_frames:true, match_about_blank:true).

(function () {
  // --- Inject a hook script into the page context (pageHook.js is bundled) ---
  try {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("pageHook.js");
    (document.head || document.documentElement).appendChild(script);
    script.remove();
  } catch (err) {
    console.warn("Clipboard Guard failed to inject pageHook:", err);
  }

  // --- Listen for events posted from page ---
  window.addEventListener("message", (evt) => {
    try {
      if (!evt.data || !evt.data.__clipboardGuardFromPage) return;
      const payload = evt.data.data || {};
      const text = String(payload.text || "").trim();
      forwardCandidate({ method: payload.type || "unknown", text });
    } catch (err) {
      console.warn("Clipboard Guard message handler error:", err);
    }
  });

  // --- Detection regexes & hardcoded heuristics ---
  const MALICIOUS_RE = /(powershell|invoke-webrequest|start-process|mshta(\.exe)?|cmd(\.exe)?|wget|curl|bitsadmin|certutil|rundll32|iex|invoke-expression|downloadstring)/i;
  const POWERSHELL_FLAGS_RE = /-(?:noprofile|executionpolicy|encodedcommand|enc|command)\b/i;
  const HTA_APPDATA_RE = /(%appdata%|\\appdata\\|%APPDATA%|\.hta)/i;
  const URL_THEN_CMD_RE = /https?:\/\/\S+.*(?:;|&&|\||\`|\$\(.*\)|start-process)\b/i;
  const BASH_EXEC_RE = /\/bin\/bash\s+-c\b/i;
  const CURL_FLAGS_RE = /\bcurl\b.*\s-(fsSL|sS|o-)\b/i;
  const CURL_UA_RE = /\bcurl\b.*\s-A\s+['"]?Mac\s+OS\s+X/i;

  const HARDCODED_KEYWORDS = [
    "verification","id","#","powershell","mshta.exe",
    "-noprofile","-executionpolicy","-enc","invoke-expression","iex"
  ];

  const TOKENS = [
    "powershell","invoke-webrequest","start-process","mshta","cmd",
    "wget","curl","bitsadmin","certutil","rundll32","iex","invoke-expression"
  ];

  // --- Forward and detect candidates ---
  function forwardCandidate({ method, text }) {
    try {
      if (!text) {
        safeSendMessage({
          type: "clipboardCandidateRaw",
          origin: safeOrigin(),
          method,
          text: ""
        });
        return;
      }

      const normalized = text.replace(/[\u2011\u2013\u2014]/g, "-");
      const s = normalized.toLowerCase();

      chrome.storage.local.get({ whitelist: [], keywords: [] }, (cfg) => {
        try {
          const host = safeOrigin();
          if (Array.isArray(cfg.whitelist) && cfg.whitelist.includes(host)) return;

          if (
            MALICIOUS_RE.test(s) ||
            POWERSHELL_FLAGS_RE.test(s) ||
            HTA_APPDATA_RE.test(s) ||
            URL_THEN_CMD_RE.test(s) ||
            BASH_EXEC_RE.test(s) ||
            CURL_FLAGS_RE.test(s)
          ) {
            handleSuspicious(text, host);
            return;
          }

          const matches = TOKENS.filter(t => s.includes(t));
          if (matches.length >= 2) {
            handleSuspicious(text, host);
            return;
          }

          if (HARDCODED_KEYWORDS.some(k => k && s.includes(k.toLowerCase()))) {
            handleSuspicious(text, host);
            return;
          }

          if (Array.isArray(cfg.keywords) && cfg.keywords.some(k => k && s.includes(String(k).toLowerCase()))) {
            handleSuspicious(text, host);
            return;
          }
        } catch (err) {
          console.warn("Clipboard Guard forwardCandidate cfg error:", err);
        }
      });

      safeSendMessage({
        type: "clipboardCandidateRaw",
        origin: safeOrigin(),
        method,
        text
      });
    } catch (e) {
      console.warn("Clipboard Guard forwardCandidate error:", e);
    }
  }

  function handleSuspicious(text, host) {
    safeSendMessage({
      type: "suspiciousClipboard",
      payload: text,
      origin: host
    });
    showCenterAlert(text, host);
  }

  // --- Helpers ---
  function safeSendMessage(msg) {
    try {
      chrome.runtime.sendMessage(msg);
    } catch (err) {
      if (err?.message?.includes("context invalidated")) {
        console.debug("Clipboard Guard message skipped (context invalidated).", msg);
      } else {
        console.warn("Clipboard Guard safeSendMessage error:", err, msg);
      }
    }
  }

  function safeOrigin() {
    try {
      return location.hostname || location.host || location.href || "unknown";
    } catch {
      return "unknown";
    }
  }

  function injectModalCss() {
    if (document.getElementById("clipboard-guard-style")) return;
    const link = document.createElement("link");
    link.id = "clipboard-guard-style";
    link.rel = "stylesheet";
    link.href = chrome.runtime.getURL("modal.css");
    document.head.appendChild(link);
  }

  function showCenterAlert(text, host) {
    if (document.getElementById("clipboard-guard-alert")) return;
    injectModalCss();

    const overlay = document.createElement("div");
    overlay.id = "clipboard-guard-alert";
    overlay.style.zIndex = "2147483647"; // max safe z-index

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

    const reportBtn = document.createElement("button");
    reportBtn.className = "cg-btn-report";
    reportBtn.textContent = "Report to Security Team";
    reportBtn.onclick = () => {
      showReportModal(text, host);
    };
    btnRow.appendChild(reportBtn);

    const spacer = document.createElement("div");
    spacer.style.flex = "1";
    btnRow.appendChild(spacer);

    const whitelistBtn = document.createElement("button");
    whitelistBtn.className = "cg-btn-whitelist";
    whitelistBtn.textContent = "Whitelist this site";
    whitelistBtn.onclick = () => {
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

      const parentOverlay = document.getElementById("clipboard-guard-alert") || document.body;
      parentOverlay.appendChild(confirmBox);

      confirmBox.querySelector(".cg-btn-yes").onclick = () => {
        chrome.storage.local.get({ whitelist: [] }, (d) => {
          const wl = Array.isArray(d.whitelist) ? d.whitelist : [];
          if (!wl.includes(host)) {
            wl.push(host);
            chrome.storage.local.set({ whitelist: wl }, () => {
              whitelistBtn.textContent = "Whitelisted ✓";
              whitelistBtn.disabled = true;
            });
          }
        });
        confirmBox.remove();
        overlay.remove();
      };

      confirmBox.querySelector(".cg-btn-no").onclick = () => confirmBox.remove();
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
      if (e.key === "Escape" && document.body.contains(overlay)) overlay.remove();
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

  function showReportModal(payload, origin) {
    const overlay = document.createElement("div");
    overlay.className = "cg-confirm-overlay";
    overlay.style.zIndex = "2147483647";

    const box = document.createElement("div");
    box.className = "cg-confirm-box";
    box.innerHTML = `
      <div class="cg-confirm-title">Report to Security Team</div>
      <div class="cg-info-text">
        Looks like you have encountered a potential malicious website.<br><br>
        Please, press the <b>"Download Report"</b> button and send it to 
        <b>security@strawberry.no</b>.<br><br>
        This will help both you and your coworkers all over the organization 
        to remain cyber safe.<br><br>
        Best Regards<br>
        Strawberry Security Team
      </div>
      <div class="cg-confirm-btns">
        <button class="cg-btn-download">Download Report</button>
        <button class="cg-btn-no">Close</button>
      </div>
    `;

    overlay.appendChild(box);

    const parentOverlay = document.getElementById("clipboard-guard-alert") || document.body;
    parentOverlay.appendChild(overlay);

    box.querySelector(".cg-btn-no").addEventListener("click", () => {
      overlay.remove();
    });

    box.querySelector(".cg-btn-download").addEventListener("click", () => {
      const report = {
        reportType: "ClickFix Threat Report",
        timeUTC: new Date().toISOString(),
        timeLocal: new Date().toLocaleString("sv-SE", { timeZone: "Europe/Stockholm" }),
        url: location.href,
        sourceHost: origin || "unknown",
        detectedClipboardPayload: payload,
        environment: {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language
        }
      };

      safeSendMessage({
        type: "downloadReport",
        data: report,
        filename: `ClickFix-ThreatReport-${Date.now()}.json`
      });

      overlay.remove();
    });
  }

})();




