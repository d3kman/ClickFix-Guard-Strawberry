// content_script.js
// Injects page-context hooks to intercept clipboard writes,
// detects suspicious payloads, and alerts the user.

(function () {
  // Inject page hook
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("pageHook.js");
  (document.head || document.documentElement).appendChild(script);
  script.remove();

  window.addEventListener("message", (evt) => {
    if (!evt.data || !evt.data.__clipboardGuardFromPage) return;
    const payload = evt.data.data || {};
    const text = typeof payload.text === "string" ? payload.text.trim() : "";
    forwardCandidate({ method: payload.type || "unknown", text });
  });

  const MALICIOUS_RE = /\b(powershell|invoke-webrequest|start-process|mshta(\.exe)?|cmd(\.exe)?|wget|curl|bitsadmin|certutil|rundll32|iex|invoke-expression|downloadstring)\b/i;
  const POWERSHELL_FLAGS_RE = /-(?:noprofile|executionpolicy|encodedcommand|enc|command)\b/i;
  const HTA_APPDATA_RE = /(%appdata%|\\appdata\\|%APPDATA%|\.hta)/i;
  const URL_THEN_CMD_RE = /https?:\/\/\S+.*(?:;|&&|\||`|\$\(.*\)|start-process)\b/i;

  const HARDCODED_KEYWORDS = [
    "verification","id","#","powershell","mshta.exe",
    "-noprofile","-executionpolicy","-enc","invoke-expression","iex"
  ];

  const TOKENS = [
    "powershell","invoke-webrequest","start-process","mshta","cmd",
    "wget","curl","bitsadmin","certutil","rundll32","iex","invoke-expression"
  ];

  function forwardCandidate({ method, text }) {
    try {
      const safeText = typeof text === "string" ? text : "";
      if (!safeText) return;

      const normalized = safeText.replace(/[\u2011\u2013\u2014]/g, "-");
      const s = normalized.toLowerCase();

      chrome.storage.sync.get({ whitelist: [], keywords: [] }, (cfg) => {
        const host = location.hostname || location.host || location.href || "unknown";
        if (cfg.whitelist && cfg.whitelist.includes(host)) return;

        if (
          MALICIOUS_RE.test(s) ||
          POWERSHELL_FLAGS_RE.test(s) ||
          HTA_APPDATA_RE.test(s) ||
          URL_THEN_CMD_RE.test(s)
        ) {
          handleSuspicious(safeText, host);
          return;
        }

        const matches = TOKENS.filter(t => s.includes(t));
        if (matches.length >= 2) {
          handleSuspicious(safeText, host);
          return;
        }

        if (HARDCODED_KEYWORDS.some(k => s.includes(k.toLowerCase()))) {
          handleSuspicious(safeText, host);
          return;
        }

        if (Array.isArray(cfg.keywords) && cfg.keywords.some(k => k && s.includes(String(k).toLowerCase()))) {
          handleSuspicious(safeText, host);
          return;
        }
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
    showCenterAlert(text, host); // always show modal
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
            This site may attempt to inject malicious clipboard payloads.
          </div>
          <div class="cg-confirm-btns">
            <button class="cg-btn-yes">Yes, continue</button>
            <button class="cg-btn-no">Cancel</button>
          </div>
        </div>`;
      document.body.appendChild(confirmBox);

      confirmBox.querySelector(".cg-btn-yes").onclick = () => {
        chrome.storage.sync.get({ whitelist: [] }, (d) => {
          const wl = d.whitelist || [];
          if (!wl.includes(host)) {
            wl.push(host);
            chrome.storage.sync.set({ whitelist: wl }, () => {
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
    document.body.appendChild(overlay);

    box.querySelector(".cg-btn-no").addEventListener("click", () => overlay.remove());

    box.querySelector(".cg-btn-download").addEventListener("click", () => {
      const nowIso = new Date().toISOString();
      const pageUrl = location.href;
      const ua = navigator.userAgent;
      const platform = navigator.platform;

      const report = {
        reportType: "ClickFix Threat Report",
        timestamp: nowIso,
        url: pageUrl,
        sourceHost: origin || "unknown",
        detectedClipboardPayload: payload,
        environment: { userAgent: ua, platform }
      };

      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const downloadUrl = URL.createObjectURL(blob);

      chrome.runtime.sendMessage({
        type: "downloadReport",
        url: downloadUrl,
        filename: "ClickFix-ThreatReport.json"
      });

      overlay.remove();
    });
  }
})();
