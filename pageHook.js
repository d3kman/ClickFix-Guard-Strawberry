(() => {
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

  // Hook DataTransfer.prototype.setData
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
})();
