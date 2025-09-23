// pageHook.js
// Hooks into clipboard operations in page context.

(function () {
  function interceptClipboardWrite(type, text) {
    window.postMessage(
      { __clipboardGuardFromPage: true, data: { type, text } },
      "*"
    );
  }

  const origExecCommand = document.execCommand;
  document.execCommand = function (cmd, ui, value) {
    if (cmd && cmd.toLowerCase() === "copy") {
      try {
        const selection = document.getSelection().toString();
        interceptClipboardWrite("execCommand", selection);
      } catch (e) {}
    }
    return origExecCommand.apply(this, arguments);
  };

  if (navigator.clipboard) {
    const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = async function (text) {
      try {
        interceptClipboardWrite("writeText", text);
      } catch (e) {}
      return origWriteText(text);
    };
  }
})();

