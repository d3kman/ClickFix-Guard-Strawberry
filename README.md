
# 🚨 ClickFix Clipboard Guard

ClickFix Clipboard Guard is a lightweight browser extension that protects you from **clipboard hijacking attacks** often used in ClickFix scams and other malware tricks.

These scams make you click on fake “verification” checkboxes or buttons and secretly copy **malicious commands** (like PowerShell payloads) to your clipboard. If you paste them into a terminal, your system can be compromised.

This extension **monitors clipboard writes** in real time and alerts you when something looks suspicious.

---

## ✨ Features

### 🔎 Clipboard Monitoring  
Detects when a site tries to write to your clipboard — even hidden or background attempts.

### ⚠ Suspicious Content Detection  
Built-in **hardcoded detection rules** catch high-risk payloads such as:  

- ClickFix-style bait text: `Verification`, `ID`, `#`  
- PowerShell & flags: `powershell`, `-NoProfile`, `-ExecutionPolicy`, `-enc`, `Invoke-Expression`, `IEX`  
- Windows LOLBins: `mshta.exe`, `certutil`, `rundll32`, `wget`, `curl`, etc.  
- Dangerous chains: commands after a URL (e.g. `https://... && powershell`)  

👉 These rules are **always enforced** and **cannot be removed** by the user.  
You may add your **own extra keywords** via the popup settings.

### 📢 On-Screen Alerts  
Shows a **centered warning modal** inside the webpage whenever suspicious clipboard activity is detected.  
- Shows the source website  
- Displays the exact suspicious payload  
- Lets you **whitelist trusted sites** with one click  

### 🔔 System Notifications  
Sends a browser desktop notification so you don’t miss important alerts.

### 📜 Activity Logs  
Keeps the **last 50 suspicious attempts** for quick review in the extension popup.

### ✅ Whitelist Trusted Sites  
If a known safe site (like a web IDE or productivity tool) legitimately uses the clipboard, you can **whitelist it** to avoid alerts.

### 🛠️ User Custom Keywords  
Add your own watchlist keywords in the popup (case-insensitive).  
- Resetting keywords only clears your custom ones — built-in protections remain permanent.

---

## 📂 Installation

1. Download or clone this repository.  
2. Open **Chrome / Edge / Brave** and go to: `chrome://extensions/`  
3. Enable **Developer mode** (toggle in the top-right).  
4. Click **Load unpacked** and select the folder with the extension.  
5. Done! 🎉 The extension is now active.

---

## 🔐 Why Use It?

Clipboard hijacking is one of the simplest but most dangerous tricks in modern scams.  

Attackers rely on you **pasting** something into PowerShell, CMD, or a terminal without noticing.  
ClickFix Clipboard Guard acts as an **intrusion alarm for your clipboard** 🚨 — giving you time to stop before executing something harmful.

---
