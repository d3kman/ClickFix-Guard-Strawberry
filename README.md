# 🚨 ClickFix Clipboard Guard

ClickFix Clipboard Guard is a lightweight browser extension that protects you from **clipboard hijacking attacks** often used in ClickFix scams and other malware tricks.  

These scams trick you with fake “verification” steps that tell you to open a terminal and paste something — while secretly copying **malicious commands** (like PowerShell or Bash payloads) into your clipboard. If you paste them, your system can be compromised in seconds.  

This extension **monitors clipboard writes in real time** and shouts at you 🚨 when something looks shady.  

---

## ✨ Features

### 🔎 Clipboard Monitoring
- Detects when **any site** tries to write to your clipboard.  
- Even sneaky, hidden, or background attempts are caught.  

### ⚠ Suspicious Content Detection
Built-in detection rules catch the nastiest stuff:  

- **ClickFix bait** → `Verification`, `ID`, `#`  
- **PowerShell & flags** → `powershell`, `-NoProfile`, `-ExecutionPolicy`, `-enc`, `Invoke-Expression`, `IEX`  
- **Windows LOLBins** → `mshta.exe`, `certutil`, `rundll32`, `wget`, `curl`, `bitsadmin`  
- **Command chaining** → URLs followed by `&&`, `;`, pipes, etc.  
- **Mac/Linux hijacks** → `/bin/bash -c`, `curl -fsSL`, curl spoofing as “Mac OS X”  

👉 These rules are **hardcoded** and **cannot be removed** — because they cover the most abused real-world attacks.  

You can also add **your own custom keywords** in the popup settings (for company-specific or new emerging threats).  

### 📢 On-Screen Alerts
When something sketchy is detected:  
- A big centered warning modal appears on the page.  
- You’ll see the **source website** + the **exact clipboard payload**.  
- You can instantly:  
  - ❌ **Dismiss** the alert  
  - ✅ **Whitelist the site** if it’s legit (e.g., a dev tool you trust)  
  - 📤 **Report to Security Team** (shows clear instructions & lets you download a JSON report for emailing to IT/SecOps).  

### 📜 Activity Logs
- Keeps the **last 50 suspicious attempts** in the extension popup.  
- Shows timestamp, origin site, and payload.  
- You can **download logs** for investigation or share with security teams.  

### ✅ Whitelist Management
- One-click **whitelist** from alerts or manually add domains.  
- Whitelisted sites won’t trigger alerts (good for trusted internal tools).  
- You can **clear the whitelist** at any time from the popup settings if you change your mind.  

### 🛠️ User Custom Keywords
- Add your own watchlist keywords (case-insensitive).  
- Great for company-specific patterns or things attackers are starting to abuse.  
- Resetting keywords only clears *your custom ones* — built-in rules are permanent.  

### 🔔 System Notifications
- Also throws a desktop notification (in addition to the on-screen modal).  
- Makes sure you don’t miss an alert even if the suspicious site hides it behind a fake captcha.  

---

## 📂 Installation

1. Download or clone this repository.  
2. Open **Chrome / Edge / Brave** and go to: `chrome://extensions/`  
3. Enable **Developer mode** (toggle in the top-right).  
4. Click **Load unpacked** and select the folder with the extension.  
5. Done! 🎉 The extension is now active and watching your clipboard’s back.  

---

## 🔐 Why Use It?

Clipboard hijacking is **ridiculously simple** for attackers — but devastating for you.  
They don’t need malware installed, just trick you into pasting a command you never meant to run.  

ClickFix Clipboard Guard acts like an **intrusion alarm for your clipboard** 🚨.  
It catches:  
- Windows payloads (PowerShell, CMD, LOLBins)  
- Mac/Linux payloads (`/bin/bash -c`, `curl -fsSL`)  
- ClickFix-style scam scripts  
- Any custom threats you define  

And gives you clear options: **stop, whitelist, or report**.  

No more blind copy-paste → 💥 ransomware.  

---

## 🧑‍💻 Everyday Workflow (How to Use)

1. **See an alert?** Don’t panic — read it.  
2. If it’s clearly **malicious** → dismiss or report to your security team.  
3. If it’s from a **legit site** you trust (like your company’s internal tools) → whitelist it.  
4. Check the **logs** anytime in the popup to review past suspicious attempts.  
5. Add **custom keywords** if you want extra eyes on certain terms or commands.  

Stay safe, copy smart ✨  
