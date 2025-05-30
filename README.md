# 🧩 Sysmon Windows Event Logs

![null](images/event-logs-cover.png) <!-- Replace with a relevant screenshot or diagram -->

---

## 📘 Introduction

This lab explores the analysis and interpretation of Windows Event Logs in a blue team context using the TryHackMe "Windows Event Logs" room. The goal was to identify and investigate suspicious activities, such as PowerShell attacks and user enumeration, by querying and filtering logs using native Windows tools. This exercise is vital for SOC analysts and defenders aiming to detect attacker behavior through system event auditing.

---

## 🎯 Objectives

- Understand how Windows Event Logs are structured and stored  
- Use Event Viewer to navigate different log categories  
- Query logs with PowerShell (`Get-WinEvent`) and `wevtutil`  
- Detect signs of attacks using specific Event IDs and log patterns  
- Interpret PowerShell execution logs, group enumeration, and log clearing

---

## 🧰 Tools & Technologies

| Tool/Service     | Purpose                                          |
|------------------|--------------------------------------------------|
| Event Viewer     | GUI tool to browse and filter Windows logs       |
| wevtutil         | CLI utility to query and export log data         |
| PowerShell       | Advanced log querying with `Get-WinEvent`        |
| Windows 10 VM    | Logging source for simulated attacker activity   |

---

## 🧪 Lab Setup

### ✅ Step 1: Open Event Viewer and Navigate Logs

1. Launch **Event Viewer** → `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`  
2. Enable the PowerShell Operational log if it's not already active  
3. Familiarize yourself with log structure and available task categories

---

### ✅ Step 2: Identify Key Event IDs

Reviewed and filtered events using the following IDs:

| Event ID | Meaning                                       |
|----------|-----------------------------------------------|
| 400      | PowerShell engine started                     |
| 403      | PowerShell command execution start            |
| 4103     | Pipeline execution details                    |
| 4104     | Script block logging (useful for script content) |
| 800      | Get-Command usage                             |
| 1102     | Security log cleared                          |
| 4688     | Process creation                              |

---

### ✅ Step 3: Filter Logs for PowerShell Attacks

- Used Event Viewer filters to find suspicious script block logs (`4104`)
- Detected a PowerShell **downgrade attack** by checking `EngineVersion` values under `Event ID 400`
- Identified malicious script behavior such as enumeration and credential dumping

---

### ✅ Step 4: Analyze Logs with PowerShell & wevtutil

```powershell
# Example: Find PowerShell script block events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | Format-List

# Export logs to a file
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text > process_creation.txt
````

---

### ✅ Step 5: Identify Log Tampering & Recon Activity

* Found `Event ID 1102` indicating someone cleared the Security log
* Searched for `net group` and other enumeration commands
* Noted timeline of attacker commands and privilege escalation techniques

---

## 📸 Screenshots

| Description                 | Screenshot                                  |
| --------------------------- | ------------------------------------------- |
| PowerShell event ID 4104    | ![null](images/powershell-script-block.png) |
| Downgrade attack detected   | ![null](images/downgrade-detected.png)      |
| Security log cleared (1102) | ![null](images/security-log-cleared.png)    |

---

## ✅ Key Takeaways

* Event logs are critical for detecting malicious behavior in Windows environments
* PowerShell Operational logs provide deep insight into attacker TTPs
* Downgrade attacks and script block logs are red flags for post-exploitation
* Log manipulation (Event ID 1102) is a strong indicator of malicious intent
* Mastery of native tools like Event Viewer, `wevtutil`, and PowerShell enhances defensive monitoring

---

## 📎 References

* [TryHackMe Room – Windows Event Logs](https://tryhackme.com/room/windowseventlogs)
* [The Dutch Hacker Write-Up](https://www.thedutchhacker.com/windows-event-logs-on-tryhackme/)
* Microsoft Docs: [Event Viewer](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-event-ids)

---

## 📬 About Me

👋 I'm **Zee**, a cybersecurity analyst focused on building secure environments, hardening infrastructure, and simulating enterprise-level defense strategies in lab environments.

🔗 [Connect with me on LinkedIn](https://www.linkedin.com/in/zee-williams)
🔍 [View more labs on my GitHub](https://github.com/zeewilliams)

```
