# Final Investigation Report — Case 004

**Case Title:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Case ID:** 004  
**Analyst:** Ryan Valera  
**Date Created:** 2026-01-25  
**Last Updated:** 2026-01-25  
**Time Standard:** UTC (unless explicitly stated otherwise)  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

AlphaFinance Group identified suspicious activity originating from a finance department workstation following access to a spoofed Microsoft 365 portal. The investigation confirmed a phishing-based initial access vector that delivered a malicious Rich Text Format (RTF) document. Opening the document triggered exploitation of a known Microsoft Equation Editor vulnerability, resulting in remote code execution.

Post-exploitation activity included execution of a PowerShell dropper, process masquerading, multiple discovery commands, redundant persistence mechanisms, and outbound command-and-control (C2) communications over non-standard ports.

The attacker demonstrated intent to maintain long-term access using user-level persistence and encrypted outbound traffic.

## 2. Investigation Scope & Objectives

### Objectives
- Identify the initial access vector
- Determine the delivery and exploit mechanism
- Trace execution and post-exploitation activity
- Identify persistence mechanisms
- Identify C2 infrastructure and communication details

### Scope
- Disk forensics (NTFS metadata and user artifacts)
- Browser artifacts (Microsoft Edge)
- Registry analysis (SAM, NTUSER.DAT, SOFTWARE)
- Host-based telemetry (Sysmon)

## 3. Initial Access & Delivery

### Phishing Access
The targeted user (`harrisr`) accessed a spoofed Microsoft-themed portal hosted on external infrastructure.

- Access Time: `2025-05-23 10:52:59 UTC`
- Delivery Method: Web-based phishing portal
- Evidence Source: Microsoft Edge browsing history

### Payload Delivery
A document named `Financial_Report.rtf` was downloaded shortly after accessing the phishing site.

- Download Time: `2025-05-23 10:53:22 UTC`
- Download Location: `C:\Users\harrisr\Downloads\`
- Evidence: Browser download records and NTFS `$MFT`

Zone.Identifier metadata confirmed the document originated from the internet.

## 4. Exploitation & Execution

### Exploited Application
- Product: Microsoft Office (Word)
- Component: Equation Editor (`EQNEDT32.EXE`)
- Version: `15.0.4420.1017`
- Vulnerability: `CVE-2017-11882`

The malicious RTF file exploited the Equation Editor vulnerability, allowing code execution without requiring macros or additional user interaction beyond opening the document.

### Execution Chain
Following exploitation, a PowerShell script (`msupdate.ps1`) was dropped into the user’s temporary directory and executed in a hidden context via `cmd.exe`. Process masquerading was observed, with execution behavior referencing a legitimate Windows binary.

- Script Creation Time: `2025-05-23 11:15:43 UTC`
- Execution Evidence: Sysmon process creation events

## 5. Post-Exploitation Activity

### Discovery Commands
The attacker executed multiple built-in Windows commands to gather host and network information:

- `whoami`
- `ipconfig /all`
- `ping`
- `netstat`

These commands indicate situational awareness and internal reconnaissance following successful exploitation.

### Process Masquerading
Execution behavior showed evidence of process spoofing using a benign Windows process name, likely intended to evade detection.

## 6. Persistence Mechanisms

The attacker implemented **redundant user-level persistence** mechanisms to ensure continued execution.

### Registry Run Key
- Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Value Name: `Microsoft Update Assistant`
- Creation Time: `2025-05-23 11:17:50 UTC`

### Startup Folder Persistence
- File: `WindowsUpdate.lnk`
- Path: User Startup folder
- Creation Time: `2025-05-23 11:17:51 UTC`

Both mechanisms executed hidden PowerShell commands to retrieve and execute a payload from external infrastructure.

## 7. Command-and-Control (C2)

Host-based telemetry confirmed outbound connections to an external host associated with attacker-controlled infrastructure.

- External Host: `63[.]176[.]96[.]97`
- Observed Ports:
  - `4444` (primary)
  - `8080` (secondary)
- Protocol: TCP
- Evidence Source: Sysmon network connection events

Use of non-standard ports suggests an attempt to evade basic network detection controls.

## 8. Timeline Summary (UTC)

- `10:52:59` — User accessed phishing portal
- `10:53:22` — Malicious RTF downloaded
- `10:53:22` — File created on disk with internet MOTW
- `10:54:02` — Outbound network connection to external host
- `10:59:18–10:59:48` — Discovery commands executed
- `11:15:43` — PowerShell script created
- `11:17:44` — Hidden PowerShell execution observed
- `11:17:50` — Registry persistence created
- `11:17:51` — Startup persistence created

## 9. Indicators of Compromise (Defanged)

### URLs
- `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`

### Files
- `Financial_Report.rtf`
- `msupdate.ps1`
- `WindowsUpdate.lnk`
- `msupdate-<random4>.exe`

### Network
- `63[.]176[.]96[.]97:4444`
- `63[.]176[.]96[.]97:8080`

## 10. Assessment & Impact

This incident represents a **high-risk compromise** involving:
- Client-side exploitation
- Arbitrary code execution
- Multiple persistence mechanisms
- Active external C2 communications

If this activity had occurred in a production environment, it would warrant:
- Immediate host isolation
- Credential reset for affected user
- Enterprise-wide IOC sweeping
- Review of Office patch levels

## 11. Lessons Learned

- Legacy Office components remain high-risk when unpatched
- RTF-based exploits continue to be effective phishing payloads
- User-level persistence is sufficient for long-term access
- Host-based telemetry is critical when network visibility is limited

## 12. Conclusion

The investigation conclusively identified a phishing-driven exploitation chain resulting in persistent compromise of a user workstation. Evidence supports deliberate attacker actions consistent with real-world tradecraft, including exploitation of known vulnerabilities, stealthy execution, redundancy in persistence, and covert command-and-control communication.

This case highlights the continued relevance of disk forensics and host telemetry in detecting and reconstructing sophisticated endpoint intrusions.
