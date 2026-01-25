# Investigation Log — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless explicitly stated otherwise)

## Purpose of This Log

This file serves as the **running investigative narrative** for Case 004.  
It documents *what was analyzed, why it was analyzed, how it was validated, and what evidence supports each conclusion*.

This log is written incrementally as the investigation progresses and intentionally mirrors real-world DFIR case notes.

## Initial Context

AlphaFinance Group reported suspicious activity following access to what appeared to be a Microsoft 365 financial portal by a finance department employee. Subsequent alerts indicated abnormal PowerShell execution, persistence mechanisms, and outbound connections to an external host.

The investigation began by validating **initial access**, then pivoting into **delivery, execution, persistence, and command-and-control** artifacts.

## Investigation Progress

### Step 1 — Identify Initial Access Vector (Phishing)

**Objective:**  
Determine whether the employee accessed a malicious external resource.

**Action Taken:**  
Parsed Microsoft Edge browsing artifacts for user `harrisr` from the CyberRange-provided disk artifacts.

**Artifact Location:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default`

**Method:**
Queried Edge SQLite databases for non-HTTPS URLs.

**Finding:**  
A spoofed Microsoft-related URL was accessed by the user.

**Indicator (defanged):**
`hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`

**Timestamp (UTC):**
`2025-05-23 10:52:59`

**Conclusion:**  
This URL represents the **initial access vector** and aligns with a phishing-based delivery mechanism.

### Step 2 — Identify Delivered Payload (Malicious Document)

**Objective:**  
Determine whether a file was downloaded from the phishing site.

**Action Taken:**  
Reviewed Edge download history artifacts for the same user profile.

**Artifact Location:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\history`

**Finding:**  
A document named `Financial_Report.rtf` was downloaded shortly after the phishing URL was accessed.

**File Name:**
`Financial_Report.rtf`

**Download Timestamp (UTC):**
`2025-05-23 10:53:22`

**Conclusion:**  
The RTF document is the **delivery mechanism** for the exploit chain.

### Step 3 — Validate File Creation via NTFS Timeline

**Objective:**  
Corroborate browser-based timestamps using disk-level evidence.

**Action Taken:**  
Extracted and parsed the NTFS Master File Table ($MFT).

**Tool Used:**
- MFTECmd
- Timeline Explorer

**Artifact Location:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\$MFT`

**Finding:**  
`Financial_Report.rtf` was created in the user’s Downloads directory, and a Zone.Identifier ADS confirms internet origin.

**Creation Time (UTC):**
`2025-05-23 10:53:22`

**Additional Evidence:**
- `.lnk` files created in Recent and Office Recent directories
- Zone.Identifier indicates download from external source

**Conclusion:**  
Disk artifacts confirm browser evidence and establish **user execution context**.

### Step 4 — Identify Targeted User Accounts

**Objective:**  
Confirm which local user accounts exist on the system to scope artifact ownership.

**Action Taken:**  
Parsed the SAM registry hive using Registry Explorer.

**Artifact Location:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\System32\config\SAM: SAM\Domains\Account\Users\Names`

**Users Identified:**
- `Administrator`
- `harrisr`
- `IT_Helpdesk`

**Conclusion:**  
The investigation is scoped to user `harrisr`, who accessed the phishing content and executed the payload.

### Step 5 — Identify Exploited Application

**Objective:**  
Determine which client-side application was exploited.

**Action Taken:**  
Reviewed installed applications and correlated document type with execution behavior.

**Applications of Interest:**
- Microsoft Office
- Google Chrome (installed but not implicated)

**Finding:**  
The RTF was opened in Microsoft Word, triggering execution of the legacy Equation Editor component.

**Office Version Identified:**
`15.0.4420.1017`

**Conclusion:**  
The exploit targets **Microsoft Office 2013 (15.x)**.

### Step 6 — Identify Exploit Used

**Objective:**  
Determine which vulnerability enabled code execution.

**Finding:**  
Timeline analysis and process behavior match a known Equation Editor RCE.

**CVE Identified:**
`CVE-2017-11882`

**Description:**  
A remote code execution vulnerability in the Microsoft Equation Editor (`EQNEDT32.EXE`) triggered via a crafted RTF file without macros.

**Conclusion:**  
This CVE explains the observed execution chain and aligns with the Office version in use.

### Step 7 — Identify Dropped Script and Execution

**Objective:**  
Determine what executed post-exploitation.

**Action Taken:**  
Filtered NTFS timeline and Sysmon logs for script creation and execution.

**Finding:**  
A PowerShell script was dropped to the user’s TEMP directory.

**Script Name:**
`msupdate.ps1`

**Creation Time (UTC):**
`2025-05-23 11:15:43`

**Execution Behavior:**
- Launched via hidden PowerShell
- Spawned through `cmd.exe`
- Process spoofing observed (notepad referenced)

**Conclusion:**  
`msupdate.ps1` represents the **primary execution and staging script**.

### Step 8 — Identify Persistence Mechanisms

**Objective:**  
Determine how the attacker maintained access.

**Findings:**

1. **Registry Run Key**
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

  - Value Name: Microsoft Update Assistant

2. **Startup Folder LNK**
`WindowsUpdate.lnk`

**Timestamps (UTC):**
- Registry persistence: `2025-05-23 11:17:50`
- Startup persistence: `2025-05-23 11:17:51`

**Conclusion:**  
The attacker implemented **redundant user-level persistence**.

### Step 9 — Identify Command-and-Control (C2)

**Objective:**  
Determine external communication endpoints.

**Action Taken:**  
Reviewed Sysmon network events (Event ID 3).

**Finding (defanged):**
`63[.]176[.]96[.]97`

**Observed Ports:**
- `4444` (primary)
- `8080` (secondary)

**Conclusion:**  
Outbound connections to a non-standard port indicate **active C2 communications**.

## Current Status

- Initial access: **Confirmed**
- Exploit chain: **Confirmed**
- Persistence: **Confirmed**
- C2 infrastructure: **Identified**
- Evidence confidence: **High**

Next steps will focus on:
- Consolidated timeline
- MITRE ATT&CK mapping
- Final IOC validation and reporting
