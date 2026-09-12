# Investigation Log — Case 004

**Document Type:** Case Note  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Log

This file serves as the **running investigative narrative** for Case 004.  
It documents *what was analyzed, why it was analyzed, how it was validated, and what evidence supports each conclusion*.

This log is written incrementally as the investigation progresses and intentionally mirrors real-world DFIR case notes.

## Initial Context

The CyberRange scenario reports that AlphaFinance Group observed suspicious activity following access to what appeared to be a Microsoft 365 financial portal by a finance department employee, with subsequent alerts indicating abnormal PowerShell execution, persistence mechanisms, and outbound connections to an external host. That context is scenario-supplied and is not independently established by the surviving record.

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
`Financial_Report.rtf` was created in the user's Downloads directory, and a Zone.Identifier ADS confirms internet origin.

**Creation Time (UTC):**
`2025-05-23 10:53:22`

**Additional Evidence:**
- `.lnk` files created in Recent and Office Recent directories
- Zone.Identifier indicates download from external source

**Conclusion:**  
Disk artifacts corroborate the browser evidence. Recent and Office Recent shortcut entries record the document's presence; no process record for its execution is preserved.

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
The investigation is scoped to user `harrisr`, whose profile holds the phishing access and download artifacts and under whose context the observed processes ran.

### Step 5 — Identify Exploited Application

**Objective:**  
Determine which client-side application was exploited.

**Action Taken:**  
Reviewed installed applications and correlated document type with execution behavior.

**Applications of Interest:**
- Microsoft Office
- Google Chrome (installed but not implicated)

**Finding:**  
The question set states that opening the RTF in Microsoft Word triggered execution of the legacy Equation Editor component. No `WINWORD.EXE` or `EQNEDT32.EXE` process record is present in the completed Q/A record to corroborate that sequence independently.

**Office Version Identified:**
`15.0.4420.1017`

**Conclusion:**  
The observed version string was interpreted in the analyst notes as consistent with the **Microsoft Office 2013 (15.x)** family. That the exploit targeted this build is analyst inference, not an independent observation.

### Step 6 — Identify Exploit Used

**Objective:**  
Determine which vulnerability enabled code execution.

**Range-supplied premise:**  
The question set states that a document opened in Word triggered the Equation Editor, exploiting a known vulnerability.

**CVE recorded by the range:**
`CVE-2017-11882`

**Reference description of the range-recorded CVE:**  
A remote code execution vulnerability in the Microsoft Equation Editor (`EQNEDT32.EXE`) triggered via a crafted RTF file. This describes the named CVE; it is not telemetry showing that mechanism on this host.

**Analyst assessment:**  
The analyst treated the recorded CVE as the likely explanatory match for the range-described Word/Equation Editor sequence and the observed Office version. The completed Q/A record contains no `WINWORD.EXE` or `EQNEDT32.EXE` process record establishing that sequence independently.

### Step 7 — Identify Script Creation and Execution

**Objective:**  
Determine what script was created and what execution the record shows.

**Action Taken:**  
Filtered NTFS timeline and Sysmon logs for script creation and execution.

**Finding:**  
A PowerShell script was created in the user's TEMP directory. The CyberRange question set supplies the premise that the detected exploit dropped it.

**Script Name:**
`msupdate.ps1`

**Creation Time (UTC):**
`2025-05-23 11:15:43`

**Execution Behavior:**
- Launched via hidden PowerShell
- Spawned through `cmd.exe`
- Range-characterized process spoofing; the surviving record shows `notepad.exe` (PID `13852`) as the parent of the `cmd.exe` process

**Conclusion:**  
The record establishes that `msupdate.ps1` was created at `11:15:43` and launched in a hidden context at `11:17:44`. Its contents are not preserved in the completed Q/A record.

### Step 8 — Identify Persistence Mechanisms

**Objective:**  
Determine what persistence artifacts were created.

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
Two user-level persistence artifacts were created. Execution of neither is established by the completed Q/A record.

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
Sysmon records outbound TCP connections to `63[.]176[.]96[.]97` on ports `4444` and `8080`. The CyberRange records `4444` as the C2 port.

## Current Status

- Initial access: **Confirmed**
- Exploit chain: **Exploitation range-reported; subsequent execution observed**
- Persistence: **Artifacts created; execution not established**
- C2 infrastructure: **Identified**

The consolidated timeline, ATT&CK mapping and IOC record are complete and are
held in the case timeline, the IOC collection and the final report. The
investigation is closed; no additional range evidence is available and no
further investigative work is pending.
