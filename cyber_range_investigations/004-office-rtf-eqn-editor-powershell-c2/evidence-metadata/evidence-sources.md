# Evidence Sources — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless explicitly stated otherwise)

## Purpose of This Document

This file documents **all evidence sources made available during the investigation**, including their origin, scope, and any limitations.  
It serves as a lightweight **chain-of-custody and evidence inventory record** suitable for DFIR reporting and portfolio review.

## Evidence Acquisition Context

- Evidence was **provided by the CyberDefenders CyberRange**
- No live acquisition was performed by the analyst
- Artifact paths reflect **pre-staged lab evidence**
- Full disk images, memory captures, and raw PCAPs may not be available

All analysis was conducted **in situ** against the provided artifacts.

## Evidence Sources Inventory

### 1. Browser Artifacts — Microsoft Edge

**Description:**  
User browsing and download activity for the targeted user account.

**User Context:**  
`harrisr`

**Artifact Paths:**
- `C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default`
- `C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\history`

**Evidence Value:**
- Phishing URL access
- Malicious document download confirmation
- Timestamp correlation with NTFS artifacts

**Limitations:**
- Limited to Edge artifacts only
- No full browser cache or memory artifacts available

### 2. NTFS Master File Table ($MFT)

**Description:**  
File system metadata used for timeline reconstruction and artifact validation.

**Artifact Path:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\$MFT`

**Tool Used:**
- MFTECmd (Eric Zimmerman)

**Evidence Value:**
- File creation, modification, and access times
- Zone.Identifier ADS confirmation
- LNK file creation and recent file tracking
- Script and payload staging verification

**Limitations:**
- Represents a snapshot in time
- Deleted file content not recoverable without full disk image

### 3. Registry Hives

#### a. SAM Hive

**Description:**  
Local user account enumeration.

**Artifact Path:**
`C:\Users\Administrator\Desktop\Start Here\Artifacts\C\Windows\System32\config\SAM: SAM\Domains\Account\Users\Names`

**Evidence Value:**
- Identification of local user accounts
- Scoping of user-specific artifacts

#### b. NTUSER.DAT (Target User)

**Description:**  
User-specific registry hive for persistence analysis.

**User Context:**
`harrisr`

**Artifact Path:**
`C:\Users\harrisr\Ntuser.dat: Software\Microsoft\Windows\CurrentVersion\Run`

**Evidence Value:**
- Run key persistence confirmation
- Encoded PowerShell command discovery
- Mapping of attacker-established autoruns

#### c. SOFTWARE Hive

**Description:**  
System-wide software configuration and installed application data.

**Artifact Reference:**
`SOFTWARE_clean`

**Evidence Value:**
- Installed Microsoft Office version identification
- Validation of vulnerable Office build (15.x)

### 4. Sysmon Event Logs

**Description:**  
Host-based telemetry capturing process execution, network connections, registry changes, and file creation.

**Event IDs Utilized:**
- **Event ID 1** — Process creation
- **Event ID 3** — Network connections
- **Event ID 11** — File creation
- **Event ID 13** — Registry value set

**Evidence Value:**
- Process execution chain reconstruction
- Discovery command identification
- C2 network activity confirmation
- Persistence mechanism timestamps

**Limitations:**
- Some event descriptions unavailable in viewer
- Analysis based on parsed event fields rather than rendered descriptions

### 5. Artifact Collection Framework Indicators

**Description:**  
Presence of collected artifacts indicates use of an automated triage framework.

**Observed Paths:**
`.\KAPE\Output\C\Users\harrisr\AppData\Roaming\Microsoft\Windows\Recent Financial_Report.lnk`

**Evidence Value:**
- Confirms structured artifact collection
- Supports timeline correlation across multiple sources

## Evidence Integrity Notes

- Evidence files were analyzed **read-only**
- No modification of original artifacts occurred
- Hash values were not provided as part of the CyberRange scenario
- All evidence paths and timestamps are recorded as provided

## Summary

The evidence set provided sufficient coverage to:
- Identify initial access
- Confirm exploit chain and execution
- Validate multiple persistence mechanisms
- Identify external command-and-control infrastructure

While constrained by the absence of full disk and memory images, the available artifacts were adequate to reconstruct attacker behavior with **high confidence**.
