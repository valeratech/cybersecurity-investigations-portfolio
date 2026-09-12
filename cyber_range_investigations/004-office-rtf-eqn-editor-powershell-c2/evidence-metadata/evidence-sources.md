# Evidence Sources — Case 004

**Document Type:** Evidence Inventory  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Document

This file records **the evidence sources made available during the investigation**, their origin, scope and limitations. This inventory does not document a chain-of-custody process for the pre-staged lab evidence.

## Investigation Scope

This investigation was conducted as a structured CyberRange question set using the artifacts available within the range. The investigation concluded when the final question was answered. Evidence or analysis outside the scope of those questions was not collected and is not treated as missing or pending investigative work.

## Evidence Acquisition Context

- Evidence was **provided by the CyberDefenders CyberRange**
- No live acquisition was performed by the analyst
- Artifact paths reflect **pre-staged lab evidence**
- Full disk images, memory captures and raw PCAPs were not part of the provided
  evidence set

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
- Limited to the Edge artifacts in the provided evidence set
- Browser cache and memory artifacts were not part of that set

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
- Script artifact creation timestamps

**Limitations:**
- Represents a snapshot in time
- Deleted file content was outside the provided evidence set

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
- Run key value creation
- Encoded PowerShell command discovery
- Record of autorun entries created on the host

#### c. SOFTWARE Hive

**Description:**  
System-wide software configuration and installed application data.

**Artifact Reference:**
`SOFTWARE_clean`

**Evidence Value:**
- Installed Microsoft Office version identification
- Identification of the installed Microsoft Office build (15.x)

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

- Analysis was performed against the pre-staged artifacts as provided
- Hash values survive in the notes only where Sysmon process-creation records embedded them for Windows system binaries; they are incidental to the questions those records answered and are not treated as case indicators
- Hashing the malicious document, script, and downloaded executable was outside the question set and formed no part of the investigation
- The artifact paths and timestamps quoted in this inventory are recorded as they appear in the surviving notes

## Summary

The evidence set supported the case record's findings:
- Identification of the initial access vector
- Range-reported exploitation with observed subsequent execution
- Creation of two persistence artifacts, execution of neither established
- Identification of external command-and-control infrastructure

Full disk and memory images were not part of the evidence set.
