# Detection Engineering Notes

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Focus:** Translate findings into actionable detections, controls, and SOC tuning.

## 1. High-Signal Detections (Priority)

### A) svchost.exe execution outside System32/SysWOW64
**Why it matters:** High-confidence masquerade indicator.

**Detection logic:**
- Process name ends with `svchost.exe`
- Path NOT in:
  - `C:\Windows\System32\svchost.exe`
  - `C:\Windows\SysWOW64\svchost.exe`
- Severity: High
- Recommended telemetry: Sysmon EID 1, EDR process events

**Tuning:**
- Allowlist known legitimate admin utilities that may drop similarly named binaries (rare).
- Validate with file signer (should be Microsoft for legitimate svchost).

### B) New local account creation (Security 4720)
**Why it matters:** Common persistence mechanism.

**Detection logic:**
- Event ID 4720
- Exclude known provisioning workflows (gold images, SCCM, Intune)
- Alert when:
  - Created by high-priv user (e.g., Administrator)
  - Account has unusual UAC flags (e.g., password not required)

**Response enrichment:**
- Capture creator SID, workstation, logon session, and subsequent logons by the new user.

### C) Service creation with user-writable ImagePath (System 7045)
**Why it matters:** Common persistence; strong if binary located in user-write paths.

**Detection logic:**
- Event ID 7045
- ImagePath contains:
  - `\Users\`
  - `\Downloads\`
  - `\AppData\`
  - `\ProgramData\` (case-by-case)
- Severity: High

**Tuning:**
- Allowlist sanctioned enterprise agents installed under ProgramData (depends on org).

### D) Scheduled task created/updated (Security 4698/4702; TaskScheduler Operational)
**Why it matters:** Persistence and execution.

**Detection logic:**
- Task created or updated
- Task action points to:
  - `\Users\`
  - `\Downloads\`
  - `\AppData\`
- Task name suspicious or generic (e.g., `spawn`)
- Severity: Medium/High depending on context

### E) Credential file access attempts (Security 4663)
**Why it matters:** Explicit targeting of sensitive material.

**Detection logic:**
- Event ID 4663 for sensitive paths:
  - `*\C-Levels\*`
  - `*\Credentials.txt`
  - password vault exports / key files (org-specific)
- Include ProcessName (e.g., `dllhost.exe`) to identify suspicious accessors.

**Tuning:**
- Ensure Object Access auditing is enabled only for high-value folders to reduce noise.

### F) Lateral movement via SMB share access (Security 5140)
**Why it matters:** Indicates discovery/exfil staging.

**Detection logic:**
- 5140 events to administrative shares or unusual shares
- Rapid enumeration patterns (many targets in short time)
- Specific high-risk file types accessed over SMB:
  - `.ps1`, `.bat`, `.vbs`, `.lnk`, `.exe`

## 2. Supporting Detections (Secondary)

### A) Telegram installation / execution in enterprise
**Why it matters:** Uncommon in many orgs; potential evasion channel.

**Detection ideas:**
- New executable runs from Telegram install paths
- New directories under:
  - `%AppData%\Telegram Desktop\`
- Alert when:
  - Telegram installed shortly before malicious execution from Downloads

**Control ideas:**
- Application allowlisting (AppLocker/WDAC)
- Software restriction policies
- Endpoint application inventory alerts

### B) Mimikatz indicators (behavioral)
**Note:** Prefer behavioral detections over simple filename matches.

**Detection ideas:**
- LSASS access attempts (Sysmon EID 10, EDR)
- `SeDebugPrivilege` enablement patterns (EDR)
- Known suspicious command lines

## 3. Suggested Sigma Rules (Logic Outline)

### Rule 1: svchost outside system directories
- Logsource: Sysmon ProcessCreate
- Condition:
  - Image endswith `\svchost.exe`
  - NOT Image startswith `C:\Windows\System32\` AND NOT startswith `C:\Windows\SysWOW64\`

### Rule 2: service install from user-writable paths
- Logsource: Windows System 7045
- Condition:
  - ImagePath contains `\Users\` OR `\Downloads\` OR `\AppData\`

### Rule 3: scheduled task action from user-writable paths
- Logsource: Security 4698/4702 or TaskScheduler Operational
- Condition:
  - TaskName exists
  - Task action contains `\Users\` OR `\Downloads\` OR `\AppData\`

### Rule 4: local user creation by privileged accounts
- Logsource: Security 4720
- Condition:
  - SubjectUserName in (Administrator, Domain Admins, etc.)
  - TargetUserName not in allowlist

## 4. Response Playbook Notes (SOC)

When the above detections trigger, collect:
- Process tree (parent/child chain) around Downloads execution
- File metadata (hash, signer, compile time where available)
- Service details:
  - ImagePath
  - StartType
  - AccountName
- Scheduled task XML (full)
- New user details:
  - groups, last logon, enabled/disabled status
- SMB targets (remote IPs and shares)
- Any outbound connections associated with the suspicious binaries (Sysmon EID 3 / firewall)

## 5. Case-Specific Indicators to Monitor (Defanged)

- New user: cpitter
- Service: cleanup-schedule
- Task: \spawn
- Masquerade path: `*\Downloads\svchost.exe`
- Remote share: `\\10[.]10[.]5[.]86\shared\lansweeper.ps1`
- Credential target: `*\C-Levels\Credentials.txt`

