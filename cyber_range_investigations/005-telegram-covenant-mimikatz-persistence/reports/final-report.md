# Final Investigation Report

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Author:** Ryan Valera  
**Source Platform:** CyberDefenders (CyberRange)  
**Time Standard:** UTC  

# 1. Executive Summary

During routine threat hunting, a suspicious binary executed from an unusual directory was identified via Sysmon logs. A forensic triage image was analyzed to determine the origin, intent, and scope of the activity.

Investigation revealed that Telegram Desktop was installed and used briefly to download a malicious payload disguised as `Minecraft.exe`. The payload was identified as the Covenant Command & Control (C2) framework. Additional analysis uncovered staging of `mimikatz.exe`, which was subsequently renamed to `svchost.exe` to evade detection.

Persistence was established through:
- Creation of a new local user account (`cpitter`)
- Creation of a Windows service (`cleanup-schedule`)
- Creation of a scheduled task (`\spawn`)

Further evidence indicated attempted access to a credential storage file and exploration of a remote network share.

The activity reflects structured post-exploitation behavior consistent with insider misuse or interactive compromise.

# 2. Scope and Evidence Reviewed

The investigation was conducted using a structured triage artifact set located at:

`C:\Users\Administrator\Desktop\Start Here\Artifacts\`

Artifacts reviewed included:

- SYSTEM and SOFTWARE registry hives
- NTUSER.DAT (Administrator)
- Windows Security Event Log (Security.evtx)
- NTFS metadata ($MFT, $LogFile, $UsnJrnl/$J)
- Scheduled task XML definitions
- LNK shortcut artifacts
- ShellBags artifacts

No live system interaction occurred. Analysis was performed offline using forensic tools.

# 3. System Baseline

| Attribute | Value |
|-----------|--------|
| Hostname | MAGENTA |
| Domain (defanged) | polo[.]shirts[.]corp |
| Windows Build | 14393 |
| Timezone (artifact) | Eastern Standard Time |
| Host IP (defanged) | 10[.]10[.]5[.]113 |
| Remote Share Host (defanged) | 10[.]10[.]5[.]86 |

Last recorded shutdown:
2021-07-30 15:25:00 UTC

# 4. Incident Timeline Summary (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2022-11-11 20:10:00 | Scheduled task `\spawn` configured |
| 2022-11-11 21:23:51 | New user account `cpitter` created |
| 2022-11-11 21:44:29 | `mimikatz.exe` created in Downloads |
| 2022-11-11 21:48:08 | `mimikatz.exe` renamed to `svchost.exe` |
| 2022-11-11 21:54:57 | Telegram Desktop directory created |
| 2022-11-11 (UserAssist) | Telegram usage recorded (383811 ms) |
| 2022-11-11 | Access attempt to `Credentials.txt` |
| 2022-11-11 | Remote share accessed: `lansweeper.ps1` |

# 5. Key Findings

## 5.1 Tool Transfer via Telegram

Telegram Desktop was installed and used briefly. NTFS journal evidence confirms file creation shortly after installation.

UserAssist Focus Time:
383811 milliseconds

This short execution window suggests Telegram was used primarily to obtain tooling.

## 5.2 Covenant C2 Deployment

The file `Minecraft.exe` was analyzed via SHA-256 hash:

b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5

Threat intelligence lookup identified the payload as Covenant (C2 framework).

## 5.3 Credential Harvesting Tool Staging

`mimikatz.exe` was created and later renamed to `svchost.exe` in the Downloads directory.

NTFS journal correlation confirms both filenames share the same FileReferenceNumber, indicating deliberate masquerade behavior.

## 5.4 Persistence Mechanisms

### New Account Creation
- Event ID 4720
- Account: cpitter

### Windows Service
- Service name: cleanup-schedule
- Registry path:
  HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule

### Scheduled Task
- Task: \spawn
- StartBoundary: 2022-11-11 20:10:00 UTC
- Task action references execution from Downloads directory.

## 5.5 Credential Targeting

Security Event ID 4663 revealed access attempt against:

`C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`

This suggests active search for credential material.

## 5.6 Lateral Movement Indicators

ShellBags and LNK analysis confirm access to:

`\\10[.]10[.]5[.]86\shared\lansweeper.ps1`

This behavior indicates exploration of remote systems, possibly for reconnaissance or credential harvesting.

# 6. ATT&CK Alignment

The observed behaviors map to:

- T1105 – Ingress Tool Transfer
- T1204 – User Execution
- T1136 – Create Account
- T1543 – Windows Service
- T1053 – Scheduled Task
- T1036 – Masquerading
- T1003 – OS Credential Dumping
- T1021 – Remote Services
- T1071 – Application Layer Protocol

# 7. Conclusion

The host experienced structured post-exploitation activity involving:

1. Tool acquisition via Telegram
2. Deployment of Covenant C2 framework
3. Staging of credential dumping utility
4. Defense evasion via filename masquerade
5. Establishment of multiple persistence mechanisms
6. Credential file targeting
7. Remote share exploration

The combination of C2 framework usage, credential tooling, and layered persistence strongly indicates intentional malicious activity rather than benign misuse.

# 8. Recommendations

- Disable and remove unauthorized account (`cpitter`)
- Remove malicious service and scheduled task
- Reset credentials for affected accounts
- Review outbound communications for C2 traffic
- Implement monitoring for:
  - Service creation (Event ID 7045)
  - Scheduled task creation (Event ID 4698)
  - Account creation (Event ID 4720)
  - Suspicious process execution from Downloads directory
- Restrict unauthorized application installation (e.g., Telegram)

# 9. Portfolio Note

This investigation demonstrates:

- Registry forensics
- NTFS journal correlation
- Masquerade detection
- Event log analysis
- LNK artifact analysis
- Persistence validation
- Threat intelligence enrichment
- ATT&CK technique mapping
- Structured forensic documentation

