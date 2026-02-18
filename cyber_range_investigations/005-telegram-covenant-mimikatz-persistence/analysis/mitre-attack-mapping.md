# MITRE ATT&CK Mapping

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders (CyberRange)

## Overview

This document maps observed attacker behaviors to MITRE ATT&CK tactics and techniques.  
Mapping is based strictly on validated forensic evidence (registry, NTFS, event logs, LNK artifacts).

# Tactic: Initial Access

### T1105 – Ingress Tool Transfer

Evidence:
- Telegram Desktop installed shortly before malicious activity.
- Suspicious payload (`Minecraft.exe`) downloaded.
- NTFS journal confirms file creation in Downloads directory.

Interpretation:
Telegram was likely used to transfer offensive tooling into the environment.

# Tactic: Execution

### T1059 – Command and Scripting Interpreter (PowerShell)

Evidence:
- Remote share artifact: `lansweeper.ps1`
- Scheduled task XML references execution of downloaded payload.

Interpretation:
PowerShell-based tooling was staged or accessed, consistent with post-exploitation scripting.

### T1204 – User Execution

Evidence:
- Telegram usage recorded in UserAssist (383811 ms focus time).
- Payload manually downloaded and executed.

Interpretation:
User-initiated execution behavior consistent with insider or compromised interactive account.

# Tactic: Persistence

### T1136 – Create Account

Evidence:
- Security Event ID 4720
- New account created: `cpitter`
- Timestamp: 2022-11-11 21:23:51 UTC

Interpretation:
Local account created to maintain continued access.

### T1543 – Create or Modify System Process (Windows Service)

Evidence:
- Registry key:
  HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule

Interpretation:
Service-based persistence mechanism established.

### T1053 – Scheduled Task/Job

Evidence:
- Task file: `\spawn`
- StartBoundary: 2022-11-11 20:10:00 UTC
- Task action references execution from Downloads path.

Interpretation:
Scheduled task configured for recurring or delayed execution.

# Tactic: Defense Evasion

### T1036 – Masquerading

Evidence:
- `mimikatz.exe` renamed to `svchost.exe`
- NTFS journal correlation via FileReferenceNumber

Interpretation:
Renaming to a legitimate Windows process name to evade detection.

# Tactic: Credential Access

### T1003 – OS Credential Dumping

Evidence:
- Presence of `mimikatz.exe`
- Attempted access to `Credentials.txt`
- Event ID 4663 logged object access attempt

Interpretation:
Credential harvesting activity likely attempted.

# Tactic: Lateral Movement

### T1021 – Remote Services

Evidence:
- Access to remote UNC path:
  \\10[.]10[.]5[.]86\shared\lansweeper.ps1
- ShellBags and LNK artifacts confirm interaction.

Interpretation:
Exploration of remote host for scripts or credentials.

# Tactic: Command and Control

### T1071 – Application Layer Protocol

Evidence:
- Covenant C2 framework identified via hash lookup.
- YARA match indicating Covenant stager.

Interpretation:
Covenant is a post-exploitation C2 framework supporting HTTP/HTTPS communications.

# ATT&CK Summary Table

| Tactic              | Technique ID | Technique Name                           | Evidence Source |
|--------------------|-------------|-------------------------------------------|-----------------|
| Initial Access     | T1105      | Ingress Tool Transfer                     | NTFS / Telegram |
| Execution          | T1204      | User Execution                            | UserAssist      |
| Persistence        | T1136      | Create Account                            | Event ID 4720   |
| Persistence        | T1543      | Windows Service                           | Registry        |
| Persistence        | T1053      | Scheduled Task                            | Task XML        |
| Defense Evasion    | T1036      | Masquerading                              | NTFS logs       |
| Credential Access  | T1003      | OS Credential Dumping                     | File artifacts  |
| Lateral Movement   | T1021      | Remote Services                           | LNK/ShellBags   |
| Command & Control  | T1071      | Application Layer Protocol                | Covenant ID     |

## Analytical Assessment

The behavior observed aligns with a structured post-exploitation workflow:

1. Tool transfer via Telegram
2. Staging of credential dumping tool
3. Masquerade for defense evasion
4. Persistence through service + scheduled task
5. Account creation for redundancy
6. Credential file targeting
7. Remote share exploration
8. C2 framework deployment (Covenant)

The attack chain demonstrates moderate sophistication consistent with insider misuse or interactive compromise.
