# Incident Flow Diagram (Outline)

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Purpose:** Provide a clean, reproducible incident flow diagram outline suitable for later conversion to Mermaid, draw.io, or PowerPoint.

## 1. Entities

- **User/Actor:** Administrator (interactive)
- **Host:** MAGENTA (polo[.]shirts[.]corp)
- **Tool Transfer App:** Telegram Desktop
- **Payload:** Minecraft.exe (identified as Covenant)
- **Credential Tool:** mimikatz.exe (renamed to svchost.exe)
- **Persistence:** cleanup-schedule (service), \spawn (scheduled task)
- **Target Data:** Credentials.txt
- **Remote Host/Share:** 10[.]10[.]5[.]86 (UNC share)

## 2. High-Level Flow (Box-and-Arrow)

1) ThreatHunting Alert (Sysmon)
   -> Suspicious binary executed from unusual path (Downloads)

2) Telegram Installed + Used Briefly
   -> Telegram Desktop directory creation evidence
   -> UserAssist shows minimal focus time (383811 ms)

3) Tool Transfer / Payload Staging
   -> Downloaded executable named `Minecraft.exe`
   -> Threat intel identifies Covenant framework

4) Credential Access Preparation
   -> `mimikatz.exe` created in Downloads
   -> Renamed to `svchost.exe` (masquerade)

5) Persistence Established
   -> New local user created: `cpitter` (Security 4720)
   -> Service created: `cleanup-schedule` (registry service key)
   -> Scheduled task created: `\spawn` (StartBoundary 2022-11-11 20:10)

6) Credential Targeting
   -> Access attempt to `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt` (Security 4663)

7) Lateral Movement / Remote Share Interaction
   -> Access to `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` (LNK + ShellBags)

8) Outcome
   -> Evidence supports structured post-exploitation activity:
      tool transfer, C2 deployment, credential theft attempt, persistence, share exploration

## 3. Diagram Nodes (Suggested Labels)

- Alert: "Sysmon flagged unusual binary path"
- Node: "Telegram installed"
- Node: "Telegram used (383811 ms)"
- Node: "Minecraft.exe staged"
- Node: "Covenant identified"
- Node: "mimikatz.exe created"
- Node: "Rename mimikatz.exe -> svchost.exe"
- Node: "Scheduled task \\spawn"
- Node: "Service cleanup-schedule"
- Node: "User cpitter created"
- Node: "Attempted access: Credentials.txt"
- Node: "Remote share accessed: lansweeper.ps1"


