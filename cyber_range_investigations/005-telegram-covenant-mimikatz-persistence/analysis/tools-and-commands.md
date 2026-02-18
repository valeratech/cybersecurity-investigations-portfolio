# Tools and Commands Used

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders (CyberRange)

## 1. Forensic Tooling

The following tools were used to analyze the triage artifacts.

### Registry Analysis
- Registry Explorer  
  Purpose:
  - Load SYSTEM and SOFTWARE hives
  - Extract OS build, hostname, timezone, shutdown time
  - Review network configuration
  - Validate service-based persistence

### NTFS Analysis
- NTFS Log Tracker  
  Purpose:
  - Parse `$LogFile`
  - Parse `$MFT`
  - Parse `$Extend\$J`
  - Correlate FileReferenceNumber values
  - Identify file creation and rename events
  - Confirm `mimikatz.exe` → `svchost.exe` rename sequence

### User Activity Analysis
- UserAssist Forensic Tool  
  Purpose:
  - Parse `NTUSER.DAT`
  - Extract Telegram usage (Focus Time = 383811 ms)

- ShellBags Explorer  
  Purpose:
  - Identify access to remote network shares
  - Confirm interaction with `\\10[.]10[.]5[.]86\shared\`

### Event Log Analysis
- Event Log Explorer  
  Purpose:
  - Review `Security.evtx`
  - Filter:
    - Event ID 4720 (User creation)
    - Event ID 4663 (Object access attempt)

### Shortcut (LNK) Analysis
- LECmd (Eric Zimmerman)  
- Timeline Explorer (review CSV output)

Purpose:
- Parse Recent / Quick Launch LNK files
- Confirm access to `lansweeper.ps1`
- Validate working directory references

### Threat Intelligence
- VirusTotal (web interface)

Purpose:
- Hash lookup for suspicious `Minecraft.exe`
- Confirm Covenant C2 identification
- Review YARA rule match metadata

### Supporting Utilities
- Visual Studio Code  
  Purpose:
  - Search exported NTFS logs for:
    - `svchost.exe`
    - `mimikatz.exe`
    - FileReferenceNumber correlation

- Windows CMD
- PowerShell

## 2. Commands Executed

### Windows CMD

Locate Security log:

dir /S /B | findstr -l "Security.evtx"

Locate $MFT:

dir /S /B | findstr "$MFT"

Locate $UsnJrnl:

dir /S /B | findstr "$J"

Locate LNK files:

dir /S /B | findstr -l "lnk"

### PowerShell

Search for task referencing Minecraft payload:

Get-ChildItem -Path "./" -Recurse -File |
Select-String -Pattern "minecraft" |
Select-Object -ExpandProperty Path

### LECmd

Example execution:

LECmd.exe -d "...\Microsoft\Windows\Recent" --csv C:\Users\Administrator\Desktop

Purpose:
- Export LNK metadata for timeline analysis
- Confirm remote share access artifacts

## 3. Artifact Correlation Methodology

### Rename Correlation (Masquerade Validation)

1. Identify `svchost.exe` execution in Downloads folder.
2. Extract FileReferenceNumber from NTFS logs.
3. Search same FileReferenceNumber for earlier `File_Renamed_Old` or `File_Created` events.
4. Confirm original filename: `mimikatz.exe`.

### Scheduled Task Validation

Artifact:
`...\Windows\System32\Tasks\spawn`

Extract:
- `<StartBoundary>` timestamp
- `<Exec>` command and arguments
- `<Author>` context

Confirmed:
StartBoundary: 2022-11-11 20:10:00 UTC

### Service-Based Persistence

Registry Path:
HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule

Validated:
- Service existence
- Creation timeframe correlation
- Association with suspicious executable

### User Creation Validation

Security Event ID:
4720

Validated:
- New account: cpitter
- Timestamp: 2022-11-11 21:23:51 UTC

## 4. Reproducibility Notes

- All timestamps normalized to UTC.
- Indicators defanged where appropriate.
- Only metadata documented in this repository.
- No live malware samples stored in repo.
