# Tools and Commands Used

**Document Type:** Analysis  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Forensic Tooling

The following tools were used to analyze the triage artifacts.

### Registry Analysis
- Registry Explorer  
  Purpose:
  - Load SYSTEM and SOFTWARE hives
  - Extract OS build, hostname, timezone, shutdown time
  - Review network configuration
  - Review service configuration

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
  - Extract program execution records: run count, last execution, focus time
  - `Telegram.exe` focus time 383811 ms; `Minecraft.exe` run count 3, focus time 187452 ms
  - Recorded execution times are 12-hour displays with no timezone indicator

- ShellBags Explorer  
  Purpose:
  - Identify remote network locations recorded in NTUSER.DAT
  - Record host context involving 10[.]10[.]5[.]86
  - ShellBags records the network location; the full file path is established by the LNK
    evidence below

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
- Record the `lansweeper.ps1` file path from LNK output
- Validate working directory references

### Threat Intelligence
- VirusTotal (web interface)

Purpose:
- Hash lookup for suspicious `Minecraft.exe`
- Record the Covenant identification returned by community data (analyst-derived enrichment)
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

1. Identify the `svchost.exe` file record in the Downloads folder.
2. Extract FileReferenceNumber from NTFS logs.
3. Search same FileReferenceNumber for earlier `File_Renamed_Old` or `File_Created` events.
4. Establish that both names refer to the same file record; earlier name `mimikatz.exe`.

### Scheduled Task Validation

Artifact:
`...\Windows\System32\Tasks\spawn`

Extract:
- `<Date>` (registration) and `<StartBoundary>` values
- `<Exec>` `Command` and `Arguments`, recorded as separate fields
- `<Author>` context

Recorded:
- `<Date>`: 2022-11-11 16:25:49, no `Z` or numeric offset stated
- `<StartBoundary>`: 2022-11-11 20:10:00, no `Z` or numeric offset stated
- `Command`: value ending in `\Downloads\Telegram`
- `Arguments`: `Desktop\Minecraft.exe`

### Service-Based Persistence

Registry Path:
HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule

Recorded:
- Service key present
- `ImagePath`: `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
- `Start`: 2, `ObjectName`: LocalSystem

No surviving artifact shows the service executing.

### User Creation Validation

Security Event ID:
4720

Recorded:
- New account: cpitter
- Timestamp: 2022-11-11 21:23:51 UTC; the Event Log Explorer view displays a UTC indicator

No surviving artifact shows subsequent use of the account.

## 4. Reproducibility Notes

- Timestamps are recorded on the basis each source attests. No offset is inferred and no
  value is converted using the host timezone setting. Three sources attest UTC: the
  supplied Sysmon view, the Event Log Explorer view, and the NTFS `EventTime (UTC 0)`
  column. Task XML values, NTFS export rows and UserAssist displays state no offset. The
  [Timeline](timeline-utc.md) carries the full breakdown.
- Indicators defanged where appropriate.
- Only metadata documented in this repository.
- No live malware samples stored in repo.
