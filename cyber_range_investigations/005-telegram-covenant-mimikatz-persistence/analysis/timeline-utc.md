# Unified Timeline

**Document Type:** Timeline  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Evidence Basis

This timeline consolidates timestamps from:

- Registry artifacts (SYSTEM / SOFTWARE hives)
- NTFS metadata ($LogFile, $MFT, $UsnJrnl/$J)
- Windows Security Event Logs (Security.evtx)
- Scheduled Task XML
- UserAssist (NTUSER.DAT)
- LNK analysis (LECmd) and ShellBags
- A CyberRange-supplied Sysmon/Splunk view preserved as a screenshot

Each entry is reported on the time basis its source attests. No offset is inferred, and no
value is converted using the host's Eastern Standard Time setting. Entries whose offset is
unestablished are held in a separate section rather than interleaved with UTC-attested
events, because interleaving them would assert an ordering the record does not support.

**Counting unit.** Sections below list *timestamp values*. One event may carry more than
one value: the supplied Sysmon record carries two distinct UTC fields.

| Source warrant | Basis |
|---|---|
| Supplied Sysmon view, `TimeCreated` field ending in `Z` | UTC |
| Supplied Sysmon view, `UtcTime` event-data field | UTC |
| Event Log Explorer view displaying a UTC indicator | UTC |
| NTFS Log Tracker `EventTime (UTC 0)` column | UTC |
| NTFS export rows with no offset column | unestablished |
| Cropped event capture with no timezone indicator | unestablished |
| Task XML value with no `Z` or numeric offset | unestablished |
| UserAssist 12-hour display with no timezone indicator | unestablished |

The former publication of this case placed all recovered timestamps into a single UTC
sequence. That normalization was not supported by the record and has been withdrawn.

## Observations — UTC-Attested Values

### 2022-11-11 21:16:22.351523300 UTC — and 21:16:21.185 UTC
**Event:** Network connect by `Minecraft.exe` (Sysmon Event ID 3)  
**Image:** `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`  
**Destination (defanged):** 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`)  
**Destination hostname (defanged):** ec2-3-125-209-94[.]eu-central-1[.]compute[.]amazonaws[.]com  
**Source (defanged):** 10[.]10[.]5[.]113 port 65431  
**Process ID:** 4328  
**Provenance:** CyberRange-supplied telemetry view, preserved as a screenshot. The
underlying raw Sysmon event log is not available.  
**Warrant:** The view records `TimeCreated SystemTime` ending in `Z` and a separate
`UtcTime` event-data field. The two differ by approximately 1.17 seconds. Both are
preserved; neither is selected as the event time.  
**Observation:** An outbound TCP connection to port 80 by the executable, labelled `http`
by `DestinationPortName`. No HTTP request or response data is recorded.

### 2022-11-11 21:23:51 UTC
**Event:** New local user account created  
**Account:** cpitter  
**Event ID:** 4720  
**Source:** Security.evtx  
**Warrant:** Event Log Explorer view displays a UTC indicator above the record list.  
**Observation:** Account creation artifact. No surviving artifact shows subsequent use of
the account.

### 2022-11-11 21:54:56 / 21:54:57 / 21:55:24 UTC
**Event:** Three NTFS journal entries bearing Telegram-related names  
**Source:** NTFS Log Tracker, `$LogFile` search result  
**Warrant:** The view carries an `EventTime (UTC 0)` column.

| LSN | EventTime (UTC 0) | Event | Name |
|---|---|---|---|
| 3980112160 | 2022-11-11 21:54:56 | Directory Creation | Telegram Desktop |
| 3980134702 | 2022-11-11 21:54:57 | File Creation | Telegram.exe |
| 3980703330 | 2022-11-11 21:55:24 | Directory Creation | Telegram Desktop |

**Observation:** The view exposes leaf names only and the parent path is not available.
The recorded UTC timestamps can be compared, but the NTFS entries cannot be bound to
the directory in the Sysmon executable path. Consequently, the surviving evidence does
not establish a same-directory creation sequence or a chronological contradiction. The adjacent analyst transcription describes LSN 3980134702 as
creation of `Telegram Desktop`; the view records `Telegram.exe`. See Limitations.

## Observations — Offset Unestablished

These entries are reported exactly as the source records them. Their position relative to
the UTC-attested values above cannot be determined from the surviving record.

### NTFS sequence, internal order established by the source

The three entries below carry no offset in the surviving NTFS export. Their order relative
to one another is established by the source; their relationship to the UTC-attested values
is not.

#### 2022-11-11 21:44:29 [offset unestablished]
**Event:** `mimikatz.exe` created in Downloads directory  
**Source:** NTFS export, File_Created  
**Observation:** Credential-dumping tool present on disk.

#### 2022-11-11 21:47:23 [offset unestablished]
**Event:** Data modification to `mimikatz.exe`  
**Source:** NTFS export, Data_Added / Data_Truncated  
**Observation:** File record modified.

#### 2022-11-11 21:48:08 [offset unestablished]
**Event:** Rename `mimikatz.exe` to `svchost.exe`  
**Source:** NTFS export, File_Renamed_Old / File_Renamed_New  
**Correlation Key:** shared FileReferenceNumber  
**Observation:** Both names refer to the same file record, not two separate files.

### 2022-11-11 19:55:51 [offset unestablished]
**Event:** Object access attempt  
**Target File:** `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`  
**Event ID:** 4663  
**Subject:** Account Name: Administrator  
**Process:** `dllhost.exe`  
**Captured Type:** Audit Success  
**Source:** Security.evtx  
**Warrant:** The surviving capture is cropped to the record row and its description pane;
no timezone indicator is visible.  
**Observation:** An access attempt against a file named `Credentials.txt` is recorded.

### 2022-11-11 20:10:00 [offset unestablished]
**Event:** Scheduled task `\spawn` StartBoundary  
**Source:** Task XML (`System32\Tasks\spawn`)  
**Field:** `<StartBoundary>`  
**Warrant:** The XML value carries no `Z` and no numeric offset.  
**Observation:** Configured first-run time.

### 2022-11-11 16:25:49 [offset unestablished]
**Event:** Scheduled task `\spawn` registration date  
**Source:** Task XML  
**Field:** `<Date>` within `<RegistrationInfo>`  
**Warrant:** The XML value carries no `Z` and no numeric offset.  
**Observation:** Task registration artifact. The task's `Exec` action carries a `Command`
value ending in `\Downloads\Telegram` and an `Arguments` value of `Desktop\Minecraft.exe`.

### 11/11/2022 9:21:15 PM [offset unestablished]
**Event:** UserAssist last-execution value for `Telegram.exe`  
**Program:** `C:\Users\Administrator\AppData\Roaming\Telegram Desktop\Telegram.exe`  
**Run count:** 4  **Focus time:** 383811 ms  
**Source:** NTUSER.DAT (UserAssist)  
**Warrant:** 12-hour display with no timezone indicator visible.  
**Observation:** Program execution and usage recorded under the Administrator profile.

### 11/11/2022 9:23:13 PM [offset unestablished]
**Event:** UserAssist last-execution value for `Minecraft.exe`  
**Program:** `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`  
**Run count:** 3  **Focus time:** 187452 ms  
**Source:** NTUSER.DAT (UserAssist)  
**Warrant:** 12-hour display with no timezone indicator visible.  
**Observation:** Execution and usage of the payload recorded under the Administrator
profile. The artifact does not record the launch mechanism or who initiated it.

### 11/11/2022 9:52:56 PM [offset unestablished]
**Event:** UserAssist entries for `gkape.exe` and `kape.exe`  
**Source:** NTUSER.DAT (UserAssist)  
**Observation:** Forensic-tool executions, separated here from the incident-behavior
entries. The surviving record does not identify the operator or bind these executions to
the triage acquisition.

## Undated Observations

### ShellBags
**Observation:** A remote network location involving host 10[.]10[.]5[.]86 is recorded in
NTUSER.DAT. ShellBags records the network location, not a file path.

### LNK / LECmd
**Observation:** The file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` is recorded in
LNK metadata. The full file path is established here, not by ShellBags.

### Context artifacts
**Observation:** A Recent-item LNK named `Invoke-UserSimulator.ps1.lnk` exists, and
LNK-derived output references Splunk Universal Forwarder and Sysmon paths. These establish
the presence of the named artifacts and host instrumentation only.

## Supporting Context

### Host Network Configuration
- Host IP: 10[.]10[.]5[.]113
- Remote share host: 10[.]10[.]5[.]86
- DHCP server: 10[.]10[.]5[.]1
- DNS server: 10[.]10[.]4[.]159
- Gateway MAC: 16-1C-22-77-E5-9C

### Earlier Registry Value
A recorded last-shutdown value of 2021-07-30 15:25:38 appears in the registry artifacts,
reported at the precision the Registry Explorer Data Interpreter displays.

## Limitations

1. **Two time bases are present and are not merged.** Six timestamp values carry an
   explicit UTC warrant; nine carry no established offset. They are held in separate
   sections because ordering them together would assert a sequence the record does not
   support.
2. **The task XML timestamps cannot be normalized.** Neither `<Date>` nor
   `<StartBoundary>` states an offset. Applying the host's Eastern Standard Time setting
   would be inference, not normalization.
3. **The NTFS Telegram-named entries cannot be bound to the payload path.** The view
   exposes leaf names only. The recorded UTC timestamps can be compared, but the NTFS
   entries cannot be bound to the directory in the Sysmon executable path. Consequently,
   the surviving evidence does not establish a same-directory creation sequence or a
   chronological contradiction.
4. **A transcription conflict is unresolved.** For LSN 3980134702 the analyst
   transcription describes creation of `Telegram Desktop` while the artifact view records
   `Telegram.exe`. The record is evidence and has not been edited; the conflict is
   recorded rather than resolved in either direction.
5. **The two Sysmon UTC fields differ** by approximately 1.17 seconds. Both are preserved
   and no cross-artifact interval is calculated from either.
6. **The NTFS mimikatz values are not UTC-attested.** The export rows carry no offset
   column. Their internal order is preserved; their position against the UTC-attested
   values is not asserted. The former publication placed them in a unified UTC sequence,
   which the record does not support.
7. **UserAssist records execution, not initiation.** The artifact establishes that
   `Minecraft.exe` ran under the Administrator profile. It does not establish the launch
   mechanism or that a human initiated it, and the record does not establish whether
   `Invoke-UserSimulator.ps1` executed or relates to this activity.
8. **Raw Sysmon telemetry is unavailable.** The 21:16:22 entry rests on a supplied
   screenshot and cannot be re-queried or corroborated against the original log.
9. **Range-supplied propositions are attributed, not adopted.** The briefing asserts that
   Telegram was used to download the payload, and separately raises monitoring evasion as
   a conditional hypothesis. Neither is adopted here. Three artifacts carry the literal payload path and a fourth
   associates the same material across two fields; none establishes the transfer itself.
10. **No use or execution evidence survives** for the `cpitter` account, the
    `cleanup-schedule` service, or the `\spawn` task.

## Related Documents

- [Case Overview](../README.md)
- [Final Report](../reports/final-report.md)
- [Evidence Inventory](../evidence-metadata/evidence-log.md)
- [MITRE ATT&CK Mapping](mitre-attack-mapping.md)
