# Final Investigation Report

**Document Type:** Final Report  
**Case Title:** Disk Forensics — Telegram, Covenant, mimikatz masquerade, and persistence artifacts  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Documentation Started:** 2026-02-18  
**Documentation Last Updated:** 2026-02-18  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

A forensic triage image was analyzed following a threat-hunting alert. This report
separates what the exercise environment supplied from what the artifacts record, and
states where the two cannot be reconciled from the surviving record.

**Range-supplied framing.** The CyberRange briefing describes a suspected insider
incident, and states that Telegram was used to download an executable. It
further raises, conditionally, that the brief Telegram usage might indicate download-only
use and an attempt to evade network monitoring. The first is a range-supplied assertion;
the second is a range-supplied hypothesis. Both originate in the exercise material and are
retained here only as attributed framing.

**Observed artifacts.** A supplied Sysmon view records an outbound TCP connection to port 80 by
`Minecraft.exe` from a path containing `Telegram Desktop`. A service configuration and a
UserAssist entry name the same full path, and UserAssist additionally records execution
of that payload. A scheduled-task definition carries `Command` and `Arguments` values
that associate the same material across two fields. NTFS journal data records entries
named `Telegram Desktop` and `Telegram.exe`, without exposing their parent path. The
`Minecraft.exe` hash was submitted to a threat-intelligence platform, which returned a
Covenant identification. `mimikatz.exe` was created and later renamed to `svchost.exe`,
the rename correlated by a shared NTFS FileReferenceNumber. Event 4720 records creation
of the `cpitter` account. An object-access event records an attempt against a file named
`Credentials.txt`. ShellBags record a remote network location and LNK artifacts record a
file path on that share.

**What the artifacts do not establish.** Three artifacts carry the literal payload path
and a fourth associates the same material across two fields. None establishes that
Telegram performed the download. The record does not establish what content traversed the
observed connection, who initiated the recorded execution, whether the service or task
ran, or the intent behind any action. Several timestamps carry no established offset, and one
cross-artifact relationship cannot be bound: the recorded UTC timestamps can be compared,
but the NTFS entries cannot be tied to the directory in the Sysmon executable path. See Section 8.

## 2. Scope and Evidence Reviewed

The investigation used a structured triage artifact set located at:

`C:\Users\Administrator\Desktop\Start Here\Artifacts\`

Artifacts reviewed:

- SYSTEM and SOFTWARE registry hives
- NTUSER.DAT (Administrator)
- Windows Security Event Log (Security.evtx)
- NTFS metadata ($MFT, $LogFile, $UsnJrnl/$J)
- Scheduled task XML definitions
- LNK shortcut artifacts
- ShellBags artifacts

One further evidence item is supplied rather than recovered: a CyberRange-supplied
Sysmon/Splunk view, preserved as a screenshot. The underlying raw Sysmon event log is not
available. Its supplied provenance is stated at every point of use.

No live system interaction occurred. Analysis was performed offline.

## 3. System Baseline

| Attribute | Value |
|-----------|--------|
| Hostname | MAGENTA |
| Domain (defanged) | polo[.]shirts[.]corp |
| Windows Build | 14393 |
| Timezone setting (artifact) | Eastern Standard Time |
| Host IP (defanged) | 10[.]10[.]5[.]113 |
| Remote share host (defanged) | 10[.]10[.]5[.]86 |

Last recorded shutdown value: 2021-07-30 15:25:38, as the Registry Explorer Data
Interpreter displays it, at the precision the tool shows.

## 4. Time Basis

Each timestamp is reported on the basis its source attests. No offset is inferred, and no
value is converted using the host timezone setting.

**Counting unit.** The table below counts *timestamp values*, not events. One event can
carry more than one value: the supplied Sysmon record carries two distinct UTC fields.

### Values with an explicit UTC warrant

| Value | Event | Source warrant |
|---|---|---|
| 2022-11-11 21:16:22.351523300 | Sysmon Event 3 `TimeCreated` | supplied view records the field ending in `Z` |
| 2022-11-11 21:16:21.185 | Sysmon Event 3 `UtcTime` | event-data field, named as UTC |
| 2022-11-11 21:23:51 | Account `cpitter` created (4720) | Event Log Explorer view displays a UTC indicator |
| 2022-11-11 21:54:56 | NTFS Directory Creation, `Telegram Desktop` | `EventTime (UTC 0)` column |
| 2022-11-11 21:54:57 | NTFS File Creation, `Telegram.exe` | `EventTime (UTC 0)` column |
| 2022-11-11 21:55:24 | NTFS Directory Creation, `Telegram Desktop` | `EventTime (UTC 0)` column |

The two Sysmon fields differ by approximately 1.17 seconds. Both are preserved; neither is
selected as the event time.

### Values with no established offset

| Value | Event | Why unestablished |
|---|---|---|
| 2022-11-11 21:44:29 | `mimikatz.exe` created | NTFS export rows carry no offset column |
| 2022-11-11 21:47:23 | `mimikatz.exe` data modification | NTFS export rows carry no offset column |
| 2022-11-11 21:48:08 | Rename to `svchost.exe` | NTFS export rows carry no offset column |
| 2022-11-11 19:55:51 | Object access attempt (4663) | capture cropped, no timezone indicator visible |
| 2022-11-11 20:10:00 | Task `\spawn` StartBoundary | task XML value carries no `Z` or numeric offset |
| 2022-11-11 16:25:49 | Task `\spawn` registration date | task XML value carries no `Z` or numeric offset |
| 11/11/2022 9:21:15 PM | UserAssist, `Telegram.exe` | 12-hour display, no timezone indicator |
| 11/11/2022 9:23:13 PM | UserAssist, `Minecraft.exe` | 12-hour display, no timezone indicator |
| 11/11/2022 9:52:56 PM | UserAssist, `gkape.exe` / `kape.exe` | 12-hour display, no timezone indicator |

The three NTFS mimikatz values retain their internal order, which the source establishes.
They are not placed in a single ordered sequence with the UTC-attested values.

## 5. Findings

### 5.1 Supplied Network Telemetry

A CyberRange-supplied Sysmon/Splunk view records Event ID 3, Network Connect, for
`Minecraft.exe`. The screenshot is surviving telemetry evidence; the underlying raw
Sysmon event log is not available.

| Field | Value |
|---|---|
| Image | `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe` |
| Event ID | 3 (Network Connect) |
| `TimeCreated` | 2022-11-11 21:16:22.351523300 UTC; the source field ends in `Z` |
| `UtcTime` | 2022-11-11 21:16:21.185 |
| Destination IP (defanged) | 3[.]125[.]209[.]94 |
| Destination hostname (defanged) | ec2-3-125-209-94[.]eu-central-1[.]compute[.]amazonaws[.]com |
| Protocol | `tcp` |
| Destination port | 80 |
| `DestinationPortName` | `http` - a port-to-service label, not protocol inspection |
| Source (defanged) | 10[.]10[.]5[.]113 port 65431 |
| Process ID | 4328 |
| Computer | MAGENTA |

The destination is an AWS EC2 hostname recorded in the supplied screenshot. Its current
DNS state was not measured and is not asserted.

This event establishes that the executable made an outbound TCP connection to port 80,
which the event labels `http`. No HTTP request or response data is recorded, so it does
not establish that HTTP was used or what content traversed the connection. The Covenant identification in Section 5.3
comes from a separate hash-based enrichment procedure and is not merged with this event.

### 5.2 Telegram-Named NTFS Entries

The surviving NTFS Log Tracker view records three entries under an `EventTime (UTC 0)`
column:

| LSN | EventTime (UTC 0) | Event | Name |
|---|---|---|---|
| 3980112160 | 2022-11-11 21:54:56 | Directory Creation | Telegram Desktop |
| 3980134702 | 2022-11-11 21:54:57 | File Creation | Telegram.exe |
| 3980703330 | 2022-11-11 21:55:24 | Directory Creation | Telegram Desktop |

The view exposes leaf names only and the parent path is not available. The recorded UTC timestamps can be compared, but the NTFS entries cannot be bound to
the directory in the Sysmon executable path. Consequently, the surviving evidence does
not establish a same-directory creation sequence or a chronological contradiction.

The adjacent analyst transcription in the surviving record describes LSN 3980134702 as
creation of `Telegram Desktop`; the view records it as creation of `Telegram.exe`. The
conflict is recorded here and is not resolved in either direction.

### 5.3 Payload Identification

The file `Minecraft.exe` was hashed:

b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5

The analyst submitted this hash to a threat-intelligence platform and recorded a Covenant
identification from the returned community data and a YARA match. This is analyst-derived
enrichment of a file hash, not host telemetry.

### 5.4 Application Usage

UserAssist records the following, with timezone offset unestablished for every value:

| Program | Run count | Last execution | Focus time |
|---|---|---|---|
| `...\AppData\Roaming\Telegram Desktop\Telegram.exe` | 4 | 11/11/2022 9:21:15 PM | 383811 ms |
| `...\Downloads\Telegram Desktop\Minecraft.exe` | 3 | 11/11/2022 9:23:13 PM | 187452 ms |

The same artifact records `gkape.exe` and `kape.exe` executions at 11/11/2022 9:52:56 PM.
These are forensic-tool executions, separated here from the incident-behavior findings.
The surviving record does not identify the operator or bind them to the triage
acquisition.

The range briefing raises, conditionally, that the short Telegram usage window might
indicate download-only use and monitoring evasion. That is a range-supplied hypothesis,
not a range assertion, and it is not adopted here. The artifact establishes run counts and
focus times; it does not establish purpose, launch mechanism, or who initiated the
recorded executions.

### 5.5 Credential Tool Staging and Rename

`mimikatz.exe` was created in the Downloads directory and subsequently renamed to
`svchost.exe`. NTFS journal records for both filenames share a FileReferenceNumber, which
establishes that the two names refer to the same file record rather than two separate
files.

### 5.6 Account, Service and Task Artifacts

Event 4720 directly records creation of the `cpitter` account. The service and task below
are configuration and definition artifacts; the surviving record does not independently
establish who created them.

#### Account
- Event ID 4720
- Account: cpitter
- 2022-11-11 21:23:51 UTC; the Event Log Explorer view displays a UTC indicator

#### Service configuration
- Service name: cleanup-schedule
- Registry path: HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule
- `ImagePath`: `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
- `Start`: 2
- `ObjectName`: LocalSystem

#### Scheduled task definition
- Task: `\spawn`
- Registration date recorded in task XML: 2022-11-11 16:25:49, no offset stated
- StartBoundary recorded in task XML: 2022-11-11 20:10:00, no offset stated
- `Exec` action fields, recorded separately as the XML carries them:
  - `Command`: value ending in `\Downloads\Telegram`
  - `Arguments`: `Desktop\Minecraft.exe`

No surviving artifact shows subsequent use of the `cpitter` account, execution of the
`cleanup-schedule` service, or execution of the `\spawn` task.

#### Payload path associations

Three artifacts carry the literal full path
`C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`: the supplied Sysmon
`Image` value, the service `ImagePath`, and the UserAssist program path. A fourth, the
task `Exec` action, associates the same material across two separate fields and does not
carry the literal path. None of the four establishes how the payload arrived there.

### 5.7 Credential File Access Attempt

Security Event ID 4663 records an access attempt against:

`C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`

The event subject is `Account Name: Administrator`; the recorded process is
`dllhost.exe`. The captured event `Type` is `Audit Success`. The range question
characterizes this attempt as unsuccessful; the captured event does not support that
characterization. The timestamp offset for this event is unestablished.

### 5.8 Remote Share Artifacts

Two artifact classes record different things:

- ShellBags (NTUSER.DAT): a remote network location involving host 10[.]10[.]5[.]86
- LNK / LECmd output: the file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1`

The full file path is established by the LNK evidence, not by ShellBags.

### 5.9 Context Artifacts

- A Recent-item LNK named `Invoke-UserSimulator.ps1.lnk` exists.
- LNK-derived output references Splunk Universal Forwarder and Sysmon paths.

These establish the presence of the named artifacts and host instrumentation. They do not
establish that the named script executed, that it produced any activity described above,
or that it relates to the activity described here at all.

## 6. ATT&CK Alignment

Technique mappings, their provenance classes and their dispositions are maintained in
[MITRE ATT&CK Mapping](../analysis/mitre-attack-mapping.md), pinned to ATT&CK Enterprise
v19.2. Of ten parent techniques, two are dispositioned ESTABLISHED, one ANALYTIC, and
seven NOT ESTABLISHED.

## 7. Conclusion

The artifacts record: an outbound TCP connection to port 80 by `Minecraft.exe` from a
Telegram-named path; a service configuration and a UserAssist entry naming the same full
path; execution of `Minecraft.exe` under the Administrator profile; a task definition
associating the same material across two fields; NTFS entries named `Telegram Desktop`
and `Telegram.exe` whose parent path is unknown; a payload hash identified externally as
Covenant; staging and rename of a credential-dumping tool; creation of the `cpitter`
account; an access attempt against a credential file; and a remote network location with
a file path on that share.

The artifacts do not establish that Telegram performed the download, what content
traversed the observed connection, who initiated the recorded execution, whether any
persistence mechanism ran, or the intent or actor class behind the activity. Propositions
the artifacts do not support originate in the exercise briefing and are retained above
only as attributed framing.

## 8. Limitations

1. **Two time bases are present and are not merged.** Six timestamp values carry an
   explicit UTC warrant. Nine carry no established offset. They are reported as recorded
   and are not converted using the host's Eastern Standard Time setting.
2. **The task XML timestamps cannot be normalized.** Neither `<Date>` nor
   `<StartBoundary>` states an offset. The host timezone artifact is Eastern Standard
   Time, but applying it would be inference, not normalization.
3. **The NTFS entries cannot be bound to the payload path.** The surviving view exposes
   leaf names only. The recorded UTC timestamps can be compared, but the NTFS entries
   cannot be bound to the directory in the Sysmon executable path. Consequently, the
   surviving evidence does not establish a same-directory creation sequence or a
   chronological contradiction.
4. **A transcription conflict in the source record is unresolved.** For LSN 3980134702
   the analyst transcription and the artifact view disagree about what was created. The
   record is evidence and has not been edited.
5. **The two Sysmon UTC fields differ.** `TimeCreated` and `UtcTime` are approximately
   1.17 seconds apart. Both are preserved rather than reconciled, and no cross-artifact
   interval is calculated from either.
6. **Execution is recorded; initiation is not.** UserAssist establishes that
   `Minecraft.exe` ran under the Administrator profile. It does not establish the launch
   mechanism or that a human initiated it.
7. **No use or execution evidence survives** for the `cpitter` account, the
   `cleanup-schedule` service, or the `\spawn` task. Absence in this record is not
   evidence that they were never used.
8. **Raw Sysmon telemetry is unavailable.** Section 5.1 rests on a supplied screenshot.
   It cannot be re-queried, filtered, or corroborated against the original log.
9. **Range-supplied propositions cannot be independently verified.** The exercise
   environment is permanently closed.

## 9. Portfolio Note

This investigation demonstrates registry forensics, NTFS journal correlation, masquerade
detection by file-record identity, event log analysis, LNK and ShellBags analysis with
separated provenance, threat-intelligence enrichment, ATT&CK mapping that distinguishes
evidence provenance from technique disposition, and documentation of evidentiary limits
including an unresolved transcription conflict and an unbindable cross-artifact
relationship.

## Related Documents

- [Case Overview](../README.md)
- [Timeline](../analysis/timeline-utc.md)
- [Evidence Inventory](../evidence-metadata/evidence-log.md)
- [MITRE ATT&CK Mapping](../analysis/mitre-attack-mapping.md)
