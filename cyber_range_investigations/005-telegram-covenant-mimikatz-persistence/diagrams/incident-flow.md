# Incident Flow Diagram (Outline)

**Document Type:** Analysis  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Purpose and Construction Rule

Provide a reproducible outline suitable for later conversion to Mermaid, draw.io, or
PowerPoint.

**Construction rule.** Nodes below are grouped by artifact class, not sequenced into a
causal chain. The previous version of this outline ordered stages so that a Telegram
stage preceded a tool-transfer stage, which asserted a causal relationship the artifacts
do not establish. Where a sequence is drawn, it must be drawn only between events whose
sources attest a comparable time basis.

Timestamps carry their attested basis. Values whose source states no offset are marked
accordingly and are not converted using the host timezone setting.

## 2. Entities

- **Host:** MAGENTA (polo[.]shirts[.]corp)
- **Profile in which activity is recorded:** Administrator
- **Telegram-named entries observed:** `Telegram Desktop`, `Telegram.exe`
- **Payload:** Minecraft.exe (identified as Covenant by hash enrichment)
- **Credential tool:** mimikatz.exe (renamed to svchost.exe)
- **Persistence artifacts:** cleanup-schedule (service configuration), \spawn (task definition)
- **Target data:** Credentials.txt
- **Remote host/share:** 10[.]10[.]5[.]86 (UNC share)
- **Recorded network destination:** 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`)

## 3. Range-Supplied Framing (not a flow stage)

The CyberRange briefing describes a suspected insider incident and states that Telegram
was used to download the executable. It separately raises monitoring evasion as a
conditional hypothesis rather than an assertion.
These are shown separately from the artifact groups below and must not be rendered as
nodes in the observed flow.

## 4. Observed Artifact Groups

### Group A — Payload path associations

Three artifacts carry the literal full path `...\Downloads\Telegram Desktop\Minecraft.exe`:

- Supplied Sysmon `Image` value
- Service `ImagePath`
- UserAssist program path

One further artifact associates the same material across two separate fields, and does
not carry the literal path:

- Scheduled task `Exec` action: `Command` value ending in `\Downloads\Telegram`,
  `Arguments` value `Desktop\Minecraft.exe`

No artifact records the transfer operation itself.

### Group B — Network activity

Provenance: CyberRange-supplied Sysmon/Splunk view preserved as a screenshot. The
underlying raw Sysmon event log is not available.

- Sysmon Event ID 3, Network Connect, by `Minecraft.exe`
- `TimeCreated` 2022-11-11 21:16:22.351523300 UTC (source field ends in `Z`), `UtcTime` 2022-11-11 21:16:21.185
- Destination 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`)
- Session content not recorded

### Group C — Telegram-named NTFS entries

- LSN 3980112160, 21:54:56 UTC 0, Directory Creation, `Telegram Desktop`
- LSN 3980134702, 21:54:57 UTC 0, File Creation, `Telegram.exe`
- LSN 3980703330, 21:55:24 UTC 0, Directory Creation, `Telegram Desktop`

Parent path not exposed by the view; these cannot be bound to the Downloads path in
Group A. The adjacent analyst transcription conflicts with the view for LSN 3980134702.

### Group D — Application usage (offset unestablished)

- `...\AppData\Roaming\Telegram Desktop\Telegram.exe` — run count 4, focus time 383811 ms
- `...\Downloads\Telegram Desktop\Minecraft.exe` — run count 3, focus time 187452 ms

### Group E — Credential tool staging and rename (offset unestablished)

- `mimikatz.exe` created in Downloads
- Renamed to `svchost.exe`, correlated by shared FileReferenceNumber

### Group F — Account, service and task artifacts

- Account `cpitter` created, Security 4720, 2022-11-11 21:23:51 UTC (Event Log Explorer view displays a UTC indicator)
- Service configuration `cleanup-schedule`, `ImagePath` to the payload, `Start` 2, `ObjectName` LocalSystem
- Task definition `\spawn`, registration 16:25:49 and StartBoundary 20:10:00, both offset unestablished

No surviving artifact shows subsequent use of the account, execution of the service, or
execution of the task.

### Group G — Credential file access attempt

- Security 4663 against `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`
- Subject `Account Name: Administrator`, process `dllhost.exe`, captured `Type: Audit Success`
- Offset unestablished

### Group H — Remote share artifacts

Two artifact classes, recording different things:

- ShellBags (NTUSER.DAT): a remote network location involving host 10[.]10[.]5[.]86
- LNK / LECmd output: the file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1`

The full file path is established by the LNK evidence, not by ShellBags.

### Group I — Context artifacts

- A Recent-item LNK named `Invoke-UserSimulator.ps1.lnk` exists.
- LNK-derived output references Splunk Universal Forwarder and Sysmon paths.

These establish the presence of the named artifacts and host instrumentation. They do
not establish that the named script executed or that it relates to the activity above.

## 5. Diagram Nodes (Suggested Labels)

Neutral labels. None asserts a transfer, an intent, or an actor.

- "Sysmon alert: binary path flagged (range-supplied)"
- "Sysmon Event 3: TCP connect to port 80 by Minecraft.exe"
- "NTFS: Telegram-named entries, parent path unknown"
- "UserAssist: Telegram.exe usage recorded"
- "UserAssist: Minecraft.exe execution recorded"
- "Minecraft.exe identified as Covenant (hash enrichment)"
- "mimikatz.exe created"
- "Rename mimikatz.exe -> svchost.exe"
- "Service configuration: cleanup-schedule"
- "Task definition: \\spawn"
- "Account created: cpitter"
- "Access attempt: Credentials.txt"
- "Remote share path recorded: lansweeper.ps1"

## 6. Rendering Constraints

1. Do not connect Group C to Group A with an arrow; the parent-path link is unproven.
2. Do not place offset-unestablished events on the same time axis as UTC-attested events.
3. Render the range-supplied framing in Section 3 as an annotation, never as a node.
4. Do not label any node with intent, actor class, or "established" persistence.

Unresolved evidentiary items are carried in the Limitations sections of the
[Timeline](../analysis/timeline-utc.md) and
[Final Report](../reports/final-report.md).
