# MITRE ATT&CK Mapping

**Document Type:** Analysis  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document maps recorded behaviors to MITRE ATT&CK tactics and techniques.

Canonical ATT&CK technique names are retained as terminology. Retaining a name does not
import its narrative: each technique below states what supports it, and whether that
support is an observed artifact, analyst-derived enrichment, or range-supplied framing.
Timestamps are reported on the basis their source attests; values whose source states no
offset are marked accordingly.

**ATT&CK version.** Mapped against ATT&CK Enterprise content **v19.2**, retrieved from
attack.mitre.org on 2026-09-15. Tactic names and memberships below are those published at
that version. Two changes matter for this case: TA0005 is named **Stealth** at v19.2
(previously Defense Evasion, same tactic ID), and Enterprise now carries 15 tactics
including TA0112 Defense Impairment. A reader comparing this mapping against an older
ATT&CK release will see different tactic labels for the same technique IDs.

Mappings are made at **parent technique level** throughout. This is an intentional
reporting choice for consistency across the portfolio, not a claim that the evidence
everywhere falls short of sub-technique specificity — in some places it would support a
sub-technique identifier. Parenthetical behavior notes have been removed from technique
names so the document does not claim one level while naming another.

**Two dimensions are used, and they are not interchangeable.**

*Provenance class* describes where a piece of evidence came from:

| Class | Meaning |
|---|---|
| OBSERVED | recorded in a recovered or supplied artifact |
| DERIVED | analyst enrichment of an artifact value, such as a hash lookup |
| RANGE-SUPPLIED | asserted by the exercise briefing or question text, not by an artifact |
| OBSERVED CONTEXT | an artifact that bears on the technique without supporting it |

*Mapping disposition* describes whether the technique itself is established:

| Disposition | Meaning |
|---|---|
| ESTABLISHED | an artifact records the behavior the technique names |
| ANALYTIC | a defensible association drawn from artifacts, not a recorded behavior |
| NOT ESTABLISHED | evidence relates to the technique but does not record its behavior |

An OBSERVED artifact never makes a technique ESTABLISHED on its own. The question is
always whether the artifact records *the behavior the technique names*.

## Techniques

### T1105 – Ingress Tool Transfer

**ATT&CK tactics:** Command and Control

**Mapping disposition: NOT ESTABLISHED.**

The technique names a transfer operation. No artifact records one. The path associations
below establish that the payload resided at a Telegram-named path; they do not establish
how it arrived there.

| Support | Detail |
|---|---|
| OBSERVED | Sysmon `Image` value, literal full path `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe` (supplied screenshot) |
| OBSERVED | Service `ImagePath` naming the same full path |
| OBSERVED | UserAssist row for the same full path |
| OBSERVED | Task `Exec` action associating the same material across two separate fields: `Command` ending in `\Downloads\Telegram`, `Arguments` `Desktop\Minecraft.exe`. This artifact does not carry the literal full path. |
| OBSERVED | NTFS entries named `Telegram Desktop` and `Telegram.exe`, parent path not exposed |
| RANGE-SUPPLIED | that Telegram was used to download the executable |

The technique is listed because the case's range framing asserts it and a reader will
expect to find it addressed, not because the artifacts support it.

### T1059 – Command and Scripting Interpreter

**ATT&CK tactics:** Execution

**Mapping disposition: NOT ESTABLISHED.**

| Support | Detail | Class |
|---|---|---|
| LNK / LECmd output records the file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` | full path established by LNK evidence | OBSERVED |
| ShellBags records a remote network location involving 10[.]10[.]5[.]86 | host context, not the file path | OBSERVED |

A `.ps1` file path is recorded. No artifact records a script interpreter executing. The
range record asks which file the attacker accessed on the remote share; it supplies no
proposition about staging or post-exploitation use.

### T1204 – User Execution

**ATT&CK tactics:** Execution

**Mapping disposition: NOT ESTABLISHED.** Execution of `Minecraft.exe` is ESTABLISHED;
the human initiation the technique names is not.

| Support | Detail | Class |
|---|---|---|
| UserAssist row for `...\Downloads\Telegram Desktop\Minecraft.exe`: run count 3, last execution 11/11/2022 9:23:13 PM, focus time 187452 ms, offset unestablished | execution and usage recorded under the Administrator profile | OBSERVED |
| UserAssist row for `...\AppData\Roaming\Telegram Desktop\Telegram.exe`: run count 4, focus time 383811 ms, offset unestablished | separate program, separate row | OBSERVED |
| A Recent-item LNK named `Invoke-UserSimulator.ps1.lnk` exists | a shortcut bearing that name; nothing more | OBSERVED CONTEXT |
| LNK-derived output references Splunk Universal Forwarder and Sysmon paths | host instrumentation present | OBSERVED CONTEXT |

UserAssist records execution and usage of `Minecraft.exe` under the Administrator
profile. It does not establish the launch mechanism and does not establish that a human
initiated it, which is the behavior T1204 names. The record does not establish whether
`Invoke-UserSimulator.ps1` executed, whether any simulator produced the `Minecraft.exe`
activity, or that the context artifacts relate to the activity described here at all.

### T1136 – Create Account

**ATT&CK tactics:** Persistence

**Mapping disposition: ESTABLISHED.** Event 4720 records the behavior the technique names.

| Support | Detail |
|---|---|
| OBSERVED | Security Event ID 4720, account `cpitter`, 2022-11-11 21:23:51 UTC |

The Event Log Explorer view displays a UTC indicator. No surviving artifact shows
subsequent use of the account.

### T1543 – Create or Modify System Process

**ATT&CK tactics:** Persistence, Privilege Escalation

**Mapping disposition: NOT ESTABLISHED.** A service configuration is recorded; no artifact
records its creation event or its execution.

| Support | Detail |
|---|---|
| OBSERVED | `HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule` |
| OBSERVED | `ImagePath` `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`, `Start` 2, `ObjectName` LocalSystem |

A service configuration is present. No surviving artifact shows the service executing.

### T1053 – Scheduled Task/Job

**ATT&CK tactics:** Execution, Persistence, Privilege Escalation

**Mapping disposition: NOT ESTABLISHED.** A task definition is recorded; no artifact records
its creation event or its execution.

| Support | Detail |
|---|---|
| OBSERVED | Task definition `\spawn` |
| OBSERVED | `<Date>` 2022-11-11 16:25:49, offset unestablished |
| OBSERVED | `<StartBoundary>` 2022-11-11 20:10:00, offset unestablished |
| OBSERVED | `Exec` action fields recorded separately as the XML carries them |

A task definition is present. No surviving artifact shows the task executing.

### T1036 – Masquerading

**ATT&CK tactics:** Stealth (TA0005 at v19.2)

**Mapping disposition: ESTABLISHED.** The rename to a system process name is recorded and
correlated by file-record identity.

| Support | Detail |
|---|---|
| OBSERVED | `mimikatz.exe` renamed to `svchost.exe` |
| OBSERVED | NTFS journal correlation via shared FileReferenceNumber |

The rename is established by file-record identity. The NTFS export rows carry no offset
column.

### T1003 – OS Credential Dumping

**ATT&CK tactics:** Credential Access

**Mapping disposition: NOT ESTABLISHED.** Tool presence and an access attempt are recorded;
no artifact records a credential-dumping operation.

| Support | Detail |
|---|---|
| OBSERVED | `mimikatz.exe` present on disk before rename |
| OBSERVED | Event ID 4663 object access against `Credentials.txt`, subject `Account Name: Administrator`, process `dllhost.exe`, captured `Type: Audit Success`, offset unestablished |
| RANGE-SUPPLIED | that the access attempt was unsuccessful |

Tool staging and an access attempt are recorded. No artifact records a credential-dumping
operation, and the captured event does not support the unsuccessful characterization.

### T1021 – Remote Services

**ATT&CK tactics:** Lateral Movement

**Mapping disposition: NOT ESTABLISHED.** Path artifacts are recorded; no artifact records
use of a remote service.

| Support | Detail | Class |
|---|---|---|
| ShellBags records a remote network location involving 10[.]10[.]5[.]86 | host context | OBSERVED |
| LNK / LECmd output records the file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` | full path established here, not by ShellBags | OBSERVED |
| the range record refers to the file the attacker accessed on the remote share | actor characterization | RANGE-SUPPLIED |

Shell and shortcut artifacts record a network location and a file path. They do not
record what was done with either.

### T1071 – Application Layer Protocol

**ATT&CK tactics:** Command and Control

**Mapping disposition: ANALYTIC.** The supplied Sysmon view records an outbound TCP
connection to port 80, which the event labels `http` through its `DestinationPortName`
field - a port-to-service mapping, not protocol inspection. No HTTP request or response
data is recorded. Together with the payload's identification as a C2 framework by hash
enrichment, an application-layer protocol association is defensible as analytic. Actual
HTTP use, and C2 use of the connection, are unverified.

| Support | Detail |
|---|---|
| OBSERVED | Sysmon Event ID 3, Network Connect, by `Minecraft.exe`, destination 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`), `TimeCreated` 2022-11-11 21:16:22.351523300 UTC (source field ends in `Z`), `UtcTime` 2022-11-11 21:16:21.185 (supplied screenshot) |
| DERIVED | Covenant identification from VirusTotal community data and a YARA match on the file hash |

An outbound TCP connection to port 80 by the executable is recorded. No payload content
of the connection is recorded, so the artifacts do not establish that HTTP was used or
that the connection carried C2 traffic. The
Covenant identification comes from hash enrichment and is not merged with the network
event.

## ATT&CK Summary Table

Disposition is the controlling column. Evidence provenance is in the per-technique tables
above and does not appear here, so that an observed artifact cannot be read as an
established technique.

| ATT&CK tactics (v19.2) | ID | Technique Name | Strongest support | Disposition |
|---|---|---|---|---|
| Command and Control | T1105 | Ingress Tool Transfer | three full-path associations plus one split-field association | NOT ESTABLISHED |
| Execution | T1059 | Command and Scripting Interpreter | `lansweeper.ps1` path in LNK output | NOT ESTABLISHED |
| Execution | T1204 | User Execution | UserAssist run count and focus time | NOT ESTABLISHED |
| Persistence | T1136 | Create Account | Event ID 4720 | ESTABLISHED |
| Persistence, Privilege Escalation | T1543 | Create or Modify System Process | service key and `ImagePath` | NOT ESTABLISHED |
| Execution, Persistence, Privilege Escalation | T1053 | Scheduled Task/Job | task definition XML | NOT ESTABLISHED |
| Stealth | T1036 | Masquerading | FileReferenceNumber correlation | ESTABLISHED |
| Credential Access | T1003 | OS Credential Dumping | tool presence, Event ID 4663 | NOT ESTABLISHED |
| Lateral Movement | T1021 | Remote Services | ShellBags location, LNK file path | NOT ESTABLISHED |
| Command and Control | T1071 | Application Layer Protocol | Sysmon Event ID 3 | ANALYTIC |

Two techniques are ESTABLISHED, one is ANALYTIC, and seven are NOT ESTABLISHED. That
distribution is the honest result of asking, for each technique, whether an artifact
records the behavior the technique names.

## Analytical Assessment

The artifacts record a set of file, registry, event log and shell entries consistent
with staging of offensive tooling, a rename to a system process name, creation of an
account, configuration of a service and a task, an access attempt against a credential
file, a remote network location with a file path on that share, and an outbound TCP
connection to port 80 by the payload.

What the artifacts do not establish: the transfer mechanism, the intent behind any
action, the actor class, whether the persistence mechanisms ran, and what content
traversed the observed connection. The briefing characterizes the activity as insider
misuse; that characterization is range-supplied and is not adopted here.

Unresolved evidentiary items are carried in the Limitations sections of the
[Timeline](timeline-utc.md) and [Final Report](../reports/final-report.md).
