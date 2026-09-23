# Investigation Report

**Document Type:** Case Overview  
**Case Title:** Memory EVTX Extraction, RDP Intrusion, WMIC Lateral Movement, Recovered LSASS Dump Command  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Documentation Started:** 2026-02-26  
**Documentation Last Updated:** 2026-09-22  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Scope

This investigation covers analysis of the provided Windows memory image (`Server.raw`).
The supplied artifact set was that image alone. No disk image, packet capture or external
log source was supplied for analysis.

Claims below carry a provenance label:

- **Observed** — recorded in an event record, command string or tool output captured in the analyst notes.
- **Range-supplied** — stated by the scenario briefing or by the wording of a question.
- **Range-accepted** — the answer recorded as accepted for a numbered question.
- **Analyst inference** — derived by the analyst from observed data.
- **Not established** — the surviving record does not support the statement.

## Case Contents

### Analysis

- [Initial Findings](analysis/initial-findings.md)
- [Timeline](analysis/timeline.md)

### Case Notes

- [Intake](case-notes/intake.md)

### Evidence Metadata

- [Evidence Register](evidence-metadata/evidence-register.md)

### Reports

- [Final Report](reports/final-report.md)
- [Reports Index](reports/README.md)

## 1. Overview

### Objective

- Identify the recorded image capture time
- Extract Windows Event Logs (EVTX) from memory
- Reconstruct `.vacb` log fragments
- Identify attacker tooling and renamed binaries
- Identify a credential-dumping command
- Identify a service-based persistence configuration
- Identify lateral movement activity
- Associate the reported activity with a user SID

### Scenario Summary

Range-supplied: a client reported a suspected compromise across several on-premises
machines, and a memory image from one affected system was provided for analysis.

Primary investigative focus was extraction of EVTX artifacts from memory using Volatility
and correlation of the resulting event records.

### Key Focus Areas

- Memory Forensics  
- Event Log Reconstruction  
- RDP Activity Analysis  
- Credential Dumping  
- Persistence Configuration  
- Lateral Movement  

## 2. Environment & Tools Used

### Environment Description

- CyberDefenders module: Memory Forensics Module
- OS Profile: `Win10x64_17763`
- Hostname: `WIN-2O66FDBAHOG`
- Memory Image: `Server.raw`
- Recorded image timestamp (UTC): `2025-05-27 09:30:20`

### Tools & Frameworks

**Memory Analysis**
- Volatility Framework 2.6.1  
  - `imageinfo`
  - `kdbgscan`
  - `dumpfiles`

**Event Log Processing**
- EvtxECmd (Eric Zimmerman)
- Timeline Explorer

**Artifact Processing**
- PowerShell
- `strings64.exe`

**Binaries named in recovered artifacts**
- `WMIC.exe`
- `cmd.exe`
- `powershell.exe`

## 3. Evidence Collected

### Evidence Artifacts

- Memory image: `Server.raw`
- EVTX artifacts extracted from memory with `dumpfiles`
- `.vacb` fragments renamed to `.evtx` for parsing
- CSV output parsed with EvtxECmd and reviewed in Timeline Explorer
- Memory strings output from `strings64.exe`

## 4. Analysis & Findings

### 4.1 Recorded Image Timestamp

Observed: Volatility `imageinfo` reports `Image date and time : 2025-05-27 09:30:20 UTC+0000`
and a local value of `2025-05-27 02:30:20 -0700`.

Range-accepted: `2025-05-27 09:30`.

The value is the timestamp the image records for itself. It is not an independently
documented acquisition or chain-of-custody event, and it does not establish that all
attacker activity ended at that moment.

### 4.2 RDP Ingress

Observed: an RDP-CoreTS event (`Event ID 131`, `2025-05-27 09:21:40`) records
`RDP server accepted a new TCP connection` with client `192[.]168[.]19[.]159:64984`
and `Connection Type: TCP`.

Range-accepted: the internal source address is `192[.]168[.]19[.]159`.

The event records an accepted TCP connection. Successful interactive authentication is
range-supplied by the wording of the questions and is not established by this event.

### 4.3 RDP Port Values — Conflicting Sources Preserved

Two source values exist and are not reconciled here:

| Value | Source |
|---|---|
| `64989, 3389` | Range-accepted answer recorded for the port question |
| `64984` client port, `3389` service port | Observed in the RDP-CoreTS event payload |

Whether the two describe the same connection, or the same perspective on it, is not
established.

### 4.4 Tool Staging

Observed: Sysmon Event ID 11 records file creation at `2025-05-27 09:21:58` under
`C:\Users\Public\Downloads\N1\N1\` — `DD.exe`, `SB.exe`, `tt.exe` and `n1.ps1` — by
`C:\Windows\Explorer.EXE` running as `WIN-2O66FDBAHOG\Administrator`.

Observed: further creation of `DD.exe`, `SB.exe`, `tt.exe` and `n1.ps1` at `09:22:22`
under `C:\Users\Default\AppData\Local\Temp\N1\`.

Not established: whether the second set was copied, moved or separately written. Only
creation events survive.

### 4.5 Renamed Discovery Tool

Range-accepted: `SB.exe` corresponds to `Seatbelt.exe`.

Observed: a file named `SB.exe` created at the paths and times in 4.4.

Not established: the rename operation itself, the binary's identity from telemetry, and
any motive for the naming. No hash, signature or execution record for `SB.exe` survives.

### 4.6 Service Persistence Configuration

Observed: a service creation record carrying `ServiceName: FireFox Update`,
`ImagePath: C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"`,
`ServiceType: user mode service`, `StartType: auto start`, `AccountName: LocalSystem`.
The decoded command is `Start-Process -FilePath 'C:\ProgramData\chocolatey\tt.exe'`.

Not established: the time the service was created, whether the service started, and
whether the configured PowerShell command ran. The record carries configuration, not
execution.

The analyst prose in the notes renders the name as `Firefox Update`; the payload value is
`FireFox Update` and is used here.

### 4.7 Credential-Dumping Command

Range-accepted and observed in the memory strings output:

```
C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
```

The switches direct a full memory dump of `lsass.exe` to `mm.tmp`.

Not established: that the command executed, that a dump file was produced, or that any
credential material was obtained. `mm.tmp` is the output path named inside the command
string, not an independently observed file.

### 4.8 Lateral Movement

Range-accepted and observed in the memory strings output:

```
wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
```

Observed: an event payload naming `C:\Windows\System32\wbem\WMIC.exe` with
`IpAddress 192[.]168[.]19[.]163`, alongside a second record naming
`C:\Windows\System32\svchost.exe` for the same target.

Not established: which WMI operation was requested. The recovered string carries
connection switches only, with no verb, alias or class, so neither remote enumeration nor
remote execution is demonstrated by it.

### 4.9 Account Context

Observed: the event payload records `SubjectUserSid`
`S-1-5-21-2346552008-2584940806-3566241850-500` with `SubjectUserName: Administrator`
and `SubjectDomainName: WIN-2O66FDBAHOG`. The same payload records
`TargetUserName: noah` and `TargetServerName: DESKTOP-U98A16J`.

Range-accepted: the SID above is the answer recorded for the account-attribution question.

Not established: that this subject SID accounts for every action described in this case.
The correlation exists for the WMIC-related records, not across the whole timeline.

### 4.10 Activity on 2025-05-26 — Unattributed

Observed on `2025-05-26`: browser downloads of `DumpIt.exe` and
`winpmem_mini_x64_rc2.exe` by `WIN-2O66FDBAHOG\Administrator`, creation of
`C:\Windows\SysWOW64\drivers\DumpIt.sys`, creation of
`WIN-2O66FDBAHOG-20250526-123246.raw`, and creation of
`C:\Users\Administrator\Tools\DumpIt.exe`.

These are memory-acquisition utilities. The surviving record neither attributes them to
the intruder nor establishes them as authorised administrative activity. They are
reported as unattributed host activity.

## 5. Indicators of Compromise (Defanged)

### IP Addresses
- `192[.]168[.]19[.]159` — source of the accepted RDP connection
- `192[.]168[.]19[.]163` — target named in the WMIC command and event payloads

### Service Configuration
- `FireFox Update` — service name in the service-creation record

### Files Observed Created
- `C:\Users\Public\Downloads\N1\N1\DD.exe`
- `C:\Users\Public\Downloads\N1\N1\SB.exe`
- `C:\Users\Public\Downloads\N1\N1\tt.exe`
- `C:\Users\Public\Downloads\N1\N1\n1.ps1`

### Paths Named Inside Recovered Command Strings
- `C:\Users\Default\AppData\Local\Temp\mm.tmp` — output path in the `DD.exe` command
- `C:\ProgramData\chocolatey\tt.exe` — target of the decoded service command

## 6. MITRE ATT&CK Alignment

Analyst inference. These mappings are the analyst's alignment of observed artifacts to the
framework. No technique identifier appears anywhere in the surviving record.

| Technique | Basis in this case | Evidentiary limit |
|---|---|---|
| T1021.001 — Remote Services: RDP | Accepted RDP TCP connection recorded | Connection only; no authenticated session established |
| T1543.003 — Create or Modify System Process: Windows Service | Service creation record with auto-start configuration | Configuration only; no service start recorded |
| T1059.001 — Command and Scripting Interpreter: PowerShell | Encoded PowerShell command configured as the service image path | Configured command; execution not demonstrated |
| T1003.001 — OS Credential Dumping: LSASS Memory | `DD.exe` command string targeting `lsass.exe` recovered from memory | Command string only; execution and output not established |
| T1047 — Windows Management Instrumentation | `WMIC.exe` process and remote target recorded; command string recovered | Operation requested is not established |

## 7. Limitations

- The supplied artifact set was the memory image alone. No disk image, packet capture or
  external log source was supplied, and this states the scope of what was analysed rather
  than what exists elsewhere.
- EVTX artifacts were reconstructed from `.vacb` fragments, so event coverage is partial
  by construction. The extent of the gap is not measurable from the surviving record.
- No hash of `Server.raw` is recorded in the investigation record. The value is not
  available and is not a pending item.
- Execution is not demonstrated for the service payload, the `DD.exe` command or the
  WMIC command. Each survives as configuration or as a recovered string.
- The notes contain, under an "Example Format" label, a `DD.exe` command line writing the
  `2025-05-26` `.raw` file. Whether that line was observed or illustrative is not
  established, and no claim rests on it.

## 8. Evidence Boundary

- The question set defined what was examined. Topics outside it — including the fate of
  `mm.tmp`, the content of `n1.ps1`, activity on `DESKTOP-U98A16J`, and any impact on
  other hosts — were not examined and are not open items.
- Causal connection between the staged files, the service configuration and the recovered
  commands is a range-supplied proposition rather than an observed chain.
- Where the record carries two values for one question, both are preserved in 4.3 rather
  than reconciled.

## 9. Conclusion

The record establishes an accepted RDP connection from an internal address, creation of
four staged files under two directories, a service configured to launch an encoded
PowerShell command, a recovered LSASS-dumping command string, a recovered WMIC command
naming a second internal host, and an event payload tying WMIC activity to an
Administrator subject SID.

It does not establish execution of the staged tooling, the service payload, the dumping
command or any WMI operation, and it does not establish the outcome of the lateral
movement attempt.

## 10. Case Status

**Status:** Complete  
