# Initial Findings

**Document Type:** Findings Summary  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Provenance Labels

Each finding states what the surviving record carries:

- **Observed** — present in an event record, command string or tool output in the notes.
- **Range-supplied** — stated by the scenario or by the wording of a question.
- **Range-accepted** — the answer recorded as accepted for a numbered question.
- **Analyst inference** — derived by the analyst from observed data.
- **Not established** — the record does not support the statement.

Each finding carries its provenance label and its evidentiary limit. No confidence rating
is assigned, at case level or per finding.

## Executive Summary

The memory image yielded reconstructed event records and recovered command strings
describing an RDP connection from an internal address, file staging under two directories,
a service configured for auto-start with an encoded PowerShell image path, an
LSASS-dumping command, and a WMIC command naming a second internal host.

Execution is not demonstrated for any of the staged binaries, the service payload, the
dumping command or the WMI operation. Those limits are stated in each finding rather than
summarised away.

## Finding 1 — Recorded Image Timestamp

**Observed.** Volatility `imageinfo` reports:

```
Image date and time : 2025-05-27 09:30:20 UTC+0000
Image local date and time : 2025-05-27 02:30:20 -0700
```

**Range-accepted.** `2025-05-27 09:30`.

The value is what the image records about itself. It is not an independently documented
acquisition event, and it does not establish that attacker activity ceased at that time.
It does bound what the image could contain.

## Finding 2 — RDP Ingress Source

**Observed.** An RDP-CoreTS record, `Event ID 131`, `2025-05-27 09:21:40`,
`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`, on computer
`WIN-2O66FDBAHOG`, map description `RDP server accepted a new TCP connection`, remote host
`192[.]168[.]19[.]159:64984`, `Connection Type: TCP`.

**Range-accepted.** The internal source address is `192[.]168[.]19[.]159`.

**Not established.** Successful interactive authentication. The event records acceptance
of a TCP connection. The premise that a session followed is range-supplied by the question
wording.

## Finding 3 — RDP Port Values: Two Sources, Not Reconciled

Two values survive and both are recorded here:

| Value | Source | Label |
|---|---|---|
| `64989, 3389` | Answer recorded for the port question | Range-accepted |
| client `64984`, service `3389` | RDP-CoreTS event payload | Observed |

**Not established.** Whether the two refer to the same connection, or to different
perspectives on it. No reconciliation is attempted, and neither value is discarded.

## Finding 4 — Staged Files

**Observed.** Sysmon Event ID 11 file-creation records, image `C:\Windows\Explorer.EXE`,
process ID 1844, user `WIN-2O66FDBAHOG\Administrator`:

- `2025-05-27 09:21:58` — `C:\Users\Public\Downloads\N1\N1\` containing `DD.exe`,
  `SB.exe`, `tt.exe` and `n1.ps1`
- `2025-05-27 09:22:22` — `C:\Users\Default\AppData\Local\Temp\N1\` containing the same
  four names

**Not established.** Whether the second set was copied, moved or separately written, and
whether any of the four executed. Only creation events survive.

## Finding 5 — Renamed Discovery Tool

**Range-accepted.** `SB.exe` corresponds to `Seatbelt.exe`.

**Observed.** A file named `SB.exe` created at the paths and times in Finding 4. The
earliest occurrence anywhere in the record is `2025-05-27 09:21:58`.

**Not established.** The rename operation, the binary's identity from telemetry, and any
motive. No hash, signature, version string or execution record for `SB.exe` survives.

## Finding 6 — Service Persistence Configuration

**Observed.** A service creation record carrying:

- `ServiceName: FireFox Update`
- `ImagePath: C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"`
- `ServiceType: user mode service`
- `StartType: auto start`
- `AccountName: LocalSystem`

The encoded command decodes to `Start-Process -FilePath 'C:\ProgramData\chocolatey\tt.exe'`.

**Not established.** The creation time of the service, whether it started, and whether the
configured PowerShell command ran. The surviving payload carries no timestamp field. A
PowerShell script-policy test file created at `2025-05-27 09:23:45` shows a PowerShell
process active on the host, but does not tie that process to this service.

The service name appears as `Firefox Update` in the analyst prose and `FireFox Update` in
the payload. The payload spelling is authoritative here.

## Finding 7 — Credential-Dumping Command Recovered

**Range-accepted and observed** in the `strings64.exe` output taken from `Server.raw`:

```
C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
```

Switches: `-accepteula`; `-ma lsass.exe` requesting a full memory dump of `lsass.exe`;
output path `mm.tmp`.

**Not established.** That the command executed, that `mm.tmp` was written, or that
credential material was obtained. A string recovered from memory records an intent
expressed on the command line, not a completed operation.

## Finding 8 — Lateral Movement Command and Target

**Range-accepted and observed** in the same strings output:

```
wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
```

**Observed.** Event payloads name `C:\Windows\System32\wbem\WMIC.exe` with
`IpAddress 192[.]168[.]19[.]163` and `IpPort 49667`, and a second record naming
`C:\Windows\System32\svchost.exe` with the same address and `IpPort 135`.

**Not established.** Which WMI operation was requested or whether it succeeded. The
recovered string carries connection switches only — no verb, alias or class — so neither
remote process enumeration nor remote execution follows from it.

The credential in the original command is withheld from published content.

## Finding 9 — Account Context

**Observed.** The event payload records `SubjectUserSid`
`S-1-5-21-2346552008-2584940806-3566241850-500`, `SubjectUserName: Administrator`,
`SubjectDomainName: WIN-2O66FDBAHOG`, with `TargetUserName: noah`,
`TargetDomainName: WIN-2O66FDBAHOG` and `TargetServerName: DESKTOP-U98A16J`.

**Range-accepted.** The SID above is the answer recorded for the account-attribution
question.

**Not established.** That this subject SID accounts for every action reported in this
case. The correlation exists in the WMIC-related records. The subject account and the
target account are distinct and are preserved as such.

## Finding 10 — Activity on 2025-05-26 Is Unattributed

**Observed.** On `2025-05-26`: browser downloads of `DumpIt.exe` (12:32:40) and
`winpmem_mini_x64_rc2.exe` (12:42:30) by `WIN-2O66FDBAHOG\Administrator`; creation of
`C:\Windows\SysWOW64\drivers\DumpIt.sys` (12:32:48); creation of
`C:\Users\Administrator\Downloads\WIN-2O66FDBAHOG-20250526-123246.raw` (12:32:48); and
creation of `C:\Users\Administrator\Tools\DumpIt.exe` (12:48:06) by `Explorer.EXE`.

**Not established.** Who directed this activity. These are memory-acquisition utilities
and the record neither attributes them to the intruder nor documents them as authorised
administrative work. The final event is a file creation; no move or rename artifact
survives.

## Assessment

What the record establishes:

1. An RDP TCP connection from `192[.]168[.]19[.]159` was accepted at `09:21:40`.
2. Four files were created under `C:\Users\Public\Downloads\N1\N1\` at `09:21:58` and
   under `C:\Users\Default\AppData\Local\Temp\N1\` at `09:22:22`.
3. A service named `FireFox Update` was configured to auto-start an encoded PowerShell
   command targeting `C:\ProgramData\chocolatey\tt.exe`.
4. An LSASS-dumping command string and a WMIC command string naming
   `192[.]168[.]19[.]163` were recovered from memory.
5. A WMIC process and that remote target appear in an event payload under an
   Administrator subject SID.

What it does not establish: execution of any staged binary, start of the service,
execution of the encoded command, completion of the LSASS dump, the WMI operation
requested, the outcome on the remote host, and attribution of the 2025-05-26 activity.

These limits are terminal. They record what the examined artifacts support, not work left
undone.
