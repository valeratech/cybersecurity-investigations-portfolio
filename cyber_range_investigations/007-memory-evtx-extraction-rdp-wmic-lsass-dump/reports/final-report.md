# Final Investigation Report

**Document Type:** Final Report  
**Case Title:** Memory EVTX Extraction, RDP Intrusion, WMIC Lateral Movement, Recovered LSASS Dump Command  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Documentation Started:** 2026-02-26  
**Documentation Last Updated:** 2026-09-22  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

A Windows 10 memory image (`Server.raw`, profile `Win10x64_17763`) supplied by the range
was analysed with Volatility 2.6.1. Windows event logs were carved from memory with the
`dumpfiles` plugin, which yielded `.vacb` cache fragments rather than complete `.evtx`
files; the fragments were renamed and parsed with EvtxECmd for review in Timeline Explorer.
Command-line artifacts were recovered separately from a `strings64.exe` pass over the
image.

The reconstructed records establish an accepted RDP connection from an internal address,
creation of four files under two directories, a service configured to auto-start an
encoded PowerShell command, and two command strings recovered from memory — one directing
a full memory dump of `lsass.exe`, one invoking WMIC against a second internal host. An
event payload ties WMIC activity and that remote host to an Administrator subject SID.

Execution is not established for any staged binary, for the service payload, for the
dumping command, or for the WMI operation. Those limits are stated against each finding
below rather than summarised away, and no case-level confidence is assigned.

## 2. Scope and Evidence Reviewed

Evidence reviewed:

- `Server.raw`, the supplied memory image (EV-001)
- EVTX artifacts extracted from memory (ART-001) and the `.evtx` files reconstructed from
  `.vacb` fragments (ART-002)
- CSV output parsed with EvtxECmd (ART-003)
- Memory strings output (ART-004)

Provenance labels used below: **observed** in an artifact; **range-supplied** by the
scenario or question wording; **range-accepted** as the answer recorded for a numbered
question; **analyst inference**; and **not established**.

The investigation scope statement is recorded in
[Evidence Register](../evidence-metadata/evidence-register.md).

## 3. Time Basis

### Values with an explicit UTC warrant

- `imageinfo`: `Image date and time : 2025-05-27 09:30:20 UTC+0000`, with local value
  `2025-05-27 02:30:20 -0700`.
- Sysmon records carry a `UtcTime` field; all Sysmon-derived times here come from it.
### Values recorded without a timezone designation

- The RDP-CoreTS record carries `Time Created 2025-05-27 09:21:40`. The surviving excerpt
  supplies no timezone field; the value is preserved as recorded, with no conversion or UTC
  basis asserted.

### Range-accepted at minute precision

- The image timestamp, recorded as `2025-05-27 09:30`.

### Values with no recorded time

- The service creation payload, both recovered command strings, and the WMIC-related event
  payloads. These are reported without clock positions.

No time conversion was applied. The recorded image timestamp bounds what the image can
contain; it does not establish that activity ceased at that moment.

## 4. Findings

### 4.1 RDP connection accepted from an internal address

Observed: RDP-CoreTS `Event ID 131` at `2025-05-27 09:21:40` records
`RDP server accepted a new TCP connection` from `192[.]168[.]19[.]159:64984`.
Range-accepted: the source address `192[.]168[.]19[.]159`.

Two port values survive: the range-accepted answer `64989, 3389`, and the observed
payload values — client `64984`, service `3389`. Both are preserved; whether they describe
the same connection or a different perspective on it is not established.

Not established: authenticated interactive logon. The event records connection acceptance
only, and the session premise is range-supplied.

### 4.2 File staging under two directories

Observed: Sysmon Event ID 11 records, image `C:\Windows\Explorer.EXE`, process ID 1844,
user `WIN-2O66FDBAHOG\Administrator`:

- `09:21:58` — `DD.exe`, `SB.exe`, `tt.exe`, `n1.ps1` created under
  `C:\Users\Public\Downloads\N1\N1\`
- `09:22:22` — the same four names created under
  `C:\Users\Default\AppData\Local\Temp\N1\`

Not established: whether the second set was copied, moved or written separately, and
whether any of the four executed. No process-creation record survives for them.

### 4.3 Renamed discovery tool

Range-accepted: `SB.exe` corresponds to `Seatbelt.exe`.

Observed: a file named `SB.exe`, first at `2025-05-27 09:21:58`.

Not established: the rename operation, identification of the binary from telemetry, and
any motive for the naming. No hash, signature or execution record survives for it.

### 4.4 Service configured for persistence

Observed: a service creation record carrying `ServiceName: FireFox Update`,
`ImagePath: C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"`,
`ServiceType: user mode service`, `StartType: auto start`, `AccountName: LocalSystem`. The
encoded command decodes to `Start-Process -FilePath 'C:\ProgramData\chocolatey\tt.exe'`.

Not established: the creation time, whether the service started, and whether the encoded
command ran. A PowerShell script-policy test file created at `09:23:45` shows a PowerShell
process active on the host but is not tied to this service.

The service name appears as `Firefox Update` in analyst prose and `FireFox Update` in the
payload; the payload value is authoritative.

### 4.5 Credential-dumping command recovered

Range-accepted and observed in the memory strings output:

```
C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
```

The switches direct a full memory dump of `lsass.exe` to `mm.tmp`.

Not established: execution, creation of `mm.tmp`, and any credential material obtained.
`mm.tmp` is a path named inside the command string, not an independently observed file.

### 4.6 Lateral movement command and remote target

Range-accepted and observed in the memory strings output:

```
wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
```

Observed: event payloads naming `C:\Windows\System32\wbem\WMIC.exe` with
`IpAddress 192[.]168[.]19[.]163` and `IpPort 49667`, and `svchost.exe` with the same
address and `IpPort 135`.

Not established: the WMI operation requested, and the outcome on the remote host. The
recovered string carries connection switches only — no verb, alias or class.

### 4.7 Account context

Observed: `SubjectUserSid S-1-5-21-2346552008-2584940806-3566241850-500`,
`SubjectUserName: Administrator`, `SubjectDomainName: WIN-2O66FDBAHOG`, with
`TargetUserName: noah` and `TargetServerName: DESKTOP-U98A16J`.

Range-accepted: that SID is the recorded answer for the account-attribution question.

Not established: that the subject SID accounts for every action reported here. The subject
and target accounts are distinct and are preserved as such.

### 4.8 Unattributed activity on 2025-05-26

Observed: browser downloads of `DumpIt.exe` and `winpmem_mini_x64_rc2.exe` by
`WIN-2O66FDBAHOG\Administrator`, creation of `DumpIt.sys` under
`C:\Windows\SysWOW64\drivers\`, creation of
`WIN-2O66FDBAHOG-20250526-123246.raw`, and creation of
`C:\Users\Administrator\Tools\DumpIt.exe`.

Not established: who directed this activity. These are memory-acquisition utilities, and
the record neither attributes them to the intruder nor documents authorised administrative
work.

## 5. ATT&CK Alignment

Analyst inference. No technique identifier appears in the investigation record; the
mappings below are the analyst's alignment of observed artifacts to the framework, each
carrying the limit that applies to it.

| Technique | Basis | Evidentiary limit |
|---|---|---|
| T1021.001 — Remote Services: RDP | Accepted RDP TCP connection at `09:21:40` | Connection only; no authenticated session established |
| T1543.003 — Create or Modify System Process: Windows Service | Service creation record with auto-start configuration | Configuration only; no start recorded |
| T1059.001 — Command and Scripting Interpreter: PowerShell | Encoded PowerShell command configured as the service image path | Configured command; execution not demonstrated |
| T1003.001 — OS Credential Dumping: LSASS Memory | `DD.exe` command string targeting `lsass.exe` | Command string only; execution and output not established |
| T1047 — Windows Management Instrumentation | `WMIC.exe` process and remote target in event payloads | Operation requested not established |

## 6. Conclusion

The examined artifacts establish: an RDP TCP connection accepted from
`192[.]168[.]19[.]159`; creation of `DD.exe`, `SB.exe`, `tt.exe` and `n1.ps1` under two
directories within about twenty-four seconds; a service named `FireFox Update` configured
to auto-start an encoded PowerShell command targeting `C:\ProgramData\chocolatey\tt.exe`;
a recovered command string directing a full LSASS memory dump to `mm.tmp`; a recovered
WMIC command string naming `192[.]168[.]19[.]163` with the account `noah`; and event
payloads placing `WMIC.exe` and that remote host under an Administrator subject SID.

They do not establish execution of any staged binary, a service start, execution of the
encoded command, completion of the LSASS dump, the WMI operation requested, or the outcome
on the remote host. The activity recorded on 2025-05-26 is not attributed.

## 7. Limitations

- The supplied artifact set was the memory image alone. No disk image, packet capture or
  external log source was supplied for analysis; this records the scope of the supplied
  artifacts, not the nonexistence of others.
- Event coverage is partial by construction: the logs were reconstructed from `.vacb`
  cache fragments, and the size of the gap is not measurable from the record.
- No hash of `Server.raw` is recorded, and the value is not available.
- The service creation record, both recovered command strings, and the WMIC-related
  payloads carry no timestamp, so they hold no position in the sequence.
- Creation events do not establish execution; no process-creation record survives for the
  staged binaries.
- The rename step from `.vacb` to `.evtx` is documented as an example approach rather than
  a transcript of the exact commands run, so the reconstruction is not reproducible
  command-for-command from the record.
- The notes contain, under an "Example Format" label, a `DD.exe` command line writing the
  2025-05-26 `.raw` file. Whether it was observed or illustrative is not established, and
  no finding rests on it.
- Matters outside the question set — the fate of `mm.tmp`, the content of `n1.ps1`,
  activity on `DESKTOP-U98A16J`, and impact on other hosts — were not examined.

## Related Documents

- [Case Overview](../README.md)
- [Initial Findings](../analysis/initial-findings.md)
- [Timeline](../analysis/timeline.md)
- [Intake](../case-notes/intake.md)
- [Evidence Register](../evidence-metadata/evidence-register.md)
