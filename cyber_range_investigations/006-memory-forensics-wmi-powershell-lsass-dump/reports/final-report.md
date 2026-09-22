# Final Investigation Report

**Document Type:** Final Report  
**Case Title:** WmiPrvSE-Spawned PowerShell and a Masqueraded LSASS Dump Invocation  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Documentation Started:** 2026-02-24  
**Documentation Last Updated:** 2026-09-21  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

A Windows 10 memory image supplied by the range was analysed with Volatility 2.6.1.

**Observed.** The process tree records `WmiPrvSE.exe` (PID 1944) as the parent of
`powershell.exe` (PID 5104). A second `lsass.exe` process (PID 1576, alongside the
legitimate PID 656), running from `C:\Windows\` rather than `System32`, carries the command line
`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp` and a recorded parent PID of 5104.
netscan records an ESTABLISHED TCP entry to `10[.]0[.]128[.]2:4337` with no owning process.
An MFT entry for `Windows\System32\svchost.bat` carries a `$STANDARD_INFORMATION` creation
value of `2023-02-03 13:25:04 UTC`.

**Range-confirmed.** The exercise states that the customer network was breached, that the
renamed process is a Sysinternals tool, that `svchost.bat` was created by the attacker and
communicated with `10[.]0[.]128[.]2:4337`, and it accepted `2023-02-03 13:23` as the time
of compromise.

**Not established.** Completion of the LSASS dump, the existence or location of
`lsass.dmp`, any credential compromise, the process owning the connection, and the
content or execution of `svchost.bat`.

## 2. Scope and Evidence Reviewed

- Windows memory image (`memory.dmp`), range-supplied
- Volatility output retained in the analyst's notes: `imageinfo`, `kdbgscan`, `pstree`,
  `psxview`, `cmdline`, `psinfo`, `netscan`, `mftparser`
- Range-supplied `strings_out.txt`, parsed for the Q8 answer (the parse command is not recorded)
- Range question text, hints and accepted answers

Not performed: `pslist`, `filescan`, `dumpfiles`, `handles`, `dlllist`, process dumping,
and file recovery with R-Studio.

## 3. Time Basis

Each value below is reported as the tool rendered it. No offset is inferred.

**Counting unit.** The table counts *timestamp values*, not events.

### Values with an explicit UTC warrant

| Value (UTC) | Event | Warrant |
| :--- | :--- | :--- |
| 2023-02-03 13:10:37 | `WmiPrvSE.exe` (PID 1944) created | pstree row rendered `UTC+0000` |
| 2023-02-03 13:23:40 | `powershell.exe` (PID 5104) and `conhost.exe` (PID 896) created | pstree rows rendered `UTC+0000` |
| 2023-02-03 13:25:04 | `$STANDARD_INFORMATION` values, `svchost.bat` | mftparser row rendered `UTC+0000` |
| 2023-02-03 13:29:30 | `lsass.exe` (PID 1576) created | psinfo field rendered `UTC+0000` |
| 2023-02-03 13:29:33 | Memory image timestamp | imageinfo `Image date and time` rendered `UTC+0000` |

imageinfo also reports the image's local time as `2023-02-03 05:29:33 -0800`. It is
recorded, not used for conversion.

### Range-accepted answers (minute precision)

| Accepted value (UTC) | Question | Relation to recorded values |
| :--- | :--- | :--- |
| 2023-02-03 13:23 | "When did the compromise occur?" (range-accepted) | matches the minute of PID 5104's creation |
| 2023-02-03 13:25 | Creation time of `svchost.bat` (range-accepted) | matches the minute of the MFT `$STANDARD_INFORMATION` value |

The accepted answers are range-confirmed values. They are not independent observations.

## 4. Findings

### 4.1 Process Lineage

Observed: `svchost.exe` (PID 884) → `WmiPrvSE.exe` (PID 1944) → `powershell.exe`
(PID 5104) → `conhost.exe` (PID 896). The command line of PID 5104 was not recorded.
The WMI method, consumer or caller that produced PID 5104 is not recorded.

### 4.2 Masqueraded lsass.exe and the Dump Invocation

Observed: two `lsass.exe` entries in psxview. PID 656 runs
`C:\Windows\system32\lsass.exe` and is present in `pslist`. PID 1576 runs from
`C:\Windows\lsass.exe`, is absent from `pslist` and `psscan`, is present in `thrdproc`,
and has no exit time. psinfo reports `Parent Process: NA PPID: 5104`: the parent PID is
recorded and the parent image was not resolved by the plugin; pstree identifies PID 5104 as
`powershell.exe` at capture.

Range-confirmed: the process is a renamed Sysinternals tool.

Analyst inference: `-accepteula -ma 656 lsass.dmp` matches ProcDump syntax for a full
memory dump of PID 656 to `lsass.dmp`.

Conclusion: a dump of the legitimate LSASS process was invoked. Its outcome is not
established.

### 4.3 Network Connection at Capture

Observed: TCPv4 `10[.]0[.]128[.]0:63944` → `10[.]0[.]128[.]2:4337`, `ESTABLISHED`, owner
PID `-1`. No owning process and no creation time are recorded.

Range-confirmed: the exercise treats this as the malicious session and
`10[.]0[.]128[.]2:4337` as the endpoint used by `svchost.bat`.

Analyst inference: the ephemeral local port suggests the imaged host was the client side of
the connection.

### 4.4 svchost.bat

Observed: an MFT entry for `Windows\System32\svchost.bat` (record 1772) with all four
`$STANDARD_INFORMATION` values at `2023-02-03 13:25:04 UTC`.

Observed in the range-supplied `strings_out.txt`: PowerShell code creating a TCP client
to `10[.]0[.]128[.]2` port 4337 and evaluating received data with `iex`.

Range-confirmed: the code belongs to `svchost.bat`, and the attacker created the file.

Not recorded: the file's content, its creator, and any execution of it.

## 5. ATT&CK Alignment

Mapped against ATT&CK Enterprise v19.2. The full disposition table, including techniques
considered and not mapped, is in the [MITRE ATT&CK Mapping](../analysis/mitre-attack-mapping.md).

| Technique | Disposition |
| :--- | :--- |
| T1003.001 — OS Credential Dumping: LSASS Memory | Invocation observed; outcome not established |
| T1036 — Masquerading | `lsass.exe` name and non-System32 path observed; renaming range-confirmed |
| T1059.001 — Command and Scripting Interpreter: PowerShell | Process observed; its commands not recorded |
| T1047 — Windows Management Instrumentation | Consistent with observed WmiPrvSE parentage; WMI method not recorded |

## 6. Conclusion

The memory image records a WmiPrvSE → PowerShell → masqueraded `lsass.exe` lineage whose
last process, created three seconds before the image timestamp, carries a dump
invocation (`-ma 656`) against the legitimate LSASS process; an ESTABLISHED TCP connection
to `10[.]0[.]128[.]2:4337` with no recorded owner; and an MFT entry for `svchost.bat`. The exercise states that these belong to one
intrusion; the surviving record supports each observation separately, not the chain.

## 7. Limitations

1. **The dump outcome is not recorded.** `filescan` and `dumpfiles` were not run. The
   command line names `lsass.dmp` relative to an unrecorded working directory.
2. **The binary behind PID 1576 was not examined.** No hash, signature or version
   information was recorded; the ProcDump match rests on argument syntax.
3. **The connection has no recorded owner or time.** netscan reports owner `-1`, so no
   process is tied to the connection, and no creation time is available.
4. **svchost.bat is known only from an MFT entry and the range's proposition.** The entry
   reports `Attribute: In Use & Directory` and shows `$STANDARD_INFORMATION` values only;
   no `$FILE_NAME` values are recorded, and `$STANDARD_INFORMATION` values can be altered.
5. **`strings_out.txt` was range-supplied.** Its derivation from this image was not
   repeated.
6. **Source-record conflicts are documented, not reconciled.** The notes carry two
   renderings of `svchost.exe` (PID 884) that disagree on parent, thread count and creation
   time (13:10:12 in the full process tree; 13:10:42 under a filter whose pattern the line
   does not contain); neither is presented as authoritative. One psinfo invocation carries
   a `-g` offset that differs from the value used in every other run. A working-note window
   of 13:23–13:28 for the dump is not supported by any recorded value and is not used.
7. **Scope not examined.** Persistence, lateral movement, exfiltration and interactive
   operation were not examined. Absence from this record is not evidence of absence.
8. **Range-supplied propositions cannot be independently verified.** The exercise
   environment is permanently closed.

## Related Documents

- [Case Overview](../README.md)
- [Timeline](../analysis/timeline-reconstruction.md)
- [Evidence Inventory](../evidence-metadata/memory-image-details.md)
- [Indicators of Compromise](../analysis/iocs.md)
