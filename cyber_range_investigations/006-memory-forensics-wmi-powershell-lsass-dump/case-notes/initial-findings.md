# Initial Findings – 006 Memory Forensics Investigation

**Document Type:** Case Note  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Initial Objective

Analyze the provided Windows memory image to:

- identify suspicious process lineage
- check for masqueraded processes and cross-view listing inconsistencies
- determine whether credential dumping was attempted
- extract network indicators named by the exercise
- build a preliminary timeline

## 2. Profile Validation

imageinfo suggested several profiles, listing `Win10x64_17763` first. kdbgscan reported
a KDBG header suggestion of `Win10x64_17763`, build string
`17763.1.amd64fre.rs5_release.180`, and `KdCopyDataBlock (V): 0xf8034da8a4d8`, which was
used with `-g` in later runs.

## 3. Process Tree Pivot

pstree records this lineage:
```
WmiPrvSE.exe (PID 1944)
└── powershell.exe (PID 5104)
    └── conhost.exe (PID 896)
```

- `powershell.exe` was created at `2023-02-03 13:23:40 UTC`.
- Working hypothesis (analyst inference): PowerShell under the WMI provider host fits
  WMI-initiated execution, so PID 1944 was treated as the pivot. The WMI method is not
  recorded.
- The exercise accepted PID 1944 as the process responsible for the malicious activity
  (range-confirmed).

## 4. Cross-View Process Validation (psxview)

Two `lsass.exe` entries:

| PID | Path (cmdline) | pslist | Notes |
|------|------|------|------|
| 656 | `C:\Windows\system32\lsass.exe` | True | Legitimate path |
| 1576 | `C:\Windows\lsass.exe` | False | Non-System32 path |

PID 1576 is absent from `pslist` and `psscan` and present in `thrdproc`. Candidate
explanations noted at this stage (process exit, unlinking, parsing effects) were not
tested.

Command line of PID 1576:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

Analyst inference: this matches Sysinternals ProcDump syntax (`-ma` full dump of PID 656
to `lsass.dmp`). The exercise states the process is a renamed Sysinternals tool
(range-confirmed). The record shows the dump was invoked; it does not show that it
completed.

## 5. File Artifact

The exercise names `C:\Windows\System32\svchost.bat` as attacker-created and asks for the
IP and port it used (range-confirmed). The range-supplied `strings_out.txt` contains
PowerShell TCP-client code for `10[.]0[.]128[.]2:4337`; the notes record no link between
that string and the file.

## 6. Network Indicator (Defanged)

netscan, filtered for `10[.]0[.]128[.]2`:

- Local: `10[.]0[.]128[.]0:63944`
- Remote: `10[.]0[.]128[.]2:4337`
- State: `ESTABLISHED`
- Owner PID: `-1` (no owning process recorded)

The exercise accepted 63944 as the source port of the malicious session (range-confirmed).

## 7. Preliminary Timeline

| Time (UTC) | Event | Warrant |
|------------|--------|--------|
| 2023-02-03 13:10:37 | WmiPrvSE.exe (PID 1944) created | pstree, `UTC+0000` |
| 2023-02-03 13:23:40 | powershell.exe (PID 5104) created | pstree, `UTC+0000` |
| 2023-02-03 13:25:04 | svchost.bat MFT `$STANDARD_INFORMATION` values | mftparser, `UTC+0000` |
| 2023-02-03 13:29:30 | lsass.exe (PID 1576) created | psinfo, `UTC+0000` |
| 2023-02-03 13:29:33 | Memory image timestamp | imageinfo, `UTC+0000` |

## 8. Working Hypothesis at This Stage

Recorded as analyst inference at the initial-findings stage, with its evidentiary status:

1. WMI-based execution produced PowerShell — consistent with the observed parentage; the
   WMI method is not recorded.
2. PowerShell created `svchost.bat` — not recorded; no file creator is observed.
3. The batch file opened the TCP connection to `10[.]0[.]128[.]2:4337` — not recorded; the
   connection has no owning process and the file's content is not recovered.
4. A renamed ProcDump dumped LSASS — the invocation is observed; completion is not.

## 9. Checks Not Performed

These checks were not run during the exercise. The environment is permanently closed, so
their results are not recoverable from the surviving notes:

- `filescan` / `dumpfiles` for `lsass.dmp`
- recovery of PowerShell command lines or history for PID 5104
- process dumping or `dlllist` for PID 1576
- `handles` for PID 5104

## 10. Analyst Notes

- Two `WmiPrvSE.exe` instances are present (PIDs 3816 and 1944).
- pstree records an unnamed entry (PID 393216) with a `1970-01-01 00:00:00 UTC+0000`
  time value and zero threads; its cause is not recoverable from the surviving notes.

**Assessment at this stage:** the dump invocation, the process lineage, the connection
state and the MFT entry are observed; the links between them are the exercise's
propositions.
