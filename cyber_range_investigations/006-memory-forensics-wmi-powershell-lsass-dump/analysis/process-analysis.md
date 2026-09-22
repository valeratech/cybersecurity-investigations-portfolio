# Process Analysis

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Record the process lineage, cross-view listing results and command lines that Volatility
reports for the processes named in the exercise, and separate them from the exercise's own
propositions.

## 2. Profile Context

- Profile: `Win10x64_17763`
- KdCopyDataBlock (V): `0xf8034da8a4d8`
- Memory image timestamp: `2023-02-03 13:29:33 UTC` (imageinfo)

## 3. Process Lineage (pstree)

The full pstree output is retained in the notes without its invocation line. The
filtered runs are recorded as (image path normalised to `memory.dmp`):

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 pstree | Select-String -Pattern 5104
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 pstree | Select-String -Pattern 'wmi' -SimpleMatch
```

Observed lineage:

```
WmiPrvSE.exe (PID 1944, parent PID 884)
└── powershell.exe (PID 5104)
    └── conhost.exe (PID 896)
```

### Observations

- `powershell.exe` (PID 5104) was created at `2023-02-03 13:23:40 UTC`, about thirteen
  minutes after `WmiPrvSE.exe` (PID 1944, `2023-02-03 13:10:37 UTC`).
- A second `WmiPrvSE.exe` (PID 3816) runs under the same parent. Multiple WMI provider
  host instances are common.
- The command line of PID 5104 was not recorded.
- Range-confirmed: the exercise accepted PID 1944 as the process responsible for the
  malicious activity.
- Analyst inference: a PowerShell process parented by `WmiPrvSE.exe` is consistent with
  process creation through WMI. The WMI method, consumer or caller is not recorded.

## 4. Cross-View Analysis (psxview)

Command as recorded:

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 psxview
```

### lsass.exe entries

| PID | Image path (cmdline) | pslist | psscan | thrdproc | Exit time |
| :--- | :--- | :---: | :---: | :---: | :--- |
| 656 | `C:\Windows\system32\lsass.exe` | True | False | True | none |
| 1576 | `C:\Windows\lsass.exe` | False | False | True | none |

### Observations

- PID 1576 carries the name of a system process but runs from `C:\Windows\` rather than
  `C:\Windows\system32\`.
- PID 1576 is absent from `pslist`, `psscan` and the full `pstree` output, and present in
  `thrdproc`. The cause of that visibility pattern was not tested; the record does not
  establish hiding, unlinking or process lifetime.

### Other psxview rows

The full psxview output also lists `RamCapture64.e` (PID 4884) and `wsmprovhost.ex`
(PID 4440), each with `pslist` False. They are disclosed as recorded; no investigative
significance is assigned to them in this case.

## 5. Command Line Analysis (cmdline)

Commands as recorded:

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 cmdline --offset=0x0000000030581080
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 cmdline --offset=0x000000010a47e0c0
```

Observed command lines:

- PID 1576: `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`
- PID 656: `C:\Windows\system32\lsass.exe`

Range-confirmed: the exercise states that this is a Sysinternals tool renamed to a common
process name.

Analyst inference: the arguments match Sysinternals ProcDump syntax:

- `-accepteula` → suppresses the licence prompt
- `-ma` → full memory dump
- `656` → target PID (the legitimate LSASS)
- `lsass.dmp` → output file name, relative to an unrecorded working directory

The binary behind PID 1576 was not examined; no hash, signature or version was recorded.

## 6. Parent Process (psinfo)

Command as recorded (the `-g` value differs from every other run in the notes):

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8aa4d8 psinfo -o 0x0000000030581080
```

Observed fields for PID 1576:

- `Parent Process: NA PPID: 5104` — the parent PID is recorded; the plugin did not resolve
  the parent image.
- `Creation Time: 2023-02-03 13:29:30 UTC+0000`
- Process path (VAD and PEB): `\Windows\lsass.exe` / `C:\Windows\lsass.exe`

pstree identifies PID 5104 as `powershell.exe` at capture. Together these give the
recorded lineage:

```
WmiPrvSE.exe (1944)
    → powershell.exe (5104)
        → lsass.exe (1576), by recorded PPID
```

Range-confirmed: the exercise accepted PID 5104 as the process that spawned PID 1576. The
range's suggested `handles` check was not run.

## 7. Unnamed Process Entry

pstree records an entry with PID 393216, no image name, zero threads and a time value of
`1970-01-01 00:00:00 UTC+0000`. Its cause is not recoverable from the surviving notes.

## 8. MITRE ATT&CK Alignment

ATT&CK Enterprise v19.2; full dispositions in the [MITRE ATT&CK Mapping](mitre-attack-mapping.md).

| Technique | ID | Basis |
| :--- | :--- | :--- |
| OS Credential Dumping: LSASS Memory | T1003.001 | Dump invocation against PID 656 observed; outcome not established |
| Masquerading | T1036 | `lsass.exe` name with non-System32 path observed |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe` (PID 5104) observed; its commands not recorded |
| Windows Management Instrumentation | T1047 | Consistent with WmiPrvSE parentage; WMI method not recorded |

## 9. Process-Level Conclusion

- **Observed:** WmiPrvSE (1944) → PowerShell (5104) → masqueraded `lsass.exe` (1576), the
  last link by recorded PPID.
- **Observed:** a dump invocation against the legitimate LSASS (PID 656).
- **Not established:** the dump's completion, its output location, the binary's identity,
  and any credential compromise.
