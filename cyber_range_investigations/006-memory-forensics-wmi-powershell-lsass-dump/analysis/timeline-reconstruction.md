# Timeline Reconstruction

**Document Type:** Timeline  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Evidence Basis

Timestamps come from Volatility 2.6.1 output retained in the analyst's notes: process
creation times from `pstree` and `psinfo`, the image timestamp from `imageinfo`, and
`$STANDARD_INFORMATION` values from `mftparser`. Each value is rendered by the tool with a
`UTC+0000` suffix in its own output row; that suffix is the warrant for each value below.
No value is converted or inferred.

**Counting unit.** Each row is one recorded timestamp value.

## 2. Timestamped Observations

### System initialization context

| Time (UTC) | Observation | Warrant |
|------------|-------------|---------|
| 2023-02-03 13:09:57 | `System` (PID 4) created | pstree row, `UTC+0000` |
| 2023-02-03 13:10:05 | `wininit.exe` (PID 512) created | pstree row, `UTC+0000` |
| 2023-02-03 13:10:06 | `lsass.exe` (PID 656, `C:\Windows\system32\lsass.exe`) created | pstree row, `UTC+0000` |

### Process lineage

| Time (UTC) | Observation | Warrant |
|------------|-------------|---------|
| 2023-02-03 13:10:37 | `WmiPrvSE.exe` (PID 1944) created, parent PID 884 | pstree row, `UTC+0000` |
| 2023-02-03 13:10:56 | `WmiPrvSE.exe` (PID 3816) created, parent PID 884 | pstree row, `UTC+0000` |
| 2023-02-03 13:23:40 | `powershell.exe` (PID 5104) created, parent PID 1944 | pstree row, `UTC+0000` |
| 2023-02-03 13:23:40 | `conhost.exe` (PID 896) created, parent PID 5104 | pstree row, `UTC+0000` |

### File system entry

| Time (UTC) | Observation | Warrant |
|------------|-------------|---------|
| 2023-02-03 13:25:04 | MFT entry `Windows\System32\svchost.bat`: `$STANDARD_INFORMATION` creation, modification, MFT-change and access values | mftparser row, `UTC+0000` |

### Masqueraded process and capture

| Time (UTC) | Observation | Warrant |
|------------|-------------|---------|
| 2023-02-03 13:29:30 | `lsass.exe` (PID 1576, `C:\Windows\lsass.exe`) created, PPID 5104; command line `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp` | psinfo field, `UTC+0000` |
| 2023-02-03 13:29:33 | Memory image timestamp | imageinfo `Image date and time`, `UTC+0000` |

### Range-accepted answers

| Accepted value (UTC) | Question | Status |
|------------|-------------|---------|
| 2023-02-03 13:23 | Time of compromise | range-accepted, minute precision |
| 2023-02-03 13:25 | Creation time of `svchost.bat` | range-accepted, minute precision |

The accepted time of compromise matches the minute of PID 5104's creation. That the
compromise began then is the exercise's proposition; the image records only when PID 5104
was created.

## 3. Established Events Without Recorded Timestamps

- **TCP connection** `10[.]0[.]128[.]0:63944` → `10[.]0[.]128[.]2:4337`: `ESTABLISHED`
  when the image was taken. The recorded netscan row carries no creation time and no owning process (owner
  PID `-1`), so the connection is not placed in the sequence above.
- **Dump invocation outcome**: not recorded. The creation time of PID 1576 is the time the
  process with the dump arguments was created, not a time at which a dump completed.

## 4. Limitations

1. **Ordering is limited to recorded values.** The rows above are ordered by their own
   recorded times. No event is dated by inference, and the connection is not assigned a time.
2. **Conflicting source values for PID 884.** The notes carry two renderings of
   `svchost.exe` (PID 884): 13:10:12 with PPID 636 and 10 threads in the full process tree,
   and 13:10:42 with PPID 656 and 18 threads under a `Select-String` filter whose pattern
   the line does not contain. The conflict is documented, not reconciled: neither value is
   presented as authoritative, and no creation time is given for PID 884. Both renderings
   agree only that PID 884 is `svchost.exe`; the parent PID 884 of PID 1944 and PID 3816
   comes from those processes' own rows.
3. **Unsupported working-note window.** The analyst's working notes mention an LSASS dump
   window of 13:23–13:28. No recorded value supports it, and it is not used.
4. **`$STANDARD_INFORMATION` only.** The MFT entry shows `$STANDARD_INFORMATION` values;
   no `$FILE_NAME` values are recorded. `$STANDARD_INFORMATION` values can be altered, so the
   `2023-02-03 13:25:04 UTC` value is reported as recorded, not as a verified creation time.
5. **Unnamed process entry.** pstree records an entry with PID 393216, no image name, zero
   threads and a time value of `1970-01-01 00:00:00 UTC+0000`. That value is not an event
   time; its cause is not recoverable from the surviving notes.
6. **Local time.** imageinfo reports the image's local time as `2023-02-03 05:29:33 -0800`.
   It is recorded and not used to convert any value.
