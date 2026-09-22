# File Artifact Analysis

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Record what the surviving notes establish about the file names involved in the exercise,
and what they do not.

## 2. File Names Under Review

| File | Path | What is recorded |
|------|------|------------------|
| svchost.bat | C:\Windows\System32\svchost.bat | MFT entry observed; malicious role range-confirmed |
| lsass.exe | C:\Windows\lsass.exe | Image path of PID 1576 observed (cmdline, psinfo) |
| lsass.dmp | not recorded | Output name in PID 1576's command line; no file observed |

No file content was recovered for any of the three.

## 3. svchost.bat

### MFT entry (observed)

Command as recorded (image path normalised to `memory.dmp`):

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 mftparser --output-file="mftparser.json"
```

| Field | Recorded value |
| :--- | :--- |
| Record number | 1772 |
| Attribute | In Use & Directory |
| Link count | 1 |
| `$STANDARD_INFORMATION` creation, modification, MFT-change, access | `2023-02-03 13:25:04 UTC+0000` (all four) |
| `$FILE_NAME` values | not recorded |

The entry's name is `Windows\System32\svchost.bat`. Its attribute field reads
`In Use & Directory`; the notes do not resolve that against the `.bat` name.
`$STANDARD_INFORMATION` values can be altered, so the value is reported as recorded.

### Content association (range-confirmed)

The exercise states that the attacker created this file and that it communicated with
`10[.]0[.]128[.]2:4337`. The range-supplied `strings_out.txt` contains PowerShell code that
opens a TCP client to that endpoint (see [Network Analysis](network-analysis.md)); the notes
record no link between that string and the file. The file's actual content, its creator and
any execution are not recorded.

R-Studio appears in the notes only as the range's suggested recovery route; no file was
recovered.

## 4. Masqueraded lsass.exe

Observed command line (cmdline): `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

- The image path is `C:\Windows\lsass.exe`, not the legitimate `C:\Windows\system32\lsass.exe`.
- The target PID is 656, the legitimate LSASS.
- Range-confirmed: the process is a renamed Sysinternals tool.
- Analyst inference: the arguments match ProcDump's full-memory-dump syntax.
- No hash, signature or version information was recorded for the binary.

## 5. lsass.dmp

`lsass.dmp` is the output name given in PID 1576's command line, relative to a working
directory that was not recorded. `filescan` and `dumpfiles` were not run, so neither the
file's existence nor its location is established, and no credential material was
observed.

## 6. MITRE ATT&CK Alignment

ATT&CK Enterprise v19.2; full dispositions in the [MITRE ATT&CK Mapping](mitre-attack-mapping.md).

| Technique | ID | Basis |
| :--- | :--- | :--- |
| Masquerading | T1036 | `lsass.exe` name with non-System32 path observed; renaming range-confirmed |
| OS Credential Dumping: LSASS Memory | T1003.001 | Dump invocation observed; outcome not established |

## 7. File Artifact Conclusion

- **Observed:** an MFT entry for `svchost.bat` with `$STANDARD_INFORMATION` values of
  `2023-02-03 13:25:04 UTC`; the masqueraded image path `C:\Windows\lsass.exe`.
- **Range-confirmed:** `svchost.bat` was attacker-created and used for communication; the
  masqueraded image is a Sysinternals tool.
- **Not established:** the content or execution of `svchost.bat`; the existence of
  `lsass.dmp`; any credential compromise.
