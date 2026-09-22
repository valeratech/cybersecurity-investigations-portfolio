# Memory Image Evidence Metadata

**Document Type:** Evidence Inventory  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Evidence Register

| Item | Description | Provenance | Retained in this repository |
|------|-------------|------------|-----------------------------|
| `memory.dmp` | Windows memory image | Range-supplied | No |
| `strings_out.txt` | Pre-generated strings output | Range-supplied; parsed, not regenerated | No |
| `mftparser.json` | MFT parser output | Generated during the analysis | No |
| Analyst notes | Volatility commands and output, question responses | Analyst record | No |

## 2. Memory Image Details

| Field | Value | Source |
|-------|-------|--------|
| Operating system | Windows 10 x64, build 17763 | kdbgscan (OptionalHeader Major 10, Minor 0; build string below) |
| Volatility profile | Win10x64_17763 | imageinfo first suggestion; kdbgscan KDBG header suggestion |
| Image timestamp | 2023-02-03 13:29:33 UTC | imageinfo `Image date and time`, rendered `UTC+0000` |
| Image local time | 2023-02-03 05:29:33 -0800 | imageinfo `Image local date and time` |
| KdCopyDataBlock (V) | `0xf8034da8a4d8` | kdbgscan |
| Kernel base | `0xfffff8034d800000` | kdbgscan |
| Build string | `17763.1.amd64fre.rs5_release.180` | kdbgscan |

Commands as recorded (image path normalised to `memory.dmp`):

```
python vol.py -f memory.dmp imageinfo
python vol.py -f memory.dmp --profile=Win10x64_17763 kdbgscan
```

## 3. Acquisition and Integrity

- The memory image was supplied by the CyberDefenders exercise. The acquisition method is
  not recorded in the surviving notes.
- No hash of the image was recorded. Integrity rests on the range distribution.
- No live acquisition was performed by the analyst.

## 4. Artifacts Referenced in the Image

| Artifact | Path | What is recorded |
| :--- | :--- | :--- |
| Batch file | C:\Windows\System32\svchost.bat | MFT entry (record 1772); malicious role range-confirmed |
| Masqueraded image | C:\Windows\lsass.exe | Image path of PID 1576 |
| Dump output name | lsass.dmp | Named in PID 1576's command line; no file observed |

## 5. Processes Referenced

| PID | Process | What is recorded |
| :--- | :--- | :--- |
| 1944 | WmiPrvSE.exe | Parent of PID 5104 (pstree) |
| 5104 | powershell.exe | Child of PID 1944; recorded PPID of PID 1576 |
| 1576 | lsass.exe | Non-System32 path; dump invocation against PID 656 |
| 656 | lsass.exe | Legitimate LSASS, `C:\Windows\system32\lsass.exe` |

## 6. Network State at Capture (Defanged)

| Field | Value |
| :--- | :--- |
| Remote endpoint | 10[.]0[.]128[.]2:4337 |
| Local endpoint (capture-specific) | 10[.]0[.]128[.]0:63944 |
| Protocol | TCPv4 |
| State | ESTABLISHED |
| Owner PID | -1 (no owning process recorded) |

## 7. Usage Notes

- Every timestamp in this case comes from Volatility output rendered with `UTC+0000`.
- Commands are shown as recorded, with the image path normalised; the analyst's
  workstation paths are omitted.
- Evidence binaries are not stored in this public repository; indicators are defanged.

## 8. Handling Limitations

- The exercise environment is permanently closed; no plugin output beyond the retained
  notes is recoverable.
- `pslist`, `filescan` and `dumpfiles` output was not recorded.
- pstree records an unnamed entry (PID 393216) with a `1970-01-01 00:00:00 UTC+0000` time
  value; its cause is not recoverable from the surviving notes.
- The notes carry two conflicting renderings of `svchost.exe` (PID 884); neither is
  treated as authoritative.
