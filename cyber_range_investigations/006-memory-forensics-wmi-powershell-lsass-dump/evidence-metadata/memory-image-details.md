# Memory Image Evidence Metadata

**Case ID:** 006  
**Investigation:** Memory Forensics – WMI → PowerShell → LSASS Dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Evidence Overview

| Field | Value |
|-------|--------|
| Evidence Type | Windows Memory Image |
| File Name | memory.dmp |
| Format | Raw Memory Dump |
| Operating System | Windows 10 x64 |
| Volatility Profile | Win10x64_17763 |
| Image Timestamp (Volatility) | 2023-02-03 13:29:33 UTC |

## 2. Acquisition Notes

- Memory image provided by CyberDefenders lab environment.
- Acquisition method not disclosed (lab-provided artifact).
- No live acquisition performed by analyst.
- Integrity assumed per lab distribution.

> Note: In real-world IR, acquisition method (WinPMEM, DumpIt, Magnet RAM Capture, etc.) and chain-of-custody documentation would be required.

## 3. Kernel & Profile Validation

Validated using:

```
python vol.py -f memory.dmp imageinfo
python vol.py -f memory.dmp --profile=Win10x64_17763 kdbgscan
```

Confirmed Profile:

- `Win10x64_17763`

*KDBG Information*
- KdCopyDataBlock (Virtual): `0xf8034da8a4d8`
- Kernel Base: `0xfffff8034d800000`
- Build String: `17763.1.amd64fre.rs5_release.180`

## 4. File System Artifacts Identified in Memory
| Artifact | Path | Notes |
| :--- | :--- | :--- |
| Batch File | C:\Windows\System32\svchost.bat | Malicious C2 script |
| Dump Output | C:\Windows\lsass.dmp | LSASS credential dump |
| Masqueraded Binary | C:\Windows\lsass.exe | Renamed ProcDump-like tool |

## 5. Suspicious Processes Identified
| PID | Process | Notes |
| :--- | :--- | :--- |
| 1944 | WmiPrvSE.exe | Spawned PowerShell |
| 5104 | powershell.exe | Interactive execution |
| 1576 | lsass.exe | **Masqueraded ProcDump** |
| 656 | lsass.exe | Legitimate LSASS |

## 6. Network Artifacts (Defanged)
| Type | Value |
| :--- | :--- |
| **Remote C2** | 10[.]0[.]128[.]2:4337 |
| **Local Source Port** | 63944 |
| **Protocol** | TCP |
| **Connection State** | ESTABLISHED |

## 7. File Creation Timeline (MFT Parser)
Extracted via:

`python vol.py -f memory.dmp --profile=Win10x64_17763 mftparser --output-file=mftparser.json`
| File | Creation Time (UTC) |
| :--- | :--- |
| Windows\System32\svchost.bat | 2023-02-03 13:25:04 |
## 8. Hashes
> Not available (lab artifact).
> 
> In a real-world case, SHA256 and MD5 hashes would be documented here.

## 9. Evidence Handling Notes
- No evidence files stored in this public repository.
- Only metadata, commands used, and analytical findings are documented.
- All IOCs are defanged for portfolio safety.

## 10. Integrity Assessment
- No signs of memory image corruption affecting core analysis.
- Minor anomalous process entry (PID 393216, epoch timestamp) observed.
- Requires deeper kernel structure validation if this were production IR.
- 
## 11. Evidence Summary
- **Evidence Status**: Validated and analyzed.
- **Compromise Confirmed**: Yes (Credential dumping + C2 communication).
