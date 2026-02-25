# Timeline Reconstruction

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Construct a chronological sequence of attacker activity using process creation times, file artifacts, and network connections recovered from memory.

## 2. System Initialization Context

| Time (UTC) | Event |
|------------|-------|
| 13:09:57 | System process started |
| 13:10:05 | wininit.exe initialized |
| 13:10:06 | Legitimate lsass.exe (PID 656) started |
| 13:10:12–13:10:27 | Core services and svchost processes initialized |

System boot and service initialization appear normal.

## 3. Initial Suspicious Activity

| Time (UTC) | Event |
|------------|-------|
| 13:10:37 | WmiPrvSE.exe (PID 1944) created |

Observation:

- WMI service instance created under svchost.exe (PID 884).
- Later identified as execution pivot for malicious activity.

## 4. Attacker Execution Phase

| Time (UTC) | Event |
|------------|-------|
| 13:23:40 | powershell.exe (PID 5104) spawned by WmiPrvSE.exe |

Analysis:

- Indicates remote or scripted execution via WMI.
- Occurs well after system stabilization.
- Marks likely beginning of hands-on-keyboard phase.

## 5. C2 Establishment

| Time (UTC) | Event |
|------------|-------|
| 13:25:04 | svchost.bat created |
| ~13:25 | TCP connection established to 10[.]0[.]128[.]2:4337 |
| Active at capture | Local port 63944 → Remote port 4337 (ESTABLISHED) |

Interpretation:

- Batch file used to establish reverse TCP shell.
- Host initiated outbound connection.

## 6. Credential Access Phase

| Time (UTC) | Event |
|------------|-------|
| 13:29:30 | Masqueraded lsass.exe (PID 1576) executed |
| 13:29:30 | LSASS (PID 656) targeted for memory dump |
| 13:29:33 | Memory image captured |

Command executed:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

Conclusion:

Credential dumping occurred immediately prior to memory acquisition.

## 7. Consolidated Attack Timeline

| Phase | Time (UTC) | Description |
|-------|------------|-------------|
| Execution | 13:23:40 | WMI spawns PowerShell |
| Persistence/C2 | 13:25:04 | Reverse shell batch file created |
| C2 Active | 13:25+ | Established outbound TCP session |
| Credential Dump | 13:29:30 | LSASS memory dump executed |
| Capture | 13:29:33 | Memory acquired |

## 8. Timeline Conclusion

The compromise began at approximately:

**2023-02-03 13:23:40 UTC**

Attack progression:

1. WMI-based execution
2. PowerShell staging
3. Reverse shell establishment
4. Credential dumping via renamed ProcDump
5. Active C2 at time of capture

The attacker maintained interactive control during the credential access phase.
