# Indicators of Compromise (IOCs)

**Case ID:** 006  
**Time Standard:** UTC  

## 1. Network Indicators (Defanged)

| Type | Indicator | Notes |
|------|----------|-------|
| Remote IP | 10[.]0[.]128[.]2 | C2 server |
| Remote Port | 4337 | Non-standard TCP port |
| Local Source Port | 63944 | Outbound ephemeral port |
| Protocol | TCP | ESTABLISHED at capture |

## 2. File Artifacts

| File | Path | Description |
|------|------|-------------|
| svchost.bat | C:\Windows\System32\svchost.bat | Reverse shell script |
| lsass.exe | C:\Windows\lsass.exe | Renamed ProcDump binary |
| lsass.dmp | C:\Windows\lsass.dmp | LSASS memory dump |

## 3. Process Indicators

| Process | PID | Indicator |
|----------|------|-----------|
| WmiPrvSE.exe | 1944 | Spawned PowerShell |
| powershell.exe | 5104 | Reverse shell staging |
| lsass.exe | 1576 | Masqueraded credential dumper |
| lsass.exe | 656 | Legitimate LSASS target |

## 4. Command-Line Indicator

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

Indicators:

- `-ma` (full memory dump)
- Target `PID 656` (LSASS)
- Output file `lsass.dmp`

## IOC Summary
- The following high-confidence indicators confirm compromise:
- Reverse TCP communication to 10[.]0[.]128[.]2:4337
- Masqueraded ProcDump executed as lsass.exe
- LSASS memory dump generated

