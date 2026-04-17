# Network Analysis – TeamCity APT Ransomware Investigation

**Document Type:** Analysis

## Objective

Analyze network-based activity to identify initial access, command-and-control (C2) communication, lateral movement patterns, and data exfiltration behavior.

## Data Sources

- Elastic network logs (ECS normalized)
- NGINX reverse proxy logs (`nginx_rp`)
- Sysmon Event ID 3 (network connections)
- PowerShell Script Block logs (Event ID 4104)

## 1. Initial Access – TeamCity Exploitation

### Observation

HTTP traffic analysis revealed repeated requests referencing a TeamCity instance within the CyberRange domain.

### Key Indicators

- Compromised server:
  - `jb01[.]cyberrange[.]cyberdefenders[.]org`
- Vulnerability exploited:
  - CVE-2024-27198 (TeamCity authentication bypass)

### Supporting Query

```kql
event.category:network and network.protocol:http and (
  url.full:(*teamcity* or *jetbrain*) or
  http.request.referrer:(*teamcity* or *jetbrain*)
)
```

### Conclusion

The attacker leveraged a vulnerable TeamCity server in the DMZ to gain initial access into the network.

## 2. Attacker Infrastructure
### Observation

Significant outbound communication from the beachhead host (`10[.]10[.]3[.]4`) to an external IP address.

### Key Indicators
Attacker IP:
- `3[.]90[.]168[.]151`
Reverse DNS:
- `ec2-3-90-168-151.compute-1.amazonaws[.]com`

### Supporting Query
```
event.category:network and network.protocol:http
and (destination.ip:3.90.168.151 or source.ip:10.10.3.4)
```

### Conclusion

The attacker operated from cloud infrastructure, using AWS-hosted systems to deliver payloads and maintain communication.

## 3. Malware Delivery
### Observation

HTTP-based file downloads were observed targeting the beachhead host.

### Indicators
File types:
- Executables (`.exe`)
- Archives (`.zip`, `.rar`)
MIME types:
- `application/x-msdownload`
- `application/octet-stream`

### Supporting Query
```
event.category:network and network.protocol:http
and source.ip:10.10.3.4
and (
  url.full:(*.exe or *.dll or *.zip or *.rar) or
  http.response.mime_type:("application/x-msdownload" or "application/octet-stream")
)
```

### Conclusion

The attacker delivered malicious payloads via HTTP downloads to establish initial foothold.

## 4. Command and Control (C2)
### Observation

Encoded PowerShell commands and persistent outbound communication patterns were observed.

### Indicators
Custom firewall rule enabled:
- Port `8080`
Tunneling password used (observed in decoded payloads)

### Supporting Query
```
event.provider:"Microsoft-Windows-Sysmon"
and event.code:1
and process.name:"powershell.exe"
and process.command_line:(*3.90.168.151*)
```

### Conclusion

The attacker established a covert C2 channel over port `8080`, bypassing standard network controls.

## 5. Lateral Movement
### Observation

Remote command execution observed across internal hosts using Windows Management Instrumentation (WMI).

### Indicators
LOLBin used:
- `wmic`
Target hosts:
- `10[.]10[.]1[.]4`
- `10[.]10[.]0[.]7`

### Supporting Query
```
process.name:"wmic.exe"
and process.command_line: *process call create*
```
### Conclusion

The attacker used WMI-based remote execution to move laterally across systems.

## 6. Data Exfiltration Preparation
### Observation

PowerShell activity consistent with compression and steganography was identified.

### Indicators
Output file:
- `jvpd2px2at1.bmp`
Embedded content:
- System binaries (`ntoskrnl.exe`, `wdigest.dll`)

### Supporting Query
```
event.code:4104 AND host.ip:"10.10.3.4"
AND message:(Compress-Archive OR System.IO.Compression OR ConvertTo-SecureString)
AND message:("*.bmp")
``` 

### Conclusion

The attacker prepared sensitive data for exfiltration by embedding it within image files.

## 7. Ransomware Network Impact
### Observation

Widespread network activity coincided with ransomware deployment.

### Indicators
File extension:
- `.lsoc`
Ransom note:
- `un-lock your files[.]html`

### Supporting Query
```
event.code:11
and file.name:*.*.lsoc
```

### Conclusion

Ransomware execution resulted in mass file encryption across multiple hosts.

## Summary
- Initial access achieved via TeamCity exploitation
- Payload delivery conducted over HTTP
- C2 established via port `8080`
- Lateral movement performed using `wmic`
- Data staged using compression and steganography
- Final impact: enterprise-wide ransomware encryption
