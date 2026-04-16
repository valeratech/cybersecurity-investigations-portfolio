# Timeline (UTC)

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Timeline of Events

| Timestamp (UTC) | System | Event Description | Source | Relevance |
|----------------|--------|------------------|--------|-----------|
| Unknown | we8105desk[.]waynecorpinc[.]local | Suspicious `osk.exe` binary staged in user AppData directory | Sysmon | Initial indicator of compromise |
| Unknown | we8105desk[.]waynecorpinc[.]local | Execution of `osk.exe` from non-standard path | Sysmon Event ID 1 | Masquerading binary execution |
| Unknown | we8105desk[.]waynecorpinc[.]local | High-volume process activity (~49,608 events) | Sysmon | Indicates automated or malicious behavior |
| Unknown | we8105desk[.]waynecorpinc[.]local | Outbound connections initiated on port `6892` | Sysmon | Primary C2 / botnet communication channel |
| Unknown | we8105desk[.]waynecorpinc[.]local | Large-scale outbound connections to `16,384` unique IP addresses | Sysmon | Botnet/scanning behavior |
| Unknown | we8105desk[.]waynecorpinc[.]local | Single outbound HTTP connection to `54[.]148[.]194[.]58` over port `80` | Sysmon | External reconnaissance |
| Unknown | we8105desk[.]waynecorpinc[.]local | External IP lookup detected | Suricata | Reconnaissance behavior |
| Unknown | Network Perimeter | Traffic classified as `Botnet` | Fortigate UTM | Network-level threat classification |
| Unknown | Network Perimeter | Traffic identified as `Cerber.Botnet` | Fortigate UTM | Malware attribution |
| Unknown | we8105desk[.]waynecorpinc[.]local | Suspicious binary loaded into memory | Sysmon Event ID 7 | Confirms execution and enables hash extraction |
| Unknown | External Intelligence | SHA256 hash linked to Cerber ransomware family | VirusTotal | Final malware attribution |

## Timeline Summary

The sequence of events indicates the deployment of a masquerading binary using the `osk.exe` name to establish persistence on a compromised host. Following execution, the system initiated high-volume outbound connections over a non-standard port, consistent with botnet activity. Additional reconnaissance behavior was observed via HTTP-based external IP lookup. Network security logs confirmed classification as Cerber botnet activity, and threat intelligence correlation verified the binary as part of the Cerber ransomware family.
