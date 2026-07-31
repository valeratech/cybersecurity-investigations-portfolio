# Network Indicators of Compromise

**Document Type:** IOC Collection

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Summary

This document contains confirmed, normalized, and defanged Indicators of Compromise (IOCs) identified during the investigation. All entries have been validated through endpoint telemetry, network analysis, and threat intelligence correlation.

## IP Addresses

- `192[.]168[.]250[.]100` (Compromised host)  
- `54[.]148[.]194[.]58` (External IP lookup / reconnaissance)  

## Domains

- `ipinfo[.]io` (External IP lookup service used for reconnaissance)  

## Network Indicators

- Primary communication port: `6892` (Botnet / C2 traffic)  
- Secondary communication port: `80` (HTTP reconnaissance)  

## File Hashes

- `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` (Cerber malware binary)

## Malware Attribution

- Malware Family: Cerber  
- Network Classification: `Cerber.Botnet`  
- Category: Botnet  

## Detection Signatures

- `ET POLICY Possible External IP Lookup ipinfo.io`  

## Notes

- All indicators have been extracted from confirmed malicious activity.  
- High-volume outbound connections (~16,384 unique IPs) indicate large-scale botnet behavior.  
- Indicators should be used for detection, correlation, and blocking where appropriate.
