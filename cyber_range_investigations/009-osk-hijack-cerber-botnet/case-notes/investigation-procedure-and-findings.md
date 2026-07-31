# Investigation Procedure and Findings

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document captures the step-by-step investigative workflow, reasoning, and analytical pivots performed throughout the investigation. It reflects the methodology used to transition from initial detection to full malware attribution.

## Investigation Procedure

### Step 1 – OSINT Baseline Validation

Performed external research on `osk.exe` to determine:

- Legitimate function: Windows Ease of Access On-Screen Keyboard  
- Expected file path:  
  - `C:\Windows\System32\osk.exe`  

Established baseline for detecting masquerading behavior.

### Step 2 – Initial SIEM Query

Executed initial query:

`index="botsv1" sourcetype=xmlwineventlog "osk.exe"`

Objective:
- Identify all activity related to `osk.exe`
- Establish scope of activity across the environment

### Step 3 – Activity Volume Assessment

Executed aggregation:

`index="botsv1" sourcetype=xmlwineventlog "osk.exe" | stats count`

Result:
- ~49,608 events associated with `osk.exe`

Interpretation:
- Abnormally high usage for an accessibility tool
- Indicates potential automated or malicious activity

### Step 4 – File Path Validation

Analyzed `Image` field in Sysmon events.

Identified suspicious execution path:

`C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`

Comparison:
- Legitimate: `C:\Windows\System32\osk.exe`
- Observed: User AppData directory with GUID structure

Conclusion:
- Strong indicator of masquerading and persistence

### Step 5 – Host Attribution

Reviewed key fields:

- `Computer`
- `SourceIp`
- `User`

Identified:

- Host: `we8105desk[.]waynecorpinc[.]local`  
- IP: `192[.]168[.]250[.]100`  
- User: `bob.smith`  

### Step 6 – Network Activity Analysis

Pivoted to network fields:

- `DestinationIp`
- `DestinationPort`

Findings:

- Primary port: `6892`
- Secondary port: `80` (single event)

Interpretation:
- Port `6892` used for sustained communication
- Port `80` used for reconnaissance

### Step 7 – Scope of External Communication

Executed:

`index="botsv1" sourcetype=xmlwineventlog "osk.exe" DestinationPort=6892 DestinationIp=* | stats dc(DestinationIp)`

Result:
- `16,384` unique destination IPs

Interpretation:
- Large-scale automated communication
- Indicative of botnet or scanning behavior

### Step 8 – Hash Extraction

Executed:

`index="botsv1" sourcetype=xmlwineventlog EventCode=7 ImageLoaded="*osk.exe*"`

Extracted SHA256:

`37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`

### Step 9 – Threat Intelligence Correlation

Submitted hash to VirusTotal.

Result:
- Malware Family: Cerber

Interpretation:
- Confirms ransomware classification
- Provides attribution for malicious activity

### Step 10 – Network Security Correlation

Executed:

`index="botsv1" sourcetype=fortigate_utm dest_port=6892`

Findings:

- Category: `Botnet`
- Application: `Cerber.Botnet`

Interpretation:
- Confirms active communication with botnet infrastructure

### Step 11 – Reconnaissance Confirmation

Identified HTTP connection:

- Destination IP: `54[.]148[.]194[.]58`

Pivoted to Suricata:

`index="botsv1" sourcetype=suricata dest_ip=54.148.194.58 event_type=alert`

Alert:

`ET POLICY Possible External IP Lookup ipinfo.io`

Interpretation:
- External IP discovery behavior
- Common malware reconnaissance technique

## Final Findings

- Persistence established via OSK accessibility binary hijack  
- Masquerading executable deployed in user AppData directory  
- High-volume outbound communication over non-standard port (`6892`)  
- Botnet-like behavior involving large-scale external connections  
- Malware attributed to Cerber ransomware family  
- Reconnaissance activity confirmed via external IP lookup  

## Conclusion

The investigation confirms a high-confidence compromise involving a Cerber-based malware infection. The attacker leveraged a legitimate Windows binary (`osk.exe`) for persistence, executed a masquerading payload, and established extensive outbound communication consistent with botnet operations. The combination of endpoint telemetry, network analysis, and threat intelligence provides a complete view of the attack lifecycle from execution through attribution.
