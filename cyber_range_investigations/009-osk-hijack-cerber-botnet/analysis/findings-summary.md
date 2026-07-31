# Findings Summary

**Document Type:** Findings

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Executive Summary

Analysis of endpoint and network telemetry confirms the presence of a malicious persistence mechanism leveraging a hijacked `osk.exe` binary. The activity is associated with large-scale outbound communication and has been definitively attributed to the Cerber ransomware family with botnet functionality.

## Confirmed Findings

### Finding 1 – Masquerading Binary Execution

#### Observation
The `osk.exe` executable was observed running from a non-standard directory:

`C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`

The legitimate path for this binary is:

`C:\Windows\System32\osk.exe`

#### Conclusion
The binary is a masquerading executable placed in a user-accessible directory to evade detection. This strongly indicates malicious staging and persistence behavior.

### Finding 2 – Host Attribution

#### Observation
Execution context identified:

- Computer: `we8105desk[.]waynecorpinc[.]local`  
- Internal IP: `192[.]168[.]250[.]100`  
- User: `bob.smith`  

#### Conclusion
The compromised activity is localized to a specific endpoint and user account, enabling precise incident scoping and containment actions.

### Finding 3 – Abnormal Process Activity Volume

#### Observation
Total `osk.exe` related events:

`49,608`

#### Conclusion
The unusually high volume of events is inconsistent with normal user behavior and suggests automated or malicious execution.

### Finding 4 – Suspicious Network Communication

#### Observation
Outbound communication characteristics:

- Primary port: `6892` (~99.998% of traffic)  
- Secondary port: `80` (single event)  
- Unique destination IPs: `16,384`  

#### Conclusion
The communication pattern indicates automated large-scale outbound connections consistent with botnet behavior or scanning activity.

### Finding 5 – Malware Identification via Hash

#### Observation
Extracted SHA256 hash:

`37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`

#### Conclusion
Threat intelligence analysis confirms the binary is associated with the Cerber malware family.

### Finding 6 – Botnet Classification from Network Security Logs

#### Observation
Fortigate UTM logs classify the traffic as:

- Category: `Botnet`  
- Application: `Cerber.Botnet`  

#### Conclusion
Network-level enrichment confirms that the infected host is communicating with botnet infrastructure associated with Cerber.

### Finding 7 – External Reconnaissance Behavior

#### Observation
A single HTTP connection was made to:

`54[.]148[.]194[.]58`

Suricata alert triggered:

`ET POLICY Possible External IP Lookup ipinfo.io`

#### Conclusion
The system attempted to determine its external IP address, a behavior commonly associated with malware reconnaissance and initial beaconing.

## Final Assessment

The investigation confirms:

- Persistence via OSK accessibility binary hijack  
- Execution of a masquerading malicious binary  
- High-volume outbound communication indicative of botnet activity  
- Malware attribution to Cerber ransomware  
- Evidence of external reconnaissance behavior  

The compromised system is actively participating in malicious network activity and represents a high-confidence security incident requiring containment and remediation.
