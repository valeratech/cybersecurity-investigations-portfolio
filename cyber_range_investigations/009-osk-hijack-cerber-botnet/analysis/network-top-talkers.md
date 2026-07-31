# Network Top Talkers Analysis

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

Identify the most active network communication patterns associated with the suspicious `osk.exe` process and determine dominant traffic characteristics.

## Data Sources

- Sysmon Event Logs (XmlWinEventLog)  
- Splunk (index="botsv1")  

## Methodology

### Query Used

`index="botsv1" sourcetype=xmlwineventlog "osk.exe" | stats count by DestinationIp, DestinationPort | sort - count`

### Analysis Approach

- Aggregated outbound connections by destination IP and port  
- Sorted results by highest volume to identify dominant communication patterns  
- Focused on identifying abnormal or high-frequency network behavior  

## Findings

### 1. Dominant Communication Port

#### Observation
The overwhelming majority of traffic is directed to:

- Destination Port: `6892`

#### Interpretation
- Non-standard port usage  
- Strong indicator of custom protocol or malware communication  
- Consistent with command-and-control (C2) or botnet activity  

### 2. Distribution of Destination IPs

#### Observation
- Total unique destination IPs: `16,384`  
- Traffic distributed across a large number of external hosts  

#### Interpretation
- Highly distributed communication pattern  
- Suggests:
  - Botnet propagation  
  - Peer discovery  
  - Scanning behavior  

### 3. Low-Frequency HTTP Traffic

#### Observation
- Single connection over port `80`  
- Destination IP: `54[.]148[.]194[.]58`  

#### Interpretation
- Not part of primary communication channel  
- Likely used for:
  - External IP lookup  
  - Initial beaconing  
  - Environment reconnaissance  

## Observations

- Traffic is overwhelmingly concentrated on a single non-standard port  
- Communication is distributed across thousands of external IP addresses  
- Minimal use of standard web protocols  
- Pattern deviates significantly from normal user or application behavior  

## Interim Conclusion

The top talker analysis confirms that the `osk.exe` process is responsible for high-volume, distributed outbound network communication over a non-standard port. This behavior is consistent with botnet activity and supports previous findings of Cerber malware involvement.
