# Network Analysis

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

Analyze network activity associated with the suspicious `osk.exe` process to identify communication patterns, potential command-and-control (C2) behavior, and overall network impact.

## Data Sources

- Sysmon Event Logs (XmlWinEventLog)  
- Fortigate UTM Logs  
- Suricata IDS Logs  

## Analysis

### 1. Primary Communication Channel

#### Observation
The majority of outbound connections from the suspicious `osk.exe` process were made over:

- Destination Port: `6892`  
- Event Volume: ~48,196 events (~99.998%)

#### Interpretation
Port `6892` is not a standard application port and its overwhelming usage strongly indicates:

- Custom protocol communication  
- Command-and-control (C2) activity  
- Botnet-related traffic  

### 2. Secondary HTTP Communication

#### Observation
A single outbound connection was observed:

- Destination IP: `54[.]148[.]194[.]58`  
- Destination Port: `80`  

#### Interpretation
This connection deviates from the primary communication pattern and represents a targeted action rather than bulk activity.

### 3. External Reconnaissance Activity

#### Observation
Suricata IDS logs identified the following alert:

`ET POLICY Possible External IP Lookup ipinfo.io`

#### Interpretation
This alert indicates the host attempted to determine its public-facing IP address, which is commonly associated with:

- Malware beaconing  
- Environment reconnaissance  
- Preparation for C2 communication  

### 4. Scope of External Communication

#### Observation
Total unique destination IP addresses contacted over port `6892`:

`16,384`

#### Interpretation
This level of outbound diversity strongly suggests:

- Automated scanning behavior  
- Botnet propagation or peer discovery  
- Large-scale distributed communication  

### 5. Network Security Classification

#### Observation
Fortigate UTM logs classify the traffic as:

- Category: `Botnet`  
- Application: `Cerber.Botnet`  

#### Interpretation
Network-level enrichment confirms:

- The system is communicating with known malicious infrastructure  
- The traffic is associated with the Cerber malware family  

## Observations

- The compromised host exhibits high-volume outbound communication  
- Traffic is primarily directed over a non-standard port (`6892`)  
- A single HTTP request indicates reconnaissance behavior  
- IDS and firewall telemetry align with known malware activity  

## Interim Conclusion

The network behavior associated with the `osk.exe` process is consistent with botnet communication linked to the Cerber malware family. The combination of high-volume outbound connections, non-standard port usage, reconnaissance activity, and threat intelligence correlation confirms malicious network activity and indicates active participation in a botnet infrastructure.
