# Initial Indicators

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

Document the initial alerts, anomalies, and suspicious activity that triggered the investigation.

## Initial Trigger

An IT technician reported a suspicious file referenced in the Windows registry associated with the `osk.exe` binary. This triggered further investigation into potential misuse of a legitimate accessibility tool.

## Indicators Identified

### 1. Suspicious Registry Reference

#### Observation
A registry entry referenced an `osk.exe` executable located outside the standard Windows system directory.

#### Interpretation
Accessibility binaries such as `osk.exe` are commonly abused for persistence due to their ability to execute at the Windows logon screen. A registry reference to a non-standard path is a strong indicator of compromise.

### 2. Abnormal Execution Path

#### Observation
The `osk.exe` binary was observed executing from:

`C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`

Expected legitimate path:

`C:\Windows\System32\osk.exe`

#### Interpretation
Execution from a user-controlled directory with a GUID-like structure strongly indicates:

- Masquerading  
- Malware staging  
- Persistence mechanism  

### 3. Unusual Activity Volume

#### Observation
Total events associated with `osk.exe`:

`49,608`

#### Interpretation
The On-Screen Keyboard is not typically used at this scale, suggesting automated execution or malicious activity.

### 4. Suspicious Network Behavior

#### Observation
The process initiated:

- High-volume outbound connections over port `6892`  
- A single HTTP connection over port `80`  

#### Interpretation
This pattern suggests:

- Command-and-control communication  
- Botnet activity  
- Reconnaissance behavior  

### 5. Endpoint Context

#### Observation
Activity associated with:

- Host: `we8105desk[.]waynecorpinc[.]local`  
- IP: `192[.]168[.]250[.]100`  
- User: `bob.smith`  

#### Interpretation
The suspicious activity is tied to a specific endpoint and user account, enabling targeted investigation and containment.

## Summary of Initial Indicators

- Registry reference to non-standard `osk.exe` path  
- Execution of masquerading binary in AppData directory  
- Abnormal process activity volume (~49,608 events)  
- High-volume outbound network communication  
- Indicators of persistence and potential privilege escalation  

## Assessment

The initial indicators strongly suggest a compromised host leveraging a hijacked accessibility binary for persistence and malicious execution. These findings warranted deeper investigation into host behavior, network activity, and threat attribution.
