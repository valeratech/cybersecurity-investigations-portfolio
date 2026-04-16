# Host-Based Analysis

**Document Type:** Analysis

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

Analyze endpoint telemetry to identify suspicious process execution, persistence mechanisms, and host-level indicators associated with the `osk.exe` binary.

## Data Sources

- Sysmon Event Logs (XmlWinEventLog)  
- Windows Event Logs  

## Analysis

### 1. Process Identification

#### Observation
Search performed:

`index="botsv1" sourcetype=xmlwineventlog "osk.exe"`

Result:
- Total events: ~49,608  

#### Interpretation
The volume of activity is significantly higher than expected for a legitimate accessibility tool, indicating abnormal or automated execution.

### 2. Execution Path Validation

#### Observation
Suspicious binary path:

`C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`

Legitimate path:

`C:\Windows\System32\osk.exe`

#### Interpretation
The binary is executing from a user-controlled directory with a GUID-like folder structure, which is a common technique used for:

- Masquerading  
- Defense evasion  
- Persistence  

### 3. Host Attribution

#### Observation
Associated system context:

- Computer: `we8105desk[.]waynecorpinc[.]local`  
- Internal IP: `192[.]168[.]250[.]100`  
- User: `bob.smith`  

#### Interpretation
The malicious activity is tied to a specific endpoint and user, enabling targeted containment and remediation.

### 4. Persistence Mechanism

#### Observation
The investigation was initiated based on a suspicious registry entry referencing the `osk.exe` binary.

Accessibility binaries such as `osk.exe` can be executed at the Windows logon screen.

#### Interpretation
This behavior suggests:

- Registry-based persistence  
- Potential SYSTEM-level execution via accessibility feature hijacking  

This technique allows attackers to:

- Execute code without user authentication  
- Maintain persistence across reboots  

### 5. Binary Execution Confirmation

#### Observation
Sysmon Event ID 7 (Image Loaded) confirms the binary was loaded into memory.

Query used:

`index="botsv1" sourcetype=xmlwineventlog EventCode=7 ImageLoaded="*osk.exe*"`

Extracted hash:

`37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`

#### Interpretation
The binary is not only present on disk but actively executed, confirming malicious activity.

## Observations

- The `osk.exe` binary is executing from a non-standard path  
- Activity volume is abnormally high  
- Execution context is tied to a specific user and host  
- Binary is confirmed loaded into memory  
- Registry-based persistence is strongly indicated  

## Interim Conclusion

Host-based analysis confirms that the system is compromised via a masquerading `osk.exe` binary. The attacker leveraged a legitimate Windows accessibility feature to establish persistence and execute malicious code, consistent with known OSK hijacking techniques used in ransomware and post-exploitation scenarios.
