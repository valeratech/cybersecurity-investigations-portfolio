# Host-Based Analysis

**Document Type:** Analysis  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

This document sets out what the record shows about the suspicious binary on the endpoint: its event volume, path, host context and hash.

## Data Sources

- Windows event logs in XML (Sysmon telemetry), searched in Splunk (Q3 to Q5, Q8).
- The `Image` field summary captured in the Q4 screenshot.

## Analysis

### 1. Event Volume (Q3)

#### Observation

**Range-accepted.** The search for `osk.exe` returned 49,608 events.

#### Analyst Interpretation

**Analyst inference.** The notes read this as a volume unusual for an accessibility tool.

### 2. Execution Path (Q2, Q4)

#### Observation

**Range-accepted.** Suspicious path: `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`.
**Range-accepted.** Expected location of the legitimate binary: `C:\Windows\System32`.
**Observed.** The `Image` field summary reports 12 values across 100% of events and shows the top 10. The suspicious path accounts for 49,594 events (99.972%).
**Observed.** The other values shown are `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp` (3 events), `C:\Windows\System32\bcdedit.exe` (2), and one event each for `C:\Program Files (x86)\Internet Explorer\iexplore.exe`, `C:\Windows\SysWOW64\explorer.exe`, `C:\Windows\System32\PING.EXE`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\notepad.exe`, `C:\Windows\System32\taskkill.exe` and `C:\Windows\System32\vssadmin.exe`.

#### Limits

The record does not show which field matched `osk.exe` in the events behind these other values, and it records no command lines, so no action is attributed to them.

#### Analyst Interpretation

**Analyst inference.** The notes read the user-profile `AppData\Roaming` location and the GUID-like folder name as signs of a masquerading executable and of obfuscation.

### 3. Host Context (Q5)

#### Observation

**Range-accepted.** Computer `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100`, user `bob.smith`, from the `Computer`, `SourceIp` and `User` fields.

### 4. Image-Load Events and Hash (Q8)

#### Observation

**Range-accepted.** SHA-256 `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`, extracted from the `Hashes` field of Image Loaded (Event ID 7) events.

#### Limits

The search `ImageLoaded="*osk.exe*"` matches both the legitimate and the suspicious path, as the notes state. The hash is the answer the range accepted for the suspicious binary.

### 5. Persistence

**Range-supplied.** The lab title describes Cerber ransomware persistence via an OSK hijack, and Q1 asks why an attacker might target the registry settings of `osk.exe` to establish persistence.
**External enrichment.** OSINT in the notes explains that the On-Screen Keyboard can be launched at the Windows logon screen with elevated privileges.
The record contains no registry query or result and no observation of a persistence mechanism. Persistence here is range-supplied framing, not an observed finding.

## Assessment

**Analyst inference.** A binary named `osk.exe` ran from a user-profile folder outside `C:\Windows\System32` in 49,594 events on `we8105desk[.]waynecorpinc[.]local`, and its hash is the value VirusTotal associates with Cerber (Q9). The notes read this as a masquerading executable.
