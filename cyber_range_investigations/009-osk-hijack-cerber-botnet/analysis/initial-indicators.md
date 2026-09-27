# Initial Indicators

**Document Type:** Analysis  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

This document sets out the report that opened the investigation and the first values the record establishes about the suspicious binary.

## Trigger

**Range-supplied.** The scenario states that an IT technician reported an unexpected file in the registry of an employee they were assisting, and asks whether the file is legitimate or malicious and what it is doing. Q2 refers to it as the `osk.exe` entry reported by the technician.
The record contains no registry query or result, so the entry's key, value and path are not recorded.

## Indicators

### 1. Execution Path (Q2, Q4)

#### Observation

**Range-accepted.** The suspicious executable's path is `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`.
**Observed.** The `Image` field summary shows this path in 49,594 events.
**Range-accepted.** The legitimate On-Screen Keyboard is expected in `C:\Windows\System32`.

#### Analyst Interpretation

**Analyst inference.** The notes read a binary named `osk.exe` running from a user-profile `AppData\Roaming` folder with a GUID-like name, rather than from `C:\Windows\System32`, as a masquerading executable. They list persistence, privilege escalation and living-off-the-land abuse as possibilities.

### 2. Event Volume (Q3)

#### Observation

**Range-accepted.** The Windows event log search returned 49,608 events containing `osk.exe`.
**Observed.** 49,594 events carry the suspicious path as their `Image` value.

#### Analyst Interpretation

**Analyst inference.** The notes read this volume as unusual for an accessibility tool.

### 3. Network Activity (Q6, Q7)

#### Observation

**Observed.** Destination port 6892 appears in 48,196 events (99.998%) and port 80 in 1 event (0.002%), among events carrying `DestinationPort` (97.156%).
**Range-accepted.** The destination ports are 6892 and 80 (Q6), and there are 16,384 distinct destination addresses of connection attempts on port 6892 (Q7).

#### Analyst Interpretation

**Analyst inference.** The notes suggest custom-service or command-and-control communication on port 6892, and read the destination count as consistent with automated scanning or botnet-like behaviour.

### 4. Endpoint Context (Q5)

#### Observation

**Range-accepted.** Host `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100`, user `bob.smith`.

## Summary

- **Range-supplied:** a reported registry entry for `osk.exe`, with no recorded registry detail.
- **Range-accepted and Observed:** the `AppData\Roaming` path of the executing binary, outside `C:\Windows\System32`.
- **Range-accepted:** 49,608 events containing `osk.exe`.
- **Observed and Range-accepted:** destination ports 6892 and 80, and 16,384 distinct destination addresses of connection attempts on port 6892.
- **Range-accepted:** the host, internal address and user.

## Assessment

**Analyst inference.** Taken together, the path, the volume and the network activity mark the binary as suspicious and lead to the host, network and threat-intelligence questions that follow.
They do not establish how the binary persisted or arrived on the host.
