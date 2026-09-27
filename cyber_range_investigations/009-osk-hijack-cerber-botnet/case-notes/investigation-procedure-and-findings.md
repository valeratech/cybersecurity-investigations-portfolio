# Investigation Procedure and Findings

**Document Type:** Analysis  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document follows the recorded question set step by step. Each step gives the question as the range worded it, the recorded answer, what the analyst's notes show, and any interpretation, marked as analyst inference.

## Investigation Workflow

### Step 1 – Purpose of `osk.exe` (Q1)

- **Range-supplied.** The question asks for the Windows Ease of Access feature associated with `osk.exe`, and why an attacker might target its registry settings to establish persistence.
- **Range-accepted.** Accessibility On-Screen Keyboard.
- **External enrichment.** The notes cite Microsoft documentation describing a built-in virtual keyboard, and add from OSINT that it can be launched at the Windows logon screen with elevated privileges.

### Step 2 – Expected Path (Q2)

- **Range-supplied.** The question asks for the expected path of the legitimate On-Screen Keyboard, as a baseline for detecting a masquerading file.
- **Range-accepted.** `C:\Windows\System32`.
- **Observed.** The notes record this as an OSINT baseline.

### Step 3 – Event Count (Q3)

- **Range-supplied.** The question asks for the total number of Sysmon events (`XmlWinEventLog`) associated with `osk.exe`.
- **Range-accepted.** 49,608.
- **Observed.** The `stats count` search returned 49,608 events.
- **Analyst inference.** The notes read this volume as unusual for an accessibility tool and a reason to investigate further.

### Step 4 – Image Path (Q4)

- **Range-supplied.** The question asks for the full file path of the suspicious executable.
- **Range-accepted.** `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`.
- **Observed.** The `Image` field summary shows this path in 49,594 events (99.972%), among 12 values present in 100% of events.
- **Analyst inference.** The notes treat the user-profile `AppData\Roaming` location and the GUID-like folder, outside `C:\Windows\System32`, as indicating a masquerading executable.

### Step 5 – Host, Address and User (Q5)

- **Range-supplied.** The question asks for the computer, internal IP address and user account associated with the suspicious file.
- **Range-accepted.** Computer `we8105desk[.]waynecorpinc[.]local`; internal IP `192[.]168[.]250[.]100`; user `bob.smith`.
- **Observed.** The values come from the `Computer`, `SourceIp` and `User` fields.

### Step 6 – Destination Ports (Q6)

- **Range-supplied.** The question asks for the destination port values associated with the suspicious process.
- **Range-accepted.** 6892, 80.
- **Observed.** The `DestinationPort` field summary shows 2 values across 97.156% of events: 6892 in 48,196 events (99.998%) and 80 in 1 event (0.002%).
- **Analyst inference.** The notes suggest custom-service or command-and-control communication on port 6892, and fallback, beacon or test traffic on port 80, as possibilities.

### Step 7 – Distinct Destinations on Port 6892 (Q7)

- **Range-supplied.** The question asks how many unique destination IP addresses the process attempted to contact on the high-volume port, and calls this the external infrastructure involved.
- **Range-accepted.** 16,384: the distinct destination addresses of connection attempts on port 6892.
- **Analyst inference.** The notes read the count as consistent with automated scanning or botnet-like behaviour.

### Step 8 – SHA-256 (Q8)

- **Range-supplied.** The question asks for the SHA-256 of the suspicious binary, using Sysmon Event ID 7 (Image Loaded).
- **Range-accepted.** `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`.
- **Observed.** The value was taken from the `Hashes` field. The notes state that the wildcard in the search matches both the legitimate and the suspicious path; the recorded answer is the hash the range accepted for the suspicious binary.

### Step 9 – VirusTotal Family (Q9)

- **Range-supplied.** The question asks for the common malware family name from the VirusTotal Detection page.
- **Range-accepted.** Cerber.
- **External enrichment.** VirusTotal vendor detections and the community entries quoted in the notes associate the hash with Cerber.

### Step 10 – Fortigate UTM Category (Q10)

- **Range-supplied.** The question asks for the malware category the firewall's enrichment assigns to traffic sharing an attribute with most of the `osk.exe` events.
- **Range-accepted.** Botnet, the Fortigate `appcat` value.
- **Observed.** The notes carry destination port 6892 into the Fortigate UTM search and reproduce one event: source `192[.]168[.]250[.]100`, destination `85[.]93[.]63[.]252`, `udp/6892`, action pass, application list Honeypot-Access, `appcat` Botnet, `app` Cerber.Botnet.
- The category is Fortigate enrichment. It records a classification of the traffic, not communication with botnet infrastructure.

### Step 11 – Fortigate UTM Name (Q11)

- **Range-supplied.** The question asks for the name Fortigate gives this malware.
- **Range-accepted.** Cerber.Botnet, the Fortigate `app` value.

### Step 12 – Primary Function (Q12)

- **Range-supplied.** The question asks for the malware's primary function, from OSINT.
- **Range-accepted.** Ransomware.
- **External enrichment.** OSINT in the notes describes Cerber as ransomware that encrypts files and demands payment, with command-and-control capability.
- No encryption, ransom note or other ransomware effect is recorded in this case.

### Step 13 – Port-80 Connection and Suricata Alert (Q13)

- **Range-supplied.** The question asks for the remote address contacted over port 80, and the Suricata `alert.signature` for alert events to it.
- **Observed.** The notes give the destination of the single port-80 event as `54[.]148[.]194[.]58`.
- **Range-accepted.** Suricata signature `ET POLICY Possible External IP Lookup ipinfo.io`. The analyst's notes give the signature as `ET INFO External IP Lookup`; the two recorded values differ and are not reconciled.
- **Analyst inference.** The notes interpret the alert as the system discovering its public IP address, which they associate with malware reconnaissance.

## Summary of Procedure

The question set moved from OSINT baselines (Q1, Q2) to searches of the Windows event logs (Q3 to Q8), then to external threat intelligence (Q9, Q12) and cross-source searches of Fortigate UTM and Suricata logs (Q10, Q11, Q13).

The record does not establish how the binary arrived on the host, how it persisted, or effects beyond the recorded network activity.
