# Final Investigation Report — Case 004

**Document Type:** Final Report  
**Case Title:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Documentation Started:** 2026-01-25  
**Documentation Last Updated:** 2026-01-25  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

AlphaFinance Group identified suspicious activity originating from a finance department workstation following access to a spoofed Microsoft 365 portal. The investigation confirmed a phishing-based initial access vector that delivered a malicious Rich Text Format (RTF) document. The CyberRange record attributes the exploitation step to a Microsoft Equation Editor vulnerability and records `CVE-2017-11882` as the answer. That attribution is range-reported; the completed Q/A record contains no Word or Equation Editor process record independently establishing the sequence.

Post-exploitation activity included execution of a PowerShell dropper, range-characterized process spoofing, multiple discovery commands, redundant persistence mechanisms, and outbound command-and-control (C2) communications over non-standard ports.

The attacker demonstrated intent to maintain long-term access using user-level persistence and outbound command-and-control communications.

## 2. Investigation Scope & Objectives

### Objectives
- Identify the initial access vector
- Determine the delivery and exploit mechanism
- Trace execution and post-exploitation activity
- Identify persistence mechanisms
- Identify C2 infrastructure and communication details

### Scope
- Disk forensics (NTFS metadata and user artifacts)
- Browser artifacts (Microsoft Edge)
- Registry analysis (SAM, NTUSER.DAT, SOFTWARE)
- Host-based telemetry (Sysmon)

## 3. Initial Access & Delivery

### Phishing Access
The targeted user (`harrisr`) accessed a spoofed Microsoft-themed portal hosted on external infrastructure.

- Access Time: `2025-05-23 10:52:59 UTC`
- Delivery Method: Web-based phishing portal
- Evidence Source: Microsoft Edge browsing history

### Payload Delivery
A document named `Financial_Report.rtf` was downloaded shortly after accessing the phishing site.

- Download Time: `2025-05-23 10:53:22 UTC`
- Download Location: `C:\Users\harrisr\Downloads\`
- Evidence: Browser download records and NTFS `$MFT`

Zone.Identifier metadata confirmed the document originated from the internet.

## 4. Exploitation & Execution

### Exploited Application
- Product: Microsoft Office
- Component: Equation Editor (`EQNEDT32.EXE`) — range-reported attribution
- Version: `15.0.4420.1017` — observed
- Vulnerability: `CVE-2017-11882` — range-reported attribution

The CyberRange question set supplies the premise that opening the RTF in Word triggered the Equation Editor and exploited a known vulnerability, and records `CVE-2017-11882` as that vulnerability. The analyst notes describe the recorded CVE as an Equation Editor remote code execution issue associated with a crafted RTF; that is a description of the named CVE rather than case telemetry. No `WINWORD.EXE` or `EQNEDT32.EXE` process record is present in the completed Q/A record to establish the sequence independently.

### Execution Chain
The CyberRange question set supplies the premise that the detected exploit dropped `msupdate.ps1`. The surviving record establishes that the script was created at `11:15:43` and launched in a hidden context via `cmd.exe` at `11:17:44`; it preserves neither the script's contents nor any artifact linking its creation to an exploit process. The Sysmon record shows `notepad.exe` as the parent of the `cmd.exe` process; the CyberRange characterizes that relationship as process spoofing.

- Script Creation Time: `2025-05-23 11:15:43 UTC`
- Execution Evidence: Sysmon process creation events

## 5. Post-Exploitation Activity

### Discovery Commands
The case record covers multiple built-in Windows commands used for host and network discovery:

- `whoami` — CyberRange question premise; no process record for it is present in the completed Q/A record
- `ipconfig /all` — Sysmon EID 1
- `ping` — Sysmon EID 1
- `netstat` — Sysmon EID 1

The observed `ipconfig`, `ping`, and `netstat` commands support host and network discovery during subsequent activity.

### Process Spoofing
The CyberRange question set states that process spoofing was used to evade detection and records `13852` as the spoofed-process PID. The surviving Sysmon record establishes that PID `13852`, running `notepad.exe`, is the parent of the `cmd.exe` process that launched the PowerShell script. Both the characterization and the evasion purpose are range-supplied; the record establishes the process relationship.

## 6. Persistence Mechanisms

The attacker created **redundant user-level persistence** mechanisms.

### Registry Run Key
- Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Value Name: `Microsoft Update Assistant`
- Creation Time: `2025-05-23 11:17:50 UTC`

### Startup Folder Persistence
- File: `WindowsUpdate.lnk`
- Path: User Startup folder
- Creation Time: `2025-05-23 11:17:51 UTC`

The Run key value preserves an encoded PowerShell command that, if executed, would retrieve a payload from external infrastructure and launch the downloaded file. The Startup folder LNK is evidenced by its file-creation event only; its target and contents are not present in the completed Q/A record. Execution of either persistence mechanism is not established by the completed Q/A record.

## 7. Command-and-Control (C2)

Host-based telemetry confirmed outbound connections to an external host associated with attacker-controlled infrastructure.

- External Host: `63[.]176[.]96[.]97`
- Observed Ports:
  - `4444` (primary)
  - `8080` (secondary)
- Protocol: TCP
- Evidence Source: Sysmon network connection events

Use of non-standard ports suggests an attempt to evade basic network detection controls.

## 8. Timeline Summary (UTC)

- `10:52:59` — User accessed phishing portal
- `10:53:22` — Malicious RTF downloaded
- `10:53:22` — File created on disk with internet MOTW
- `10:54:02` — Outbound network connection to external host
- `10:59:18–10:59:48` — Discovery commands executed
- `11:15:43` — PowerShell script created
- `11:17:44` — Hidden PowerShell execution observed
- `11:17:50` — Registry persistence created
- `11:17:51` — Startup persistence created

## 9. Indicators of Compromise (Defanged)

### URLs
- `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]`

### Files
- `Financial_Report.rtf`
- `msupdate.ps1`
- `WindowsUpdate.lnk`
- `msupdate-<random4>.exe`

### Network
- `63[.]176[.]96[.]97:4444`
- `63[.]176[.]96[.]97:8080`

## 10. Assessment & Impact

This incident represents a **high-risk compromise** involving:
- Client-side exploitation
- Arbitrary code execution
- Multiple persistence mechanisms
- Active external C2 communications

If this activity had occurred in a production environment, it would warrant:
- Immediate host isolation
- Credential reset for affected user
- Enterprise-wide IOC sweeping
- Review of Office patch levels

## 11. Lessons Learned

- Legacy Office components remain high-risk when unpatched
- RTF-based exploits continue to be effective phishing payloads
- User-level persistence is sufficient for long-term access
- Host-based telemetry is critical when network visibility is limited

## 12. Limitations

- **Range-supplied context.** Some investigation context originates in CyberRange scenario and question premises rather than independently preserved telemetry. Such context should be interpreted according to that provenance unless the surviving record independently corroborates it.
- **Claim strength.** Some causal and technical characterizations are not independently demonstrated by the surviving artifacts and should not be read as direct observations.
- **Bounded record.** Interpretation of this report is bounded by the completed question-set record.

## 13. Conclusion

The investigation conclusively identified a phishing-driven compromise of a user workstation, persistence mechanisms, and command-and-control activity. The exploitation step is attributed by the CyberRange record to a known vulnerability and is not independently established by preserved Word or Equation Editor process telemetry. Evidence supports deliberate attacker actions consistent with real-world tradecraft, including stealthy execution, redundancy in persistence, and covert command-and-control communication.

This case highlights the continued relevance of disk forensics and host telemetry in detecting and reconstructing sophisticated endpoint intrusions.

## Related Documents

- [Case Overview](../README.md)
- [Timeline](../case-notes/timeline.md)
- [Indicators of Compromise](../evidence-metadata/artifacts-of-interest.md)
- [Evidence Sources](../evidence-metadata/evidence-sources.md)
