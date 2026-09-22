# Lessons Learned

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Unassessed Controls

The exercise supplied a memory image only. It did not expose the environment's
monitoring, alerting, credential-protection or egress settings, so none of them is
assessed here. Whether WMI activity was monitored, whether PowerShell activity raised
alerts, whether LSASS access was restricted, and whether connections to uncommon ports
were permitted by policy are all unknown.

## 2. Recommended Detection Coverage

- Alert on `WmiPrvSE.exe` spawning PowerShell.
- Detect `lsass.exe` executing from any path other than System32.
- Monitor process access to LSASS with broad access rights.
- Correlate PowerShell process trees with network sessions.

## 3. Recommended Safeguards

- Enable Sysmon (ProcessCreate, ProcessAccess, NetworkConnect).
- Enable Credential Guard or LSA protection.
- Enable PowerShell Script Block Logging.
- Restrict remote WMI execution where it is not needed.

## 4. Analytical Lessons

- A command line records what was requested, not what completed. The dump invocation in
  this case is observed; its outcome is not.
- A connection without an owning process cannot be attributed to a process tree, however
  plausible the link.
- Range questions can join observations that the evidence records separately; the
  distinction is kept in the published case.

## 5. Key Takeaway

The recorded chain is WmiPrvSE → PowerShell → masqueraded `lsass.exe` with a dump
invocation against LSASS, alongside a separately recorded TCP connection and MFT entry.
Behavioral correlation across process, file and network telemetry is what would join
them in a real investigation.
