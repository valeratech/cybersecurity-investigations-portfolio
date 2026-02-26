# Lessons Learned

**Case ID:** 006  
**Time Standard:** UTC  

## 1. Detection Gaps

- WMI execution was not monitored.
- PowerShell activity lacked alerting.
- LSASS memory access was not restricted.
- Outbound connections on non-standard ports were allowed.

## 2. Early Detection Opportunities

- Alert on WmiPrvSE.exe spawning PowerShell.
- Detect non-System32 execution of lsass.exe.
- Monitor full-memory access to LSASS.
- Correlate PowerShell execution with outbound TCP sessions.

## 3. Defensive Improvements

- Enable Sysmon (ProcessCreate, ProcessAccess, NetworkConnect).
- Enforce Credential Guard or LSASS protection.
- Enable PowerShell Script Block Logging.
- Restrict WMI remote execution where unnecessary.

## 4. Key Takeaway

This case demonstrates a classic post-exploitation chain:

WMI execution → PowerShell staging → Reverse TCP shell → LSASS credential dump.

Behavioral correlation across process, file, and network telemetry is essential for reliable detection.
