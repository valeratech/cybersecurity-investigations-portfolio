# Network Indicators of Compromise – TeamCity APT Ransomware Investigation

**Document Type:** IOC Collection

## Overview

This document contains confirmed, normalized, and defanged indicators of compromise (IOCs) identified during the investigation. All entries have been deduplicated and validated against observed malicious activity.

## IP Addresses

- `3[.]90[.]168[.]151` (Attacker Infrastructure)
- `10[.]10[.]3[.]4` (Beachhead Host – JB01)
- `10[.]10[.]0[.]6` (SQL Server)
- `10[.]10[.]0[.]4` (Domain Controller – DC01)
- `10[.]10[.]0[.]7` (File Server – FS01)
- `10[.]10[.]1[.]4` (IT Workstation – IT01)

## Domains / FQDNs

- `jb01[.]cyberrange[.]cyberdefenders[.]org`
- `cyberrange[.]cyberdefenders[.]org`
- `ec2-3-90-168-151.compute-1.amazonaws[.]com`

## URLs

- `https[:]//github[.]com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe`

## File Names

- `java64.exe`
- `AddressResourcesSpec.dll`
- `WowIcmpRemoveReg.dll`
- `EDRSandblast.exe`
- `winPEASx64_ofs.exe`
- `GDRV.sys`
- `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`
- `jvpd2px2at1.bmp`
- `hiv1.zip`
- `un-lock your files[.]html`

## File Extensions

- `.lsoc` (Ransomware Encryption Extension)

## Registry Keys / Values

- `HKLM\SOFTWARE\Microsoft\Windows Defender\DisableRealtimeMonitoring`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin`

## Commands

- `vssadmin.exe Delete Shadows /All /Quiet`
- `wmic product get name,version`
- `Get-WindowsDriver -Online -All`

## Network Ports

- `8080` (C2 Communication)

## Notes

- All indicators have been confirmed through log correlation and analysis.
- Indicators are defanged for safe handling and sharing.
- This list is intended for detection engineering, threat hunting, and incident response reuse.
