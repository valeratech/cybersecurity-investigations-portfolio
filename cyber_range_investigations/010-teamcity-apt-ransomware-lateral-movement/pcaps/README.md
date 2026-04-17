# PCAPs Directory

**Document Type:** Reference

## Overview

This directory is reserved for packet capture (PCAP) files or references to network traffic data used during the investigation.

## Current Status

No raw PCAP files were directly analyzed in this investigation.

All network analysis was conducted using:
- Elastic network telemetry
- Pre-parsed log data from multiple hosts

## Expected Contents (If Applicable)

If PCAP data is provided in future investigations, this directory should contain:

- `.pcap` or `.pcapng` files
- Network capture exports
- Associated metadata files

## Handling Guidelines

- Do NOT modify original PCAP files
- Maintain original file integrity at all times
- Reference PCAP files in:
  - `evidence-metadata/evidence-inventory.md`
- Use read-only analysis tools (e.g., Wireshark, tcpdump)
