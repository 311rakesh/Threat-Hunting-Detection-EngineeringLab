# Sysmon Configuration Guide

## Overview

Sysmon (System Monitor) is a Microsoft Sysinternals tool that extends Windows event logging by providing detailed telemetry about system activity.

Unlike standard Windows Security logs, Sysmon records rich endpoint events that help security analysts detect malware, persistence, credential theft, lateral movement, and other attacker techniques.

Many detections in this repository use Sysmon events to improve visibility and reduce false positives.

---

# Common Sysmon Event IDs

| Event ID | Description | Security Use Case |
|----------|-------------|-------------------|
| 1 | Process Creation | Detect suspicious process execution |
| 2 | File Creation Time Changed | Timestomping detection |
| 3 | Network Connection | Detect C2 communication |
| 5 | Process Terminated | Process lifecycle tracking |
| 7 | Image Loaded | DLL sideloading detection |
| 8 | CreateRemoteThread | Process injection detection |
| 10 | Process Access | Credential dumping detection |
| 11 | File Created | Malware dropper detection |
| 12 | Registry Object Created/Deleted | Registry persistence |
| 13 | Registry Value Modified | Run key persistence |
| 22 | DNS Query | Detect suspicious domains |

---

# Important Sysmon Events

## Event ID 1 – Process Creation

Records:

- Process name
- Parent process
- Command line
- User
- Hashes
- Process GUID

Common detections:

- PowerShell abuse
- LOLBins
- Office spawning PowerShell
- Suspicious command execution

---

## Event ID 3 – Network Connection

Records:

- Source IP
- Destination IP
- Destination Port
- Protocol
- Process initiating the connection

Common detections:

- Command and Control (C2)
- Beaconing
- Suspicious outbound connections

---

## Event ID 11 – File Creation

Useful for detecting:

- Malware downloads
- Dropped executables
- Ransomware staging
- Suspicious files in Temp or Downloads folders

---

## Event ID 13 – Registry Value Set

Records changes to registry values.

Useful for detecting:

- Run key persistence
- Malware autostart entries
- Unauthorized registry modifications

---

# Why Sysmon Matters

Sysmon provides significantly more detail than default Windows logging, making it a key telemetry source for threat hunting and detection engineering.

Combining Windows Security logs with Sysmon enables higher-confidence detections and richer investigations.

---

# Best Practices

- Use the latest Sysmon version.
- Deploy a community-reviewed configuration (such as SwiftOnSecurity or Olaf Hartong's Sysmon Modular).
- Collect only relevant events to reduce noise.
- Forward Sysmon logs to the SIEM.
- Regularly review and tune Sysmon configuration based on your environment.

---

# References

- Microsoft Sysinternals Sysmon
- SwiftOnSecurity Sysmon Configuration
- Olaf Hartong Sysmon Modular
- MITRE ATT&CK Framework
