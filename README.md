![Splunk](https://img.shields.io/badge/Splunk-Enterprise%20Security-black?logo=splunk)
![Windows](https://img.shields.io/badge/Windows-Event%20Logs-blue?logo=windows)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-success)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![SPL](https://img.shields.io/badge/SPL-Detection%20Engineering-orange)
# Threat Hunting & Detection Engineering Lab

## Overview

This repository showcases practical threat hunting and detection engineering techniques using Splunk Enterprise Security, Windows Security Event Logs, Sysmon, SPL, and the MITRE ATT&CK Framework.

The project demonstrates how security telemetry can be analyzed to detect malicious activity, investigate Indicators of Compromise (IOCs), and develop detection logic aligned with adversary tactics and techniques.

---

## Objectives

- Develop SPL-based detection logic for Windows environments
- Hunt for malicious activity using Windows Security Event Logs and Sysmon
- Detect PowerShell abuse and suspicious command execution
- Identify suspicious process execution
- Detect brute-force authentication attempts
- Detect common Windows persistence techniques
- Correlate multiple log sources during investigations
- Map detections to the MITRE ATT&CK Framework

---

## Technologies

| Technology | Purpose |
|------------|---------|
| Splunk Enterprise Security | Security Information and Event Management (SIEM) |
| Splunk Processing Language (SPL) | Detection Engineering & Threat Hunting |
| Windows Security Event Logs | Authentication & Security Monitoring |
| Sysmon | Endpoint Telemetry & Process Monitoring |
| MITRE ATT&CK | Adversary Behavior Mapping |

---

## Repository Structure

```text
Threat-Hunting-Detection-Engineering-Lab
│
├── detections/
├── queries/
├── reports/
├── attack-mapping/
├── datasets/
└── images/
```

---

## Detection Use Cases

| Detection Use Case | MITRE ATT&CK |
|--------------------|--------------|
| PowerShell Abuse Detection | T1059.001 |
| Encoded PowerShell Commands | T1059.001 |
| Suspicious Process Execution | T1059 |
| Brute Force Logon Detection | T1110 |
| Registry Run Key Persistence | T1547.001 |
| Scheduled Task Persistence | T1053.005 |

---

## Skills Demonstrated

- Threat Hunting
- Detection Engineering
- SPL Query Development
- Windows Log Analysis
- Sysmon Analysis
- IOC Investigation
- Security Event Correlation
- MITRE ATT&CK Mapping
- SOC Investigation Methodology

---

## Disclaimer

This repository contains lab-generated content created for learning and portfolio purposes.

No confidential, proprietary, or production data from any organization is included.
