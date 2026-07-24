# Windows Event Logging

## Overview

Windows Event Logs record operating system, security, and application activities. These logs provide the primary telemetry used by Security Information and Event Management (SIEM) platforms to detect suspicious behavior.

Many detection rules in this repository rely on Windows Security Logs and Sysmon events to identify attacker techniques.

---

# Common Windows Security Event IDs

| Event ID | Description | Security Use Case |
|----------|-------------|-------------------|
| 4624 | Successful Logon | User authentication monitoring |
| 4625 | Failed Logon | Brute-force detection |
| 4634 | Logoff | Session tracking |
| 4648 | Explicit Credential Logon | Credential abuse detection |
| 4672 | Special Privileges Assigned | Privileged account monitoring |
| 4688 | Process Creation | Process execution monitoring |
| 4697 | Service Installed | Persistence detection |
| 4698 | Scheduled Task Created | Persistence detection |
| 4702 | Scheduled Task Updated | Persistence monitoring |
| 4720 | User Account Created | Unauthorized account creation |
| 4726 | User Account Deleted | Account management auditing |
| 4732 | User Added to Security Group | Privilege escalation monitoring |
| 4738 | User Account Changed | Identity monitoring |

---

# Why Event ID 4688 Is Important

Event ID **4688 (Process Creation)** is one of the most valuable Windows Security events for threat detection.

It records:

- Process Name
- Parent Process
- Command Line
- User
- Time of Execution

Many detections in this repository, including PowerShell abuse, LOLBins, and suspicious process execution, depend on this event.

---

# Common Detection Use Cases

- PowerShell abuse
- Encoded PowerShell
- LOLBins
- Process injection indicators
- Office spawning PowerShell
- Command execution
- Persistence mechanisms
- Lateral movement

---

# Best Practices

- Enable Advanced Audit Policy for Process Creation.
- Enable command-line logging for Event ID 4688.
- Forward logs to a SIEM platform.
- Combine Windows Security Logs with Sysmon for richer visibility.

---

# References

- Microsoft Windows Security Auditing Documentation
- Microsoft Sysmon Documentation
- MITRE ATT&CK Framework
