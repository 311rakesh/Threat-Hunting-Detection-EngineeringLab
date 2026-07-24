# MITRE ATT&CK Framework

## Overview

The MITRE ATT&CK Framework is a globally recognized knowledge base of adversary tactics, techniques, and procedures (TTPs). It helps security teams classify attacker behavior and develop detections based on real-world techniques rather than malware names or file hashes.

This repository maps each detection to one or more MITRE ATT&CK techniques to provide context and improve investigation workflows.

---

# ATT&CK Tactics

Some common tactics covered in this repository include:

| Tactic | Description |
|---------|-------------|
| Initial Access | How an attacker gains access to a system |
| Execution | Running malicious code |
| Persistence | Maintaining access after a reboot or logout |
| Privilege Escalation | Gaining higher-level permissions |
| Defense Evasion | Avoiding security controls |
| Credential Access | Stealing credentials |
| Discovery | Learning about the environment |
| Lateral Movement | Moving between systems |
| Collection | Gathering sensitive data |
| Command and Control | Communicating with attacker infrastructure |
| Impact | Disrupting or damaging systems |

---

# Techniques Used in This Repository

| Technique ID | Technique |
|--------------|-----------|
| T1059.001 | PowerShell |
| T1110 | Brute Force |
| T1218 | Signed Binary Proxy Execution (LOLBins) |
| T1547.001 | Registry Run Keys / Startup Folder |
| T1053.005 | Scheduled Task |

---

# Why ATT&CK Mapping Matters

Mapping detections to MITRE ATT&CK helps:

- Standardize detection engineering.
- Improve threat hunting.
- Prioritize investigation activities.
- Measure detection coverage.
- Communicate detections using a common language.

---

# Best Practices

- Map detections to the most specific ATT&CK technique whenever possible.
- Review mappings as ATT&CK is updated.
- Validate detections against real attack scenarios.
- Use ATT&CK Navigator to visualize detection coverage.

---

# References

- MITRE ATT&CK Framework
- MITRE ATT&CK Navigator
