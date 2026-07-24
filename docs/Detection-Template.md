# Detection Engineering Template

Every detection in this repository follows a standardized structure to ensure consistency, maintainability, and ease of investigation.

## Standard Detection Structure

1. Detection Overview
2. Detection Objective
3. Attack Scenario
4. Detection Scope
5. Required Log Sources
6. Windows Event IDs
7. Sysmon Event IDs
8. MITRE ATT&CK Mapping
9. Detection Logic
10. SPL Query
11. Investigation Workflow
12. Potential False Positives
13. Detection Tuning
14. Analyst Response
15. References

## Design Principles

- Focus on attacker behavior instead of file hashes.
- Reduce false positives through tuning.
- Use multiple telemetry sources where possible.
- Align detections with the MITRE ATT&CK framework.
- Ensure detections are practical for SOC analysts to investigate.
