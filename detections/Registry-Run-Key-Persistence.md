# Registry Run Key Persistence Detection

## Detection Overview

Registry Run Keys are commonly abused by attackers to achieve persistence on Windows systems. By adding malicious executables or scripts to autorun registry locations, malware can automatically execute whenever a user logs on.

This detection identifies modifications to Windows Run and RunOnce registry keys using Sysmon Registry Events and correlates them with process creation activity for investigation.

---

# Detection Objective

Detect unauthorized modifications to Windows Registry Run Keys that may indicate an attempt to establish persistence.

---

# Attack Scenario

An attacker gains access to a workstation through a phishing email.

The attacker executes a PowerShell script that creates a registry value under:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

The malicious executable launches automatically every time the user logs in.

Sysmon records the registry modification.

Splunk detects the persistence mechanism and generates an alert.

---

# Detection Scope

**Operating Systems**

- Windows 10
- Windows 11
- Windows Server 2016+
- Windows Server 2019+
- Windows Server 2022

**Required Data Sources**

- Sysmon Event ID 13 (Registry Value Set)
- Sysmon Event ID 12 (Registry Object Create/Delete)
- Windows Event Logs (Optional)

---

# Log Sources

| Source | Event ID | Description |
|---------|----------|-------------|
| Sysmon | 12 | Registry Object Create/Delete |
| Sysmon | 13 | Registry Value Set |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |

---

# Registry Paths Monitored

- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

---

# Detection Logic

Generate an alert when:

- A registry value is created or modified
- The registry path contains:
  - CurrentVersion\Run
  - CurrentVersion\RunOnce
- The registry value points to an executable, script, or suspicious command.

---

# Production SPL Query

```spl
index=windows EventCode=13

| eval RegistryPath=coalesce(TargetObject,RegistryPath)

| where like(RegistryPath,"%CurrentVersion\\Run%")
    OR like(RegistryPath,"%CurrentVersion\\RunOnce%")

| table _time
        host
        user
        Image
        RegistryPath
        Details

| sort -_time
```

---

# Investigation Workflow

1. Identify the endpoint.
2. Review the modified registry path.
3. Determine which process created the registry value.
4. Review the executable or script referenced by the registry entry.
5. Verify whether the file is digitally signed.
6. Review parent-child process relationships.
7. Search for additional persistence mechanisms.
8. Determine whether the modification was legitimate.

---

# Potential False Positives

- Software installation
- Antivirus updates
- Enterprise management software
- Legitimate startup applications

---

# Detection Tuning

Exclude:

- Approved enterprise software
- Microsoft signed applications
- Known software deployment tools

Review exclusions regularly.

---

# Analyst Response

- Verify the registry modification.
- Investigate the referenced executable.
- Remove unauthorized persistence.
- Isolate the endpoint if malicious.
- Hunt for similar persistence across the environment.

---

# References

- MITRE ATT&CK T1547.001
- Microsoft Sysmon Documentation
- Microsoft Windows Registry Documentation
