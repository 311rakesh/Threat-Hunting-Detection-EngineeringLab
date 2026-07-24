
<h1 align="center">Suspicious Process Execution Detection</h1>

<p align="center">
Detection Engineering • Threat Hunting • Splunk ES • Windows Event Logs • Sysmon • MITRE ATT&CK
</p>
<p align="center">

![Splunk](https://img.shields.io/badge/Splunk-Enterprise_Security-000000?style=for-the-badge&logo=splunk)
![Windows](https://img.shields.io/badge/Windows_Event_Logs-0078D6?style=for-the-badge&logo=windows)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-2E8B57?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![SPL](https://img.shields.io/badge/SPL-Detection_Engineering-orange?style=for-the-badge)

</p>

## Detection Overview

Threat actors often abuse legitimate Windows processes to execute malicious payloads while attempting to blend in with normal system activity. Monitoring suspicious parent-child process relationships can reveal malware execution, phishing payloads, LOLBins, and post-exploitation activity.

This detection identifies suspicious process executions by analyzing Windows Security Event Logs and Sysmon Process Creation events.

---

# Detection Objective

Detect abnormal process creation based on executable names, command-line arguments, and unusual parent-child process relationships.

---

# Detection Scope

**Operating Systems**

- Windows 10
- Windows 11
- Windows Server 2016+
- Windows Server 2019+
- Windows Server 2022

**Required Data Sources**

- Windows Security Event ID 4688
- Sysmon Event ID 1

---

# Log Sources

| Source | Event ID | Description |
|---------|----------|-------------|
| Windows Security | 4688 | Process Creation |
| Sysmon | 1 | Process Creation |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | Signed Binary Proxy Execution | T1218 |
| Defense Evasion | System Binary Proxy Execution | T1218 |

---

# Detection Logic

Generate an alert when commonly abused binaries execute or when suspicious parent-child relationships are observed.

Examples include:

- winword.exe → powershell.exe
- excel.exe → cmd.exe
- outlook.exe → mshta.exe
- explorer.exe → certutil.exe
- wscript.exe → powershell.exe
- rundll32.exe executing unexpected DLLs

---

# Production SPL Query

```spl
index=windows (EventCode=4688 OR EventCode=1)

| eval Process=coalesce(Image,New_Process_Name,process_name)
| eval ParentProcess=coalesce(ParentImage,Parent_Process_Name)
| eval CommandLine=coalesce(CommandLine,Process_Command_Line)

| where
(
match(lower(ParentProcess),"winword.exe|excel.exe|outlook.exe")
AND
match(lower(Process),"powershell.exe|cmd.exe|mshta.exe|wscript.exe|cscript.exe")
)

OR

match(lower(Process),"certutil.exe|regsvr32.exe|rundll32.exe|bitsadmin.exe")

| table _time host user ParentProcess Process CommandLine

| sort -_time
```

---

# Investigation Workflow

1. Identify the parent process.
2. Determine whether the execution originated from a user action.
3. Review the command line.
4. Identify child processes.
5. Review network connections.
6. Review file creation events.
7. Search for persistence mechanisms.
8. Map activity to MITRE ATT&CK.

---

# Potential False Positives

- Administrative scripts
- Software installation
- Microsoft Office add-ins
- Enterprise management tools

---

# Detection Tuning

Exclude:

- Approved administration tools
- Enterprise software deployment
- Known management agents

Review exclusions regularly.

---

# Analyst Response

- Review command-line arguments.
- Identify downloaded payloads.
- Verify digital signatures.
- Search for related activity.
- Isolate endpoint if malicious.

---

# References

- MITRE ATT&CK T1059
- MITRE ATT&CK T1218
- Microsoft Sysmon Documentation
