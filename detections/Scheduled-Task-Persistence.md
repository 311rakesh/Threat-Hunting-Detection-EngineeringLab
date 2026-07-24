# Scheduled Task Persistence Detection

## Detection Overview

Windows Scheduled Tasks are widely used by administrators for automation. Threat actors also abuse Scheduled Tasks to maintain persistence, execute malicious payloads, and establish recurring execution after system reboots or user logons.

This detection identifies the creation or modification of scheduled tasks that may indicate malicious persistence.

---

# Detection Objective

Detect suspicious Scheduled Task creation by monitoring Windows Security Logs, Task Scheduler Operational Logs, and Sysmon Process Creation events.

---

# Attack Scenario

An attacker gains initial access through a phishing email.

A malicious PowerShell script creates a scheduled task that executes a payload every time the user logs on.

The task is registered using **schtasks.exe**.

Windows logs the task creation and Splunk generates an alert.

---

# Detection Scope

**Operating Systems**

- Windows 10
- Windows 11
- Windows Server 2016+
- Windows Server 2019+
- Windows Server 2022

**Required Data Sources**

- Windows Security Logs
- Microsoft-Windows-TaskScheduler/Operational
- Sysmon Event ID 1

---

# Log Sources

| Source | Event ID | Description |
|---------|----------|-------------|
| Sysmon | 1 | Process Creation |
| Task Scheduler | 106 | Task Registered |
| Task Scheduler | 140 | Task Updated |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Persistence | Scheduled Task | T1053.005 |

---

# Detection Logic

Generate an alert when:

- schtasks.exe is executed
- OR a new scheduled task is registered
- OR an existing scheduled task is modified

Increase severity when the command line references:

- PowerShell
- cmd.exe
- mshta.exe
- rundll32.exe
- wscript.exe
- cscript.exe

---

# Production SPL Query

```spl
index=windows

(
(EventCode=1 Image="*schtasks.exe")
OR
(EventCode=106)
OR
(EventCode=140)
)

| eval Process=coalesce(Image,process_name)

| eval CommandLine=coalesce(CommandLine,Process_Command_Line)

| table _time
        host
        user
        EventCode
        Process
        CommandLine

| sort -_time
```

---

# Investigation Workflow

1. Identify the newly created task.
2. Review the executable launched by the task.
3. Determine who created the task.
4. Verify the task trigger.
5. Review the parent process.
6. Check whether the payload is signed.
7. Review related PowerShell or CMD executions.
8. Search for additional persistence mechanisms.

---

# Potential False Positives

- Windows Updates
- Enterprise management software
- Backup applications
- IT automation
- SCCM
- Intune

---

# Detection Tuning

Exclude:

- Microsoft scheduled tasks
- Approved enterprise software
- Known management servers

Review newly observed scheduled tasks regularly.

---

# Analyst Response

- Validate task legitimacy.
- Review associated executable.
- Disable malicious task.
- Remove persistence.
- Hunt for additional attacker activity.

---

# References

- MITRE ATT&CK T1053.005
- Microsoft Task Scheduler Documentation
- Microsoft Sysmon Documentation
