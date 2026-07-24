# Encoded PowerShell Command Detection

## Detection Overview

Threat actors frequently use Base64-encoded PowerShell commands to conceal malicious scripts and evade basic command-line monitoring. This detection identifies PowerShell executions that use encoded commands, which are commonly observed during malware execution, post-exploitation, and red team operations.

---

# Detection Objective

Detect PowerShell executions containing Base64-encoded commands that may indicate malicious or obfuscated activity.

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
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

# Detection Logic

Generate an alert when:

- powershell.exe or pwsh.exe is executed
- AND the command line contains:
  - -enc
  - -EncodedCommand

---

# SPL Query

```spl
index=windows
(EventCode=4688 OR EventCode=1)

| eval Process=coalesce(Image, New_Process_Name, process_name)
| eval CommandLine=coalesce(CommandLine, Process_Command_Line)
| eval ParentProcess=coalesce(ParentImage, Parent_Process_Name)

| where like(lower(Process), "%powershell.exe")
    OR like(lower(Process), "%pwsh.exe")

| where match(lower(CommandLine),"(-enc|encodedcommand)")

| table _time host user ParentProcess Process CommandLine

| sort - _time
```

---

# Investigation Workflow

1. Review the complete command line.
2. Extract the Base64 string.
3. Decode the command.
4. Determine the command's purpose.
5. Identify the parent process.
6. Review child processes.
7. Investigate network activity.
8. Determine whether execution was authorized.

---

# Potential False Positives

- Enterprise automation
- Administrative scripts
- Configuration management tools
- Security testing

---

# Detection Tuning

Exclude approved administrative scripts and trusted automation accounts after validating their behavior.

---

# Analyst Response

- Decode the command immediately.
- Determine the intent.
- Search for additional executions across the environment.
- Investigate persistence or follow-on activity.
- Escalate if malicious behavior is confirmed.

---

# References

- MITRE ATT&CK T1059.001
- MITRE ATT&CK T1027
- Microsoft PowerShell Documentation
