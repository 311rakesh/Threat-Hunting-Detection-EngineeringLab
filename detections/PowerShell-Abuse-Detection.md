<p align="center">

![Splunk](https://img.shields.io/badge/Splunk-Enterprise_Security-000000?style=for-the-badge&logo=splunk)
![Windows](https://img.shields.io/badge/Windows_Event_Logs-0078D6?style=for-the-badge&logo=windows)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-2E8B57?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![SPL](https://img.shields.io/badge/SPL-Detection_Engineering-orange?style=for-the-badge)

</p>
# PowerShell Abuse Detection

## Detection Overview

PowerShell is a legitimate Windows administration framework that is frequently abused by threat actors for command execution, defense evasion, credential access, lateral movement, and payload delivery.

This detection identifies suspicious PowerShell executions by analyzing Windows Security Event Logs and Sysmon Process Creation events. It focuses on detecting attacker behaviors while minimizing false positives through command-line analysis.

---

# Detection Objective

Identify PowerShell executions that exhibit characteristics commonly associated with malicious activity, including:

- Encoded PowerShell commands
- Hidden PowerShell windows
- Execution Policy bypass
- Download cradle activity
- Invoke-Expression (IEX)
- Base64 encoded payloads
- Suspicious parent-child process relationships

---

# Detection Scope

**Operating System**

- Windows 10
- Windows 11
- Windows Server 2016+
- Windows Server 2019+
- Windows Server 2022

**Required Data Sources**

- Windows Security Event Logs (4688)
- Sysmon Event ID 1

---

# Log Sources

| Source | Event ID | Description |
|---------|----------|-------------|
| Windows Security | 4688 | Process Creation |
| Sysmon | 1 | Process Creation with Command Line |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command and Control | Ingress Tool Transfer | T1105 |

---

# Detection Logic

Generate an alert when:

- powershell.exe or pwsh.exe is executed
- AND the command line contains one or more suspicious keywords

Suspicious Indicators

- -enc
- -EncodedCommand
- -nop
- -w hidden
- -WindowStyle Hidden
- -ExecutionPolicy Bypass
- IEX
- Invoke-Expression
- DownloadString
- DownloadFile
- Net.WebClient
- FromBase64String
- iex(
- Invoke-WebRequest
- Start-BitsTransfer

---

# Production SPL Query

```spl
index=windows
(EventCode=4688 OR EventCode=1)

| eval Process=coalesce(Image,New_Process_Name,process_name)

| eval CommandLine=coalesce(CommandLine,Process_Command_Line)

| eval ParentProcess=coalesce(ParentImage,Parent_Process_Name)

| where like(lower(Process),"%powershell.exe")
    OR like(lower(Process),"%pwsh.exe")

| where match(lower(CommandLine),
"(encodedcommand|-enc|-nop|-w hidden|windowstyle hidden|executionpolicy bypass|invoke-expression|iex|downloadstring|downloadfile|net.webclient|frombase64string|invoke-webrequest|start-bitstransfer)")

| table _time
        host
        user
        ParentProcess
        Process
        CommandLine

| sort - _time
```

---

# Investigation Workflow

## Step 1

Identify the endpoint.

- Hostname
- Logged-in user
- Time of execution

---

## Step 2

Review the full PowerShell command.

Determine whether it contains:

- Encoded content
- Download activity
- Obfuscation
- Remote URLs

---

## Step 3

Review Parent Process

Expected parents include:

- explorer.exe
- cmd.exe
- services.exe

Unexpected parents may include:

- winword.exe
- excel.exe
- outlook.exe
- mshta.exe
- rundll32.exe
- wscript.exe

---

## Step 4

Review Child Processes

Look for execution of:

- cmd.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- mshta.exe
- net.exe
- whoami.exe

---

## Step 5

Review Network Activity

Identify connections to:

- External IPs
- Newly observed domains
- File download locations

---

## Step 6

Review File Activity

Look for:

- New executables
- DLL creation
- Scheduled Tasks
- Registry modifications

---

# Expected False Positives

Legitimate PowerShell activity may originate from:

- Microsoft Intune
- SCCM
- Azure Automation
- Backup software
- Enterprise management tools
- Administrative scripts

---

# Detection Tuning

Consider excluding:

- Approved administration servers
- Automation accounts
- Patch management systems
- Configuration management platforms
- Known maintenance scripts

Review exclusions periodically to prevent attackers from abusing trusted processes.

---

# Analyst Response

If malicious activity is confirmed:

1. Isolate the endpoint.
2. Terminate the PowerShell process.
3. Preserve forensic evidence.
4. Identify persistence mechanisms.
5. Search for related IOCs across the environment.
6. Block malicious hashes, domains, or IP addresses.
7. Escalate according to the incident response process.

---

# References

- MITRE ATT&CK – T1059.001 (PowerShell)
- Microsoft Sysmon Documentation
- Windows Security Auditing Documentation
