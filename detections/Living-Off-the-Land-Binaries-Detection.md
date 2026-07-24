# Living Off the Land Binaries (LOLBins) Detection

## Detection Overview

Living Off the Land Binaries (LOLBins) are legitimate Windows executables that can be abused by attackers to execute malicious code, download payloads, bypass security controls, and evade detection.

Because these binaries are signed by Microsoft and commonly present on Windows systems, they are frequently used during post-exploitation and lateral movement.

---

# Detection Objective

Detect suspicious execution of commonly abused Windows binaries that are often associated with attacker activity.

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

# Monitored LOLBins

- certutil.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe
- bitsadmin.exe
- installutil.exe
- wmic.exe
- cscript.exe
- wscript.exe

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Defense Evasion | Signed Binary Proxy Execution | T1218 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Execution | Command and Scripting Interpreter | T1059 |

---

# Detection Logic

Generate an alert when one or more monitored LOLBins execute.

Increase severity if the command line contains:

- http://
- https://
- powershell
- cmd.exe
- javascript:
- vbscript:
- dll
- scrobj.dll
- file downloads
- encoded commands

---

# Production SPL Query

```spl
index=windows (EventCode=4688 OR EventCode=1)

| eval Process=coalesce(Image,New_Process_Name,process_name)

| eval ParentProcess=coalesce(ParentImage,Parent_Process_Name)

| eval CommandLine=coalesce(CommandLine,Process_Command_Line)

| where match(lower(Process),
"certutil.exe|mshta.exe|rundll32.exe|regsvr32.exe|bitsadmin.exe|installutil.exe|wmic.exe|cscript.exe|wscript.exe")

| table _time
host
user
ParentProcess
Process
CommandLine

| sort -_time
```

---

# Investigation Workflow

1. Identify the LOLBin executed.
2. Review the complete command line.
3. Determine the parent process.
4. Check for downloaded payloads.
5. Review network activity.
6. Verify digital signatures.
7. Search for child processes.
8. Determine whether execution was expected.

---

# Potential False Positives

- SCCM
- Microsoft Intune
- Enterprise software deployment
- Administrative scripts
- Software installation

---

# Detection Tuning

Exclude:

- Approved administration servers
- Enterprise management tools
- Software deployment platforms
- Known maintenance scripts

Regularly review exclusions.

---

# Analyst Response

- Validate execution.
- Investigate downloaded files.
- Review persistence.
- Hunt for additional LOLBin usage.
- Isolate endpoint if malicious.

---

# References

- MITRE ATT&CK T1218
- LOLBAS Project
- Microsoft Sysmon Documentation
