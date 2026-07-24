# PowerShell Abuse Detection Validation

## Objective

Validate that the PowerShell Abuse Detection rule successfully detects suspicious PowerShell execution using Windows Security Event ID 4688 or Sysmon Event ID 1.

---

## Detection Under Test

**Detection:** PowerShell Abuse Detection

**MITRE ATT&CK:** T1059.001 - PowerShell

---

## Test Scenario

A user executes PowerShell using suspicious command-line arguments.

Example:

powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA

---

## Required Logs

- Windows Security Event ID 4688
- Sysmon Event ID 1

---

## Expected Detection

The detection should identify:

- PowerShell execution
- Suspicious command-line arguments
- Parent process
- User
- Host
- Timestamp

---

## Investigation Checklist

- Verify the parent process.
- Review the full command line.
- Check for Base64-encoded commands.
- Identify the executing user.
- Determine whether the execution was expected.
- Search for additional PowerShell activity from the same endpoint.

---

## Expected Outcome

The detection should generate an alert that includes:

- Host
- User
- Parent Process
- PowerShell Process
- Command Line
- Timestamp

---

## Validation Status

- [ ] Successful
- [ ] Requires Tuning
- [ ] False Positive
