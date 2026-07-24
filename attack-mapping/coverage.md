# Detection Coverage

This document tracks the current MITRE ATT&CK coverage provided by the detection rules in this repository.

| Detection | MITRE Technique | ATT&CK ID | Status |
|-----------|-----------------|-----------|--------|
| PowerShell Abuse Detection | PowerShell | T1059.001 | ✅ Implemented |
| Encoded PowerShell Detection | PowerShell | T1059.001 | ✅ Implemented |
| Brute Force Authentication Detection | Brute Force | T1110 | ✅ Implemented |
| Suspicious Process Execution | Command and Scripting Interpreter | T1059 | ✅ Implemented |
| Registry Run Key Persistence | Registry Run Keys / Startup Folder | T1547.001 | ✅ Implemented |
| Scheduled Task Persistence | Scheduled Task | T1053.005 | ✅ Implemented |
| Living-Off-the-Land Binaries Detection | Signed Binary Proxy Execution | T1218 | ✅ Implemented |

## Current Coverage

### Execution
- T1059 - Command and Scripting Interpreter
- T1059.001 - PowerShell

### Persistence
- T1547.001 - Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task

### Credential Access
- T1110 - Brute Force

### Defense Evasion
- T1218 - Signed Binary Proxy Execution
