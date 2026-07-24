# Brute Force Authentication Detection

## Detection Overview

Brute force attacks involve repeated authentication attempts against user accounts in an attempt to guess valid credentials. These attacks are commonly performed against local systems, Active Directory, VPNs, RDP services, and externally exposed applications.

This detection identifies repeated failed logon attempts originating from the same source within a defined time window.

---

# Detection Objective

Detect multiple failed Windows logon attempts that may indicate password guessing or brute force activity.

---

# Detection Scope

**Operating Systems**

- Windows 10
- Windows 11
- Windows Server

**Required Data Sources**

- Windows Security Logs

---

# Log Sources

| Source | Event ID | Description |
|---------|----------|-------------|
| Windows Security | 4625 | Failed Logon |
| Windows Security | 4624 | Successful Logon (Correlation) |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Credential Access | Brute Force | T1110 |

---

# Detection Logic

Generate an alert when:

- More than 10 failed logon attempts
- From the same source IP
- Against the same user
- Within 5 minutes

---

# SPL Query

```spl
index=windows EventCode=4625
| bucket span=5m _time
| stats count values(host) as TargetHost by Source_Network_Address Account_Name _time
| where count >= 10
| rename Source_Network_Address as SourceIP
| table _time SourceIP Account_Name TargetHost count
| sort -count
```

---

# Investigation Workflow

1. Identify the source IP.
2. Determine whether the account exists.
3. Review authentication history.
4. Check whether a successful logon occurred afterward.
5. Review endpoint activity.
6. Check firewall and VPN logs.
7. Determine whether multiple accounts were targeted.

---

# Potential False Positives

- Users entering incorrect passwords
- Password synchronization failures
- Automated monitoring tools
- Service accounts with outdated passwords

---

# Detection Tuning

Exclude:

- Approved vulnerability scanners
- Internal monitoring systems
- Known service accounts

Adjust thresholds based on the organization's authentication patterns.

---

# Analyst Response

- Identify affected accounts.
- Reset passwords if necessary.
- Block malicious source IPs.
- Enable MFA where applicable.
- Escalate if compromise is suspected.

---

# References

- MITRE ATT&CK T1110
- Microsoft Event ID 4625 Documentation
