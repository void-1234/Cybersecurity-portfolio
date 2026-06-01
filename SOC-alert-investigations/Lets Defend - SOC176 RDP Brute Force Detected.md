#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 234  
**Rule:** SOC176 - RDP Brute Force Detected  
**Date Investigated:** Mar 07, 2024  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|Mar 07, 2024 11:44 AM|
|Source IP|218.92.0.56|
|Destination IP|172.16.17.148|
|Destination Hostname|Matthew|
|Protocol|RDP|
|Destination Port|3389|
|Firewall Action|Allowed|
|Alert Trigger Reason|Login failure from single source with different non-existing accounts|

---

## IP Reputation

|Source|Result|
|---|---|
|VirusTotal|9/91 vendors flagged malicious|
|AbuseIPDB|453,051 reports|
|LetsDefend Threat Intel|Confirmed malicious|

> [!danger] IOC **218.92.0.56** — Confirmed malicious across all three sources. AbuseIPDB report count of 453,051 identifies this as a well-known mass scanner operating at scale — not a targeted one-off attempt.

---

## Attack Timeline

```
Mar 07, 2024
|
|-- 11:44 AM -- Alert triggered
|               218.92.0.56 begins RDP brute force against 172.16.17.148
|               Multiple connection attempts — same source IP, rotating source ports
|               Destination port 3389 constant across all attempts
|               Two failed login attempts confirmed for admin and guest accounts
|
|-- 11:44:29 -- Outbound connection from Matthew to 218.92.0.56
|-- 11:44:32 -- Outbound connection from Matthew to 218.92.0.56
|-- 11:44:37 -- Outbound connection from Matthew to 218.92.0.56
|-- 11:44:51 -- Outbound connection from Matthew to 218.92.0.56
|               Bidirectional traffic confirms attacker gained access
|
|-- 11:45:18 -- cmd.exe launched on Matthew's machine
|-- 11:45:51 -- whoami executed
|-- 11:45:58 -- net user letsdefend executed
|-- 11:46:34 -- net localgroup administrators executed
|-- 11:46:53 -- netstat -ano executed
```

> [!warning] On Failed Login Count Only two failed login attempts were visible in logs — admin and guest. The remaining raw log entries appeared empty. The low visible count does not mean only two attempts were made. AbuseIPDB's 453,051 report count confirms this IP conducts mass brute force at scale. Do not let sparse log data reduce confidence in the brute force classification.

> [!info] Rotating Source Ports The attacker used the same source IP but different source ports across attempts. This is a deliberate technique to evade per-port firewall blocking rules and connection rate limiting. The destination IP and port 3389 remained constant throughout.

---

## Endpoint Investigation

**Process logs:** No abnormal parent or child processes observed.

**Network activity:** Outbound connections from Matthew (172.16.17.148) to attacker IP (218.92.0.56) confirmed at 11:44 — bidirectional traffic establishes that the attacker successfully authenticated.

**Terminal history:**

|Time|Command|
|---|---|
|11:45:18|cmd.exe launched|
|11:45:51|whoami|
|11:45:58|net user letsdefend|
|11:46:34|net localgroup administrators|
|11:46:53|netstat -ano|

> [!danger] Post-Exploitation Reconnaissance Confirmed whoami executed at 11:45 — one minute after brute force began. Credentials were successfully guessed. The subsequent command sequence is standard post-exploitation enumeration:
> 
> - `whoami` — confirm identity and privilege level
> - `net user letsdefend` — enumerate specific user account details
> - `net localgroup administrators` — identify accounts with admin privileges
> - `netstat -ano` — map active network connections and listening ports

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Credential Access|Brute Force: Password Guessing|T1110.001|Multiple RDP login attempts from 218.92.0.56 against different accounts on port 3389|
|Initial Access|Valid Accounts|T1078|Successful authentication confirmed by bidirectional traffic and command execution at 11:45|
|Discovery|System Owner/User Discovery|T1033|whoami executed at 11:45:51|
|Discovery|Account Discovery: Local Account|T1087.001|net user letsdefend and net localgroup administrators executed|
|Discovery|System Network Connections Discovery|T1049|netstat -ano executed at 11:46:53|

> [!caution] Mapping Note Command and Control via Remote Access Software (T1219) was considered but not mapped — no RAT or backdoor was found on the endpoint. RDP is the attacker's access method, not a separately installed C2 tool. Lateral movement was investigated but not mapped — no evidence of the attacker moving to other internal devices from Matthew's machine.

---

## Persistence Investigation

**Registry Run Keys checked:**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — Nothing found
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` — Nothing found

**Scheduled Tasks:** No new tasks observed.

> [!note] Persistence Assessment No persistence mechanism confirmed. The attacker's access is dependent on the RDP session remaining active or re-brute-forcing credentials. Forcing a password reset eliminates re-entry via the same credentials.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |RDP Brute Force|Achieved|
> |Valid Credentials Obtained|Achieved — login confirmed by bidirectional traffic|
> |System Reconnaissance|Achieved — user accounts, privileges, network connections enumerated|
> |Persistence|Not confirmed|
> |Lateral Movement|Not observed|
> 
> Full attacker success up to reconnaissance. The attacker has enumerated user accounts, admin group membership, and active network connections on Matthew's machine. This data is sufficient to plan privilege escalation or lateral movement as a follow-up step.

---

## Actions Taken

- Alert classified as True Positive
- Matthew's machine (172.16.17.148) contained
- Source IP 218.92.0.56 blocked at firewall
- Password reset required for all accounts enumerated via net user and net localgroup
- RDP access policy review recommended — port 3389 should not be directly internet-facing

> [!danger] Containment Rationale Firewall Action was Allowed. Attacker successfully authenticated via RDP and completed post-exploitation reconnaissance. All enumerated account credentials should be treated as compromised. RDP should be restricted to VPN-only access or protected behind an MFA-enforced gateway.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. AbuseIPDB report count matters — 453,051 reports identifies a mass scanner, not an opportunistic attacker. The scale of prior activity informs the threat level
> 2. Rotating source ports is a deliberate evasion technique — same attacker, different ports to bypass per-port firewall rules
> 3. Sparse failed login logs do not mean few attempts — raw log gaps are a logging limitation, not evidence the attack was minimal
> 4. Bidirectional traffic between victim and attacker IP is confirmation of successful access — outbound from the victim is the key indicator
> 5. The post-exploitation command sequence is consistent across attack types — whoami, net user, netstat appear in RAT cases and manual RDP access alike. Recognise the pattern regardless of the access method
> 6. RDP on port 3389 directly internet-facing is a permanent target — it should always sit behind VPN or MFA

---

## References

- [MITRE T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE T1087.001 — Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/)
- [MITRE T1049 — System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)

---
