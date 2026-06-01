#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 257  
**Rule:** SOC282 - Phishing Alert - Deceptive Mail Detected  
**Date Investigated:** May 13, 2024  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|May 13, 2024 09:22 AM|
|SMTP Address|103.80.134.63|
|Source Address|free@coffeeshooop.com|
|Destination Address|Felix@letsdefend.io|
|Internal Destination|172.16.20.3 (Exchange Server)|
|Victim Endpoint|172.16.20.151|
|Email Subject|Free Coffee Voucher|
|Device Action|Allowed|

---

## IP and Domain Reputation

|Indicator|Source|Result|
|---|---|---|
|103.80.134.63|VirusTotal|10/91 vendors flagged malicious|
|103.80.134.63|AbuseIPDB|No data|
|103.80.134.63|LetsDefend Threat Intel|Tagged — Phishing|
|coffeeshooop.com|VirusTotal|Clean|
|coffeeshooop.com|LetsDefend Threat Intel|No data|
|Download URL|VirusTotal|14/91 flagged malicious|
|coffeee.exe hash|VirusTotal|61/91 flagged — RAT / Backdoor|

> [!danger] IOCs
> 
> - **103.80.134.63** — Attacker SMTP relay. Confirmed malicious.
> - **coffeeshooop.com** — Typosquatted phishing domain. Clean on VT but used as sender — treat as malicious infrastructure.
> - **https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip** — Malicious payload URL. 14/91 vendors.
> - **coffeee.exe** — RAT / Backdoor. Hash: `CD903AD2211CF7D166646D75E57FB866000F4A3B870B5EC759929BE2FD81D334`

> [!caution] On coffeeshooop.com The domain is clean on VirusTotal and not found in LetsDefend Threat Intel. However the triple-o typosquatting of a legitimate brand combined with a confirmed malicious SMTP IP is sufficient to treat this as malicious infrastructure. A clean VT result does not clear a domain used in an active phishing campaign.

---

## Attack Timeline

```
May 13, 2024
|
|-- 09:20 AM -- Phishing email sent from free@coffeeshooop.com
|               Delivered to Exchange Server 172.16.20.3
|               Forwarded to Felix@letsdefend.io
|
|-- 09:21 AM -- Alert triggered by SIEM
|               Device Action: ALLOWED — email reached the inbox
|
|-- 12:58 PM -- TVN Server process observed on victim endpoint
|               Occurred before link click — logged as separate finding
|               Not directly linked to this attack chain
|
|-- 12:59 PM -- Felix clicks the malicious download link
|               Browser history confirms access to:
|               files-ld.s3.us-east-2.amazonaws.com/.../free-coffee.zip
|               explorer.exe opens chrome.exe
|
|-- 13:00 PM -- explorer.exe executes coffeee.exe
|               Hash confirmed as RAT / Backdoor by 61/91 VT vendors
|               Masquerading as dllhost.exe
|
|-- 13:01 PM -- coffeee.exe spawns cmd.exe
|               Automated post-exploitation reconnaissance begins
```

> [!warning] Delivery to Execution Gap Email delivered at 09:20 AM. Victim clicked at 12:59 PM — approximately 3.5 hours later. This is normal for phishing campaigns. The victim likely read the email later in the day. Always check endpoint activity, not just the alert timestamp.

---

## Phishing Email Analysis

**Sender:** free@coffeeshooop.com  
**Subject:** Free Coffee Voucher  
**Lure:** Social engineering using a free reward theme to entice the victim to click

> [!info] Typosquatting The sender domain `coffeeshooop.com` uses triple-o to mimic a legitimate domain. This is a deliberate typosquatting technique designed to pass a casual visual inspection. Always check domain spelling character by character, not at a glance.

---

## Malicious Payload

**Download URL:**

```
https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/59cbd215-76ea-434d-93ca-4d6aec3bac98-free-coffee.zip
```

**File:** free-coffee.zip → coffeee.exe  
**Hash:** `CD903AD2211CF7D166646D75E57FB866000F4A3B870B5EC759929BE2FD81D334`  
**VirusTotal:** 61/91 vendors — classified as RAT / Backdoor  
**Masquerading as:** dllhost.exe (legitimate Windows process)

---

## Process Chain

```
explorer.exe
    └── coffeee.exe (RAT — masquerading as dllhost.exe)
            └── cmd.exe
                    ├── systeminfo
                    ├── hostname
                    ├── wmic logicaldisk get caption
                    ├── net user
                    ├── tasklist /svc
                    ├── ipconfig /all
                    └── route print
```

> [!danger] Post-Exploitation Reconnaissance The command sequence executed by cmd.exe is a standard automated post-exploitation enumeration script. Each command individually appears benign — combined in sequence within seconds of RAT execution, this is the attacker fingerprinting the compromised system:
> 
> - `systeminfo` — OS version, patch level, hardware
> - `hostname` — machine identity
> - `wmic logicaldisk` — drive enumeration
> - `net user` — local account enumeration
> - `tasklist /svc` — running processes and services
> - `ipconfig /all` — network configuration
> - `route print` — routing table, network topology

---

## Persistence Investigation

**Registry Run Keys checked:**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — Nothing found
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` — Nothing found

**Scheduled Tasks:** No new tasks created around 13:00

> [!note] Persistence Assessment No persistence mechanism confirmed. coffeee.exe did not register registry run keys or scheduled tasks. The RAT may rely on re-infection or manual redeployment. The absence of persistence does not reduce the severity — the reconnaissance data has already been collected and sent.

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Initial Access|Phishing: Spearphishing Link|T1566.002|Email with malicious download link delivered to Felix@letsdefend.io|
|Execution|User Execution: Malicious Link|T1204.001|Browser history confirms victim clicked the download URL at 12:59 PM|
|Defense Evasion|Masquerading: Match Legitimate Name or Location|T1036.005|coffeee.exe masquerading as dllhost.exe — legitimate Windows process name|
|Discovery|System Information Discovery|T1082|systeminfo, hostname, wmic logicaldisk executed via cmd.exe|
|Discovery|System Network Configuration Discovery|T1016|ipconfig /all, route print executed via cmd.exe|
|Discovery|Account Discovery: Local Account|T1087.001|net user executed via cmd.exe|
|Discovery|Process Discovery|T1057|tasklist /svc executed via cmd.exe|
|Command and Control|Remote Access Software|T1219|coffeee.exe confirmed RAT/Backdoor by 61/91 VT vendors|

> [!caution] Mapping Note Persistence was investigated but not mapped — no registry run keys or scheduled tasks found. If follow-up investigation reveals a persistence mechanism, T1053 or T1547 would apply.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |Phishing Email Delivered|Achieved|
> |Victim Clicked Malicious Link|Achieved|
> |RAT Installed on Victim Endpoint|Achieved|
> |System Reconnaissance Completed|Achieved — full system fingerprint collected|
> |Persistence|Not confirmed|
> |Lateral Movement|Not observed — investigation ongoing|
> 
> Full attacker success up to RAT installation and initial reconnaissance. The attacker has a complete fingerprint of Felix's machine including OS details, network configuration, user accounts, and running services.

---

## Actions Taken

- Alert classified as True Positive
- Victim endpoint 172.16.20.151 contained
- SMTP IP 103.80.134.63 blocked at perimeter
- coffeeshooop.com blocked at email gateway
- Payload URL and download domain blocked at proxy
- coffeee.exe hash added to blocklist

> [!danger] Containment Rationale RAT confirmed on victim endpoint. Automated reconnaissance already executed — the attacker has system information that can be used to plan follow-up attacks including lateral movement and privilege escalation. Contain immediately. Treat all data on Felix's machine as potentially enumerated.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. Typosquatting requires character-by-character inspection — `coffeeshooop.com` passes a visual glance but fails on close inspection
> 2. A clean VirusTotal result on a sender domain does not clear it — cross-reference with the SMTP IP and campaign context
> 3. Benign-looking commands executed in rapid sequence post-infection are automated reconnaissance — context and timing matter, not just the command itself
> 4. A 3.5 hour gap between email delivery and victim click is normal — always investigate the endpoint, never assume no click because of time elapsed
> 5. Masquerading as dllhost.exe is a deliberate choice — legitimate Windows process names are used specifically because they blend into process lists
> 6. Absence of persistence does not reduce severity — reconnaissance data collected by the RAT has already left the machine

---

## References

- [MITRE T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE T1204.001 — Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [MITRE T1036.005 — Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)

---
