#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 250  
**Rule:** SOC275 - Application Token Steal Attempt Detected  
**Date Investigated:** Apr 19, 2024  
**Analyst:** Void  
**Verdict:** True Positive | Account Compromised

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|Apr 19, 2024 08:23 AM|
|Hostname|Gloriana|
|IP Address|172.16.17.172|
|Affected User|gloriana@letsdefend.io|
|Trigger Request|GET /reset-password?email=gloriana@letsdefend.io HTTP/1.1|
|Device Action|Redirect|

---

## IP and Domain Reputation

|Indicator|Source|Result|
|---|---|---|
|23.82.12.29|VirusTotal|1/91 vendors flagged malicious|
|homespottersf.com|VirusTotal|2/91 vendors flagged malicious|
|Phishing email link|VirusTotal|10/91 vendors flagged malicious|
|download.cyberlearn.academy|VirusTotal|10/91 vendors flagged malicious|

> [!danger] IOCs
> 
> - **23.82.12.29** — Attacker-controlled server. Received the stolen reset token.
> - **homespottersf.com** — Attacker-controlled domain. Used as X-Forwarded-Host to redirect the reset token.
> - **https://download.cyberlearn.academy/download/download?url=** — Malicious redirect URL embedded in phishing email.

---

## Attack Timeline

```
Apr 19, 2024
|
|-- 07:48 AM -- Phishing email delivered to gloriana@letsdefend.io
|               Email crafted to appear as a Discord password reset request
|               Contains malicious link: download.cyberlearn.academy/download/...
|               10/91 VT vendors flag the link as malicious
|
|-- 08:00 AM -- Discovery commands begin on Gloriana's endpoint
|               systeminfo, ipconfig /all observed
|               NOTE: These precede the link click — origin unexplained
|               See Investigation Gap section
|
|-- 08:23 AM -- Gloriana clicks the malicious link
|               Browser follows redirect chain
|               GET /reset-password?email=gloriana@letsdefend.io issued
|               X-Forwarded-Host poisoned to homespottersf.com
|               Status: 302 Redirect
|
|-- 08:23:46 -- Attacker's server receives the reset token
|               POST /reset-password?token=123letsdefendisthebest123
|               Destination: 23.82.12.29:8081
|               Status: 200 OK — password reset confirmed successful
|
|-- 08:30 AM → 10:45 AM -- Discovery commands continue on endpoint
|               netstat, tasklist, net user, wmic, driverquery observed
|               Parent process: msedge.exe throughout
```

---

## How the Attack Works — Host Header Poisoning

This attack abuses how web applications generate password reset links.

**Normal flow:** When a user requests a password reset, the server reads the Host header from the incoming request and uses it to build the reset URL. The token is embedded in that URL and sent to the user.

**Attacker's manipulation:** By poisoning the X-Forwarded-Host header to point to `homespottersf.com`, the attacker causes the server to build the reset URL using the attacker's domain. The legitimate reset token is then sent to the attacker's server instead of the real application.

**Step by step:**

1. Phishing email sent to Gloriana disguised as a Discord password reset
2. Gloriana clicks the link — her browser follows the redirect chain
3. A GET request is made to `/reset-password?email=gloriana@letsdefend.io`
4. X-Forwarded-Host header is set to `homespottersf.com` — server generates token and sends it there
5. 302 redirect issued — token delivered to attacker's server at 23.82.12.29:8081
6. Attacker immediately POSTs the token back — status 200 confirms password reset succeeded
7. Attacker controls Gloriana's Discord account

> [!info] What download.cyberlearn.academy Does The link in the phishing email is not a direct reset link. It is a redirect URL that routes Gloriana through a malicious intermediary before triggering the password reset flow. This intermediary sets the poisoned X-Forwarded-Host header before the request reaches the application server.

---

## Proxy Log Evidence

**Request 1 — Token Request**

|Field|Value|
|---|---|
|Timestamp|19/Apr/2024 08:23:40 +0000|
|Request|GET /reset-password?email=gloriana@letsdefend.io HTTP/1.1|
|Target URL|http://homespottersf.com:8081/reset-password|
|X-Forwarded-Host|homespottersf.com|
|X-Forwarded-Port|8081|
|Status Code|302|

**Request 2 — Token Submission**

|Field|Value|
|---|---|
|Timestamp|19/Apr/2024 08:23:46 +0000|
|Request|POST /reset-password?token=123letsdefendisthebest123 HTTP/1.1|
|Destination|23.82.12.29:8081|
|X-Forwarded-Host|homespottersf.com|
|Status Code|200|

> [!danger] Status 200 Confirmation The 200 response on the POST confirms the password reset completed successfully. The attacker now controls Gloriana's Discord account. The 6-second gap between 08:23:40 and 08:23:46 shows the token was intercepted and resubmitted almost instantly — automated tooling was likely used.

---

## Endpoint Investigation

**Process logs:** All parent and child processes show msedge.exe as parent. No RAT or backdoor confirmed.

**Discovery commands observed:**

|Time|Command|
|---|---|
|08:00:00|systeminfo|
|08:15:00|ipconfig /all|
|08:30:00|netstat -ano|
|08:45:00|tasklist|
|09:00:00|ver|
|09:15:00|driverquery|
|09:30:00|systeminfo|
|09:45:00|net user|
|10:00:00|wmic product get name|
|10:15:00|fsutil volume diskfree C:|
|10:30:00|wmic memorychip get capacity|
|10:45:00|time /t|

> [!warning] Investigation Gap — Pre-Click Commands Discovery commands begin at 08:00 AM — 23 minutes before Gloriana clicked the link at 08:23 AM. These commands cannot have been triggered by the token steal event. Two possibilities:
> 
> - Gloriana ran them legitimately for a system-related task
> - A separate prior access vector exists that is not visible in available logs
> 
> Machine compromise is not confirmed by this investigation. The pre-click commands remain unexplained and should be escalated for further review.

> [!note] msedge.exe as Parent All processes show msedge.exe as parent. A browser spawning system enumeration commands is suspicious regardless of the absence of a confirmed RAT. This warrants further investigation if memory forensics or EDR telemetry becomes available.

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Initial Access|Phishing: Spearphishing Link|T1566.002|Malicious email delivered to gloriana@letsdefend.io at 07:48 AM containing redirect URL|
|Credential Access|Steal Application Access Token|T1528|Reset token intercepted via X-Forwarded-Host poisoning and delivered to attacker-controlled server|
|Initial Access|Valid Accounts|T1078|Status 200 on token POST confirms attacker successfully reset and controls Gloriana's Discord account|
|Discovery|System Information Discovery|T1082|systeminfo, ver, driverquery, wmic memorychip executed on endpoint|
|Discovery|System Network Configuration Discovery|T1016|ipconfig /all, netstat -ano executed|
|Discovery|Account Discovery: Local Account|T1087.001|net user executed|
|Discovery|Software Discovery|T1518|wmic product get name — enumerates installed software|

> [!caution] Mapping Note Command and Control via Application Layer Protocol was considered but not mapped — no confirmed outbound C2 traffic beyond the token theft mechanism itself. Do not map without direct evidence. Machine compromise was not confirmed. Discovery commands preceded the click event — their origin is unresolved. If a separate access vector is identified, additional techniques would apply.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |Phishing Email Delivered|Achieved|
> |Victim Clicked Malicious Link|Achieved|
> |Reset Token Intercepted|Achieved|
> |Discord Account Takeover|Achieved — status 200 confirms password reset|
> |Machine Compromise|Unconfirmed — pre-click commands unexplained|
> |Lateral Movement|Not observed|
> 
> Gloriana's Discord account is confirmed compromised. The attacker controls it from the moment the POST returned 200. Machine-level compromise is a separate open question requiring further investigation.

---

## Actions Taken

- Alert classified as True Positive
- Gloriana's Discord account password reset immediately — invalidate all active sessions
- Gloriana's endpoint (172.16.17.172) flagged for further investigation — pre-click commands unexplained
- IOCs blocked at perimeter:
    - 23.82.12.29
    - homespottersf.com
    - download.cyberlearn.academy
- Pre-click discovery commands escalated for separate investigation

> [!danger] Containment Rationale Password reset confirmed via status 200. Attacker has had control of Gloriana's Discord account since 08:23:46 AM. All sessions, tokens, and OAuth authorisations on that account should be invalidated immediately. Pre-click endpoint activity cannot be explained by this alert alone — treat the machine as potentially compromised until proven otherwise.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. Host header poisoning redirects legitimate application tokens to attacker-controlled infrastructure — the application itself generates and sends the token to the wrong destination
> 2. A 302 redirect followed by a 200 on a token POST is confirmation of a successful account takeover — status codes tell the story
> 3. X-Forwarded-Host is a trust boundary — applications that blindly use it to build reset URLs are vulnerable to this exact attack
> 4. Artifacts that precede the trigger event are not noise — commands running before the alert timestamp need a separate explanation, not dismissal
> 5. Account compromise and machine compromise are different findings — do not conflate them in the report
> 6. A 6-second gap between token interception and resubmission indicates automated tooling — manual attackers do not operate that fast

---

## References

- [MITRE T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE T1518 — Software Discovery](https://attack.mitre.org/techniques/T1518/)
- [PortSwigger — Host Header Attacks](https://portswigger.net/web-security/host-header)

---
