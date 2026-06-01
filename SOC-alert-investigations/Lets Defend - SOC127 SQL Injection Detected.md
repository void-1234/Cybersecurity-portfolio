#team/blue 
**Related Notes:** [[Alert Investigation Checklist - LetsDefend]]
**Platform:** LetsDefend  
**Event ID:** 235  
**Rule:** SOC127 - SQL Injection Detected  
**Date Investigated:** Mar 07, 2024  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|Mar 07, 2024 12:51 PM|
|Source Address|118.194.247.28|
|Destination Address|172.16.20.12|
|Destination Hostname|WebServer1000 (Atlanta-Server)|
|Request Method|GET|
|Status Code|200|
|Device Action|Allowed|

---

## IP Reputation

|Source|Result|
|---|---|
|VirusTotal|10/91 vendors flagged malicious|
|AbuseIPDB|4,300+ reports|
|LetsDefend Threat Intel|No data|

> [!danger] IOC **118.194.247.28** — Confirmed malicious. 4,300+ AbuseIPDB reports indicates persistent malicious activity at scale, not an isolated incident.

---

## Trigger Request — Decoded

**URL-encoded:**

```
GET /?douj=3034%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
```

**Decoded:**

sql

```sql
GET /?douj=3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name 
FROM information_schema.tables WHERE 2>1--/***/; 
EXEC xp_cmdshell('cat ../../../etc/passwd')#
```

> [!danger] Three Attacks in One Payload
> 
> - **UNION-based SQL Injection** — extracting table names from information_schema.tables
> - **XSS Injection** — `<script>alert("XSS")</script>` embedded in SQL output attempting stored or reflected XSS
> - **xp_cmdshell** — OS command execution attempting to read `/etc/passwd` via path traversal

---

## Attack Timeline

```
Mar 07, 2024
|
|-- 12:50 PM -- Suspicious curl request observed on victim server
|               127.0.0.1 GET / HTTP/1.1 200 1860 curl/7.68.0
|               Internal loopback curl — origin unexplained
|
|-- 12:51 PM -- Alert triggered
|               SQL injection attempt from 118.194.247.28
|               Status 200 — request processed by server
|
|-- 12:51 → 12:53+ PM -- Six pages of sqlmap requests logged
|               Rotating source ports from attacker
|               Destination port 80 constant
|               User-Agent confirms sqlmap/1.7.2 automated tooling
|               All requests return status 200
```

---

## SQLmap Identification

**Evidence from logs:**

```
"GET /index.php?id=%28SELECT%20CONCAT... HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
"GET / HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
```

> [!info] SQLmap is an open-source automated SQL injection tool. Its presence in the User-Agent string is a direct fingerprint of automated exploitation — not manual probing. Six pages of requests is consistent with sqlmap running a full enumeration scan across multiple injection techniques simultaneously.

---

## Exfiltration Assessment

**Status codes:** 200 across all requests — server processed every injection attempt.

**Response size:** Consistent 865 bytes across requests.

> [!warning] Exfiltration — Unconfirmed Status 200 confirms SQL injection queries were processed by the server. However consistent 865-byte responses suggest the server may have returned error pages or empty results rather than actual database content.
> 
> True data exfiltration would produce variable and larger response sizes as database content is returned. 865 bytes is too small for meaningful data extraction.
> 
> Injection success is confirmed. Full data exfiltration is not confirmed from available evidence — would require deeper log analysis of response bodies to determine actual data returned.

---

## Suspicious curl Request

```
127.0.0.1 - - [07/Mar/2024:12:50:05 +0000] "GET / HTTP/1.1" 200 1860 "-" "curl/7.68.0"
```

> [!warning] Internal Loopback curl A curl request from 127.0.0.1 (localhost) to the web server one minute before the SQL injection began is suspicious. This could indicate:
> 
> - A script or process on the server itself probing its own web service
> - Prior compromise where a planted script is testing connectivity
> 
> Origin is unconfirmed — flagged as a separate finding for further investigation.

---

## Command History — Date Discrepancy

All command history on Atlanta-Server is dated **2023-11-10** — approximately 4 months before this alert. No commands logged for 2024.

**Commands of concern from 2023-11-10:**

```
09:14:25  useradd -m test
09:14:31  passwd test
09:23:00  whoami
```

> [!danger] Suspicious Account Creation `useradd -m test` followed immediately by `passwd test` — a new local user account was created on this web server. Creating accounts on a production web server without documented reason is suspicious regardless of when it occurred.
> 
> The absence of any 2024 command logs on a server that received six pages of SQL injection traffic in 2024 is itself a finding — logs may have been cleared.

> [!warning] Date Discrepancy Two possibilities for the 2023 date on commands:
> 
> - Legitimate historical admin activity unrelated to this attack
> - Timestamp manipulation by an attacker to obscure when commands were actually run
> 
> The test account creation should be investigated and verified against change management records regardless of the date.

---

## MITRE ATT&CK Mapping

| Tactic         | Technique                         | ID    | Evidence                                                                           |
| -------------- | --------------------------------- | ----- | ---------------------------------------------------------------------------------- |
| Initial Access | Exploit Public-Facing Application | T1190 | SQL injection via GET requests against internet-facing web server                  |
| Execution      | Command and Scripting Interpreter | T1059 | xp_cmdshell attempting OS command execution via SQL injection                      |
| Discovery      | File and Directory Discovery      | T1083 | `cat ../../../etc/passwd` via path traversal in xp_cmdshell — reading system files |
| Discovery      | Account Discovery                 | T1087 | information_schema.tables enumeration — mapping database structure                 |
| Persistence    | Create Account                    | T1136 | `useradd -m test` in command history — suspicious local account creation           |

> [!caution] Mapping Note Exfiltration over Web Service (T1567) was considered but not mapped — response sizes do not confirm actual data was returned. Map only when evidence supports it. Create Account (T1136) is flagged but the date discrepancy means it cannot be definitively linked to this attack. Documented as a suspicious finding requiring separate verification. XSS injection observed in payload — outside MITRE SOC mapping scope for this alert but documented as an additional attack vector tested by sqlmap.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |SQL Injection Attempts Processed|Achieved — status 200 across all requests|
> |Database Structure Enumeration|Likely — information_schema queries returned 200|
> |OS Command Execution via xp_cmdshell|Attempted — success unconfirmed|
> |/etc/passwd Read via Path Traversal|Attempted — success unconfirmed|
> |Data Exfiltration|Unconfirmed — response sizes inconsistent with data return|
> |Persistent Access via Test Account|Suspicious — requires verification|
> 
> Automated SQL injection campaign confirmed. Injection attempts were processed by the server. Full extent of data accessed is unconfirmed without response body analysis.


---

## References

- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE T1136 — Create Account](https://attack.mitre.org/techniques/T1136/)
- [SQLmap Documentation](https://sqlmap.org)