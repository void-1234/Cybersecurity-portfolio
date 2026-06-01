# Cybersecurity Portfolio

Self-taught security practitioner with hands-on experience across both offensive and defensive domains. Currently working in network operations while actively building toward a full-time role in security operations. Background in industrial automation and networking provides a practical foundation in how systems and infrastructure work at a ground level.

This repository documents real investigative work, lab exercises, and security testing done as part of structured self-directed learning. Everything here was done hands-on — no walkthroughs followed without understanding the underlying reasoning.

---

## SOC Alert Investigations

Platform: LetsDefend

Eight alert investigations covering phishing, malware delivery, command injection, credential theft, brute force, and web application exploitation. Each investigation follows a consistent methodology:

- Evidence gathered from logs before forming conclusions
- Attack timeline reconstructed from available artifacts
- Findings mapped to MITRE ATT&CK with supporting evidence for each technique
- Gaps and uncertainties documented explicitly rather than assumed away
- Containment and remediation steps documented

Alerts investigated:

| Event | Rule | Verdict |
|---|---|---|
| 249 | PAN-OS Command Injection — CVE-2024-3400 | True Positive |
| 263 | Check Point Arbitrary File Read — CVE-2024-24919 | True Positive |
| 316 | Lumma Stealer — DLL Side-Loading via ClickFix Phishing | True Positive |
| 235 | SQL Injection Detected | True Positive |
| 238 | Suspicious PowerShell Script Executed | True Positive |
| 234 | RDP Brute Force Detected | True Positive |
| 250 | Application Token Steal Attempt | True Positive |
| 257 | Phishing — Deceptive Mail with RAT Payload | True Positive |

---

## CTF Labs

Platforms: TryHackMe

Writeups from controlled lab environments covering offensive techniques. These are learning exercises, not real engagements. Documented to extract reusable methodology rather than just record steps taken.

Topics covered:

- Binary reverse engineering with Ghidra — scanf format string analysis
- IDOR exploitation via MD5 hash enumeration
- Arbitrary file upload — Python reverse shell delivery
- SSRF via PDF export functionality
- JWT algorithm confusion — alg:none bypass
- File upload restriction bypass and SUID privilege escalation via systemctl
- XOR known-plaintext attack and key recovery

---

## AppSec Pentest

Authorized black-box security assessment performed on a client web application with verbal authorization. All target-specific details including domain names, IP addresses, and endpoint paths have been redacted.

Testing covered:

- API endpoint discovery via JavaScript source analysis and browser DevTools
- Input validation testing across form fields and API parameters
- CORS misconfiguration
- Rate limiting on authentication and booking endpoints
- Security header analysis
- SQL injection on login endpoint
- XSS reflection testing
- IDOR on document access endpoints
- Sensitive data exposure in API responses

The `methodology.md` file in this folder documents the approach used to simulate browser behavior, extract backend API structure, and write automated test cases using pytest.

Tools used: Burp Suite, pytest, requests, BeautifulSoup, ffuf, browser DevTools.

---
