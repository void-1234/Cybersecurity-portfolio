#team/red 
**Related tools:** [[Burp Suite]]  **Related notes:** [[SSRF]]
## Enumeration (recon)

### Port scanning (Nmap):
Command: `nmap -sS -sV [IP_ADDRESS]`

**Results**:
1. port 22 is open and ssh service running
2. port 80 is open with http service running

### Directory brute forcing (ffuf):
Command: `ffuf -w path/wordlist.txt -u http://[IP_ADDRESS]/FUZZ`

**Results**:
Mostly all the results are forbidden except for `/robots.txt`

>[!info] Observation: 
>- The `http://[IP_ADDRESS]` has a login page 
>- The `/robots.txt` page has a disallowed route called `backups/chat`

**Key findings:**
1. The chats page gives us two hints
    - Saying there is a export to PDF function in the website
    - Hinting the username and password of the admin
2. After logged in as admin found that the flag is located in `/internal/admin.php` path
3. When  accessed `/internal/admin.php` the pages says "it can be only accessed locally" hinting we need to add loopback address in some place.
4. There is an export to PDF button exports a PDF by server requesting  for a URL.
5. The URL that server uses to generate the PDF is `http://127.0.0.1/server-info.php`

### Exploitation:
1. Open burpsuite and capture the export to PDF request which is `http://1[IP_ADDRESS/export2pdf.php`
2. In the body there is a URL parameter and in  that change the `server-info.php` to the flag path which is `interal/admin.php`
3. Now forward the modified request and the flag will be printed in the PDF


