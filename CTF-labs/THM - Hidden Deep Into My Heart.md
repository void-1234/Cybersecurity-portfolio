#team/red 
## Enumeration (recon)

### port scanning (Nmap)
Command: `nmap -sS -sV [IP_ADDRESS]`

**Key findings:**
1. port 5000  is open with  pnp service running

### Directory brute forcing (ffuf)
Command: `ffuf -w path/wordlist.txt -u http://[IP_ADDRESS]:5000/FUZZ`

**Results:**
1. /robots.txt

> Inside robots.txt found an another hidden path called `cupids_secret_vault` and comment `cupid_arrow_2026!!!` which might be useful for later


**Steps taken:**
1.  used ffuf again to enumerate the directories with the command `ffuf -w path/wordlist.txt -u http://[IP_ADDRESS]:5000/cupids_secret_vault/FUZZ`
2. Found the secret `/administrator` page and started guessing for different usernames and password 
3. Found the flag using the `username = admin` as this is the administrator login page and `password = cupid_arrow_2026!!!`











