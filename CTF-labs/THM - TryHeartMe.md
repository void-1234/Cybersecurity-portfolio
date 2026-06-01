#team/red 
## Enumeration (recon)
### Port scanning (Nmap)
Command : `nmap -sS -sV [IP_ADDRESS]`

**Key findings:**
1. port 22 is open with ssh service running 
2. port 5000 is open with upnp service 
### Directory brute forcing (ffuf)
Command: `ffuf -w path/wordlist.txt -u http://[IP_ADDRESS]:5000/FUZZ`

**Results:**
1. `/login`
2. `/logout`
3. `/account`
4. `/admin`
5. `/register`

>After playing around for a while created an account and noticed the website gives me the role as `user` which means there must also be a role for `admin`
## Exploitation (JWT) 

>[!info] Observation After registering, the JWT payload contained: `{"role": "user", "credits": 0}`.

>Noticed the website uses JWT cookie for authentication. Check [[JWT Exploitation]]  for more info.

**Steps Taken:**

1. Captured the `/account` request in **Burp Suite**.       
2. Sent the request to **Repeater**.         
3. Decoded the JWT and changed the payload to:   JSON
```
    {
      "role": "admin",
      "credits": 9999
    }
```
4. Modified the header to `{"alg": "none"}` and removed the signature.     
5. Swapped the cookie in the browser's **Inspect -> Application -> Cookies** tab.   

**Final Result:** Accessed the `/admin` panel and retrieved the flag.





