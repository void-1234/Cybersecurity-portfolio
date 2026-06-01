#team/purple 

**Related tools:** [[Analysis and cracking websites]]

This room gives a python program to analyse and need to find two flags based on the program 

```
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

**Code explanation:**
- The code starts a server at port 1337
- It creates a key of length 5 with randomly generated alphanumeric values
- It takes flag1 (plain text) and do xor operation on that text using the randomly generated key.
- The gibberish xored result is encoded into Hex format
- The server provides the hex code and  expects the correct key used for the  xor operation to print the second flag

>[!tip] 
>The property of XOR 
>  - A⊕B=C
>  - A⊕C=B
>  - B⊕C=A
>  Consider A = plain text, B = Secret key and C = is the Cipher text

**Steps taken:**
1. As we already know most of the Tryhackme flags starts with  `THM{` we can use it to our advantage.
2. First convert the `THM{` into Hex so we can find exactly find how many characters it takes in Hex. The answer is for four plain text characters it takes 8 characters in Hexadecimal.
3. Now based on this we can find the first 4 characters of the key by copying the first 8 characters of Hex code that the server printed out.
```
This XOR encoded text has flag 1: 1f212109277a08001c230e111833233f5d0f19340a071e41362725151a02391d154222391123002a
What is the encryption key? 

```
4. The above is the server output and using the first 8 characters in the hex and THM{  we can find the first 4 characters of the key. In this case `Kilr` is the part of the key    
![[wiseguyTHM-1.png]]

5. Now we can brute force by trying all the characters from 0-9, a-z , A-Z to find the actual key. Below is the screen shots of those 
![[wiseguyTHM-2.png]]
6. So based on this `KilrW` is the random key generated and the flag 1 is obtained in the output panel in cyberchef 
7. Copy paste the key into the server input to get the second flag

>[!note] 
>The process is reversed to decrypt the encrypted text. From plain --> Xor with key --> Hex To Hex --> Xor with key --> plain 

