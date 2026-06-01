#team/red 
**Related Tools:** [Cyberchef](https://gchq.github.io/CyberChef/)

### Room Concept
The room expects us to escape from the Corridor by using IDOR vulnerability 
## Observation

- nmap scan revealed that http port is open. opend the web browser at `http://[ip_address]`
- Found there are 13 clickable room doors and when clicked each room  door take us to the room
- When each door is clicked the path on the top also changes
- `eg http://ip_address/c4ca4238a0b923820dcc509a6f75849b` 
- Those Hexadecimal values looks like MD5 hash
- Using Cyberchef found out each room has different has that there are 13 rooms so 13 hashes
- When decrypted the hashes found every hash stands for the room number such as 1,2,3.....to 13

## Steps taken 
- So to escape the corridor tried using the next room number which is 14. So hashed the number 14 and took the value and pasted in the route but no such room. Tried the same for number 15 and no luck.
- Finally when tried hashing the value 0 and pasted in the path `http://[ip_address]/cfcd208495d565ef66e7dff9f98764da` the flag is visible 
