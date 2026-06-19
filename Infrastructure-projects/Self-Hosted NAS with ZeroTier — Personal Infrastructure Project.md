#topic/networking 
**Related Notes:** [[ZeroTier Installation]] 

## Overview

Built a self-hosted file server using a Raspberry Pi running headless Debian 13, with an external hard disk attached for storage. Remote access between devices is handled through ZeroTier, a software-defined networking (SDN) tool that creates an encrypted peer-to-peer virtual network between devices regardless of their physical location or network.

The goal was to have a personal file server accessible remotely without exposing any ports to the public internet or relying on third-party cloud storage.

---

## Hardware and OS

| Component | Detail |
|---|---|
| Device | Raspberry Pi |
| OS | Debian 13 |
| Mode | Headless — managed entirely over SSH, no monitor attached |
| Storage | External hard disk, ext4 filesystem |

ext4 was used for the storage drive on the Pi. Cross-platform access from Windows was still achieved over SFTP using WinSCP — the filesystem only needs to be readable by the Pi's Linux OS, since Windows clients access files through SFTP rather than mounting the drive directly.

---

## Network Setup — ZeroTier

ZeroTier creates a virtual private network (VPN-like overlay) between devices, assigning each device a ZeroTier-managed IP address. Devices on the same ZeroTier network can communicate directly and securely as if they were on the same local network, even when physically distributed across different networks.

**Setup steps:**

1. Installed ZeroTier on the Raspberry Pi
2. Installed ZeroTier on the primary administration machine (Ubuntu)
3. Created a network ID using ZeroTier Central
4. Joined both devices to the same network ID
5. Authorized both devices in ZeroTier Central's member list
6. Each device received a ZeroTier-assigned IP address

Once both devices were on the same virtual network, they could communicate directly over their ZeroTier IPs — encrypted and without requiring port forwarding or exposing the Pi to the public internet.

> [!info] Why ZeroTier instead of traditional port forwarding
> Port forwarding requires opening ports on the home router, which increases the attack surface and exposes the device to internet-wide scanning. ZeroTier avoids this entirely — there is no public-facing port. All communication happens over the encrypted virtual network, and devices must be explicitly authorized in ZeroTier Central to join.
>
> Port forwarding was also not a viable option in this case due to CGNAT (Carrier-Grade NAT) imposed by the ISP. Under CGNAT, the home router does not receive a public IP address — it shares a public IP with multiple other customers behind the ISP's own NAT layer. This means incoming connections cannot reach the router at all, regardless of port forwarding configuration, since there is no dedicated public IP to forward to. ZeroTier bypasses this limitation entirely by establishing outbound connections from both devices to ZeroTier's coordination infrastructure, which removes the need for any inbound connection to the home network.

---

## Remote Access — SSH and SFTP

The Raspberry Pi runs an SSH server, which provides both SSH terminal access and SFTP file transfer using the same service.

**Administration:**
- SSH used for terminal access to the Pi — installing packages, managing the mounted drive, general administration

**File Access:**
- SFTP used for file transfer to and from the Pi
- Verified cross-platform compatibility by connecting from a Windows machine using WinSCP, joined to the same ZeroTier network, confirming the file share was accessible without OS-specific issues

---

## Multi-User Access — Privacy by Design

A friend was also added to the same ZeroTier network to allow file sharing from the Pi. He can connect to the Raspberry Pi and download files directly.

By design, neither of our personal machines runs an SSH server — only the Raspberry Pi does. This means we are both able to reach the shared NAS, but we cannot directly access each other's personal machines, even though we are on the same ZeroTier network. ZeroTier provides network-layer reachability between all devices on the network, but actual access still depends on what services each device chooses to expose. Not installing an SSH server on personal machines keeps them isolated from each other by default — only the shared NAS is reachable, which is the intended setup.

---

## Linux User Account Hardening

The Raspberry Pi initially only had the default administrative user with full sudo access. To allow the friend's account to access the shared NAS without granting unnecessary system privileges, a separate low-privilege user account was created specifically for file access.

**Approach:**

1. Created a dedicated user account for SFTP access — no sudo group membership
2. Set file and folder ownership and permissions on the shared directory so this account could only read and write within its designated folder
3. Verified the account could not access system files, other users' home directories, or any path outside the shared NAS folder
4. Confirmed the account had no ability to install packages, modify system configuration, or escalate privileges

```bash
# Create a new user without sudo privileges
sudo adduser shareduser

# Restrict the account to only the shared directory
sudo chown -R shareduser:shareduser /mnt/nas-share
sudo chmod -R 750 /mnt/nas-share
```

> [!info] Principle of Least Privilege
> The administrative account used to manage the Pi and the account used for file sharing are kept separate intentionally. A compromised or misused low-privilege account is limited to the shared directory only — it cannot read system logs, modify configuration, or access any other user's files. This is the same principle applied in production environments where service accounts are scoped to the minimum access required for their function, rather than running everything as a privileged user.

---

## Key Learnings

> [!note] Lessons from This Project
>
> 1. Headless Linux administration requires SSH access configured correctly from first boot — no fallback to a local monitor if something goes wrong
> 2. exFAT is the right choice for storage that needs to be accessed across multiple operating systems without compatibility issues
> 3. ZeroTier provides secure network-layer connectivity without exposing any ports publicly, but it does not automatically expose services — each device only becomes reachable for SSH/SFTP if that service is explicitly installed and running. This was used deliberately to keep personal machines private while still sharing the NAS
> 4. By default, Ubuntu installs only the SSH client, not the SSH server — useful to know when deciding which machines should and should not be reachable on the network
> 5. Separating the administrative account from the shared-access account follows the principle of least privilege — even on a personal project, scoping permissions correctly limits the blast radius if an account is ever compromised or misused
> 5. Testing cross-platform access (Windows via WinSCP) early in the setup confirmed the storage and sharing configuration worked beyond just the Linux environment it was built in

---

## Tools Used

| Tool | Purpose |
|---|---|
| Debian 13 | Operating system for the Raspberry Pi |
| ZeroTier | Software-defined networking — encrypted peer-to-peer virtual network |
| OpenSSH | Remote terminal access and SFTP file transfer |
| WinSCP | Cross-platform SFTP client used to verify access from Windows |

