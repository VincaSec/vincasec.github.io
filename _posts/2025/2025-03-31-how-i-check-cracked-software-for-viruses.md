---
title: "How I Check Cracked Software for Viruses"
date: 2025-04-01
categories: [Malware, Piracy]
image: https://miro.medium.com/v2/resize:fit:640/format:webp/1*wEWINE2Ann0Ok4agc5R69g.jpeg
alt: "wallpaper"
---

Like any other student, I have to spend a lot of time on my computer for multiple reasons. Be it for taking care of personal projects, school tasks, or even conducting research; I depend on my computer and the appropriate software. There are instances where some programs are either extremely expensive or difficult to find. These scenarios sorely tempt me to seek out cracked versions of software. Even though the prospect is tempting, I have learned the hard way of why cracked software is not an option from a functional point of view. From using it, I have learned all too well the negative consequences it can lead to. That is why I have found numerous ways to identify suspicious programs such as cracked software to keep myself safe.

## Understanding Cracked Software

Before I get into specifics about how I check for suspicious or cracked software, it is vital that I explain what a cracked software is in the first place. Cracked software is a type of software which has been modified to an extent to allow usage without validation through purchase or a licensed copy. Despite initially apparent advantages, it can have a wide range of negative effects.

### Where to Find Cracked Software

![Boat](https://miro.medium.com/v2/resize:fit:720/format:webp/1*kxa4aAFusADh-gLoxuFd7Q.jpeg)

I stumble upon cracked software on different file-sharing sites together with forums ,social networking platforms and torrent sites. Users can find illegal free downloads of costly programs through these websites. The platforms feature harmful files which intent to carry out data theft or place malicious software on your system.

Early on I discovered that downloading programs from unapproved or unknown sources remains extremely dangerous. You wouldn’t know that the software has been tampered with until it is already too late even when it appears authentic.

### Investigating the Cracked Program

![Youtube](https://miro.medium.com/v2/resize:fit:720/format:webp/1*l1uYTur_WWyXT1QaFK8Rvg.png)

![Youtube](https://miro.medium.com/v2/resize:fit:720/format:webp/1*4XwvrpgFopEhEIW5fQul2A.png)

I proceeded with uploading the cracked software file to VirusTotal after running it through Any.Run’s sandbox service then downloaded the .exe file. The review of results made me become instantly worried about their contents. The file attracted multiple antivirus engines to classify it as threatening software that several security providers recognized as dangerous. This was a clear red flag.

The detection of Crowdsourced Sigma Rules during this process became a more specific point of interest for me. The detection criteria which security professionals use to examine suspicious activity are known as Sigma rules. Security professionals along with enthusiasts from the community participate in collecting and creating these rules while drawing from their investigations into actual malware situations. Several Sigma rules discovered suspicious behavioral patterns within the file which proved this was undeniably not an ordinary piece of software.

![VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*0Be0Aa8N4LmLD-YpSyeWUg.png)

![VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*by2toa_p1oVmpmA5BtT5Xw.png)

The history of the file on VirusTotal showed great concern because its first submission was from many years back. The file existed in active circulation since a long time but remained active because its submission during this year showed that users kept getting tricked into downloading it. The software underwent multiple unauthorized modifications that made it seem like a cracked version of the original program while remaining in active distribution.

The analysis revealed the suspicious .exe file performed network communications toward two different domains. A domain monitored numerous instances of malware traffic which indicated it connected with other elements of a bigger network. The second domain pointed to C&C (Command and Control) servers where Lokibot malware operated as the main malware. The mentioned IPs maintained connections with both Lokibot Command and Control servers and the password-striking malware implementation known as Lumma Stealer. Analysis established that the detected file served as an operational backdoor which allowed both command transfer and stolen data upload because it functioned beyond simple program cracking capabilities.

Through reviewing thought communities and threat intelligence databases I learned that other observers identified the same suspicious domains together with their linked malware. User-contributed information in these forums enabled better understanding of the serious danger.

![VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*yUglopK8rQSs0v0RLi6ucg.png)

![VirusTotal](https://miro.medium.com/v2/resize:fit:640/format:webp/1*FmIbjt2001i6ktDYIvvUaw.png)

![VirusTotal](https://miro.medium.com/v2/resize:fit:640/format:webp/1*OT6PoVqP0qjgzApp8iLYpA.png)

![VirusTotal](https://miro.medium.com/v2/resize:fit:640/format:webp/1*hkmCsGzyc81FHu1xDVxaeg.png)

![threatfox.abuse.ch](https://miro.medium.com/v2/resize:fit:640/format:webp/1*yQldyO0VbMmS7FAdfgshrw.png)


### Using Intezer Analyzer for Deeper Analysis

![analyze.intezer.com](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Y8lft9VD2mZeSLr71_bg0A.png)

I used Intezer Analyzer for additional investigation of the cracked program since it serves as a powerful instrument for inspecting malware and suspicious file content. Intezer utilizes its expertise to detect files through their genetic malware mapping system. The file entered the platform after which the system identified it as malicious content. Intezer revealed detailed information about the program’s code and actions which indicated multiple connections to established malware families.

![analyze.intezer.com](https://miro.medium.com/v2/resize:fit:720/format:webp/1*TB3SIhilPfBfgztlmKLtKw.png)

The Intezer Analyzer results also showed several MITRE ATT&CK techniques, confirming the file’s malicious behavior. Key findings included:

- Obfuscated Files or Information (T1027): The file used obfuscation to hide its true actions.

- Command and Scripting Interpreter (T1059): It executed suspicious commands using cmd.exe, created processes from unusual locations, and used the tasklist command, a common tool for listing running processes, to hide its activity.

- Dead IP Connections: The malware tried connecting to inactive IPs, suggesting communication with a C&C server.

![analyze.intezer.com](https://miro.medium.com/v2/resize:fit:720/format:webp/1*6mYwgTyequMS0JouYcZOYA.png)

Research showed that the malware connected with previously detected IP addresses and domain which belong to C&C servers linked to Lokibot and Lumma Stealer malware operations. The identified IP addresses as well as the domain connected users to servers operating Command and Control (C&C) services linked to Lokibot and Lumma Stealer malware.

![analyze.intezer.com](https://miro.medium.com/v2/resize:fit:720/format:webp/1*dbja5VOeeK2f_No1m7Q6-Q.png)

The process tree starts when <ANALYZED-FILE-NAME>.exe triggers a cmd.exe execution with the /NCRC flag disabled for check bypassing. This sequence of events leads the file to create a batch script named Geek.tmp.bat before it executes the script possibly for executing subsequent malicious orders. Tasklist.exe works as a process information gatherer while findstr.exe serves as a tool to detect security applications like antivirus programs to evade discovery. Moreover it generates new folders while taking in supplementary malicious payloads by executing extrac32.exe. Various cmd.exe commands generate logical combinations of files including Guyana.com which may serve as targets for execution. The malicious activities of choice.exe delay operations while the hijacked svchost.exe and WmiPrvSE.exe system processes keep persistence active for system activities. The malware makes continuous efforts to evade detection through the implementation of standard system utilities along with obfuscation methods throughout its operation.

### Conclusion

The proper assessment of cracked software or suspicious programs needs a systematic procedure for their identification and evaluation. The tools known as sandboxes (Browserling or Any.Run) enable secure execution of files since they allow me to monitor their behavior without damaging my system. The analysis of uploads sent to VirusTotal along with Intezer Analyzer detects malware indicators while offering structural and behavioral information about the files. The tools I use for comprehensive analysis include many others besides what I have demonstrated. The evaluation of command line activity together with network communications and process trees demonstrates how programs attempt to survive detection by evading detection.

**While piracy is against the law I specifically disapprove of software piracy and all such illegal activities. The practice of using cracked programs entails personal responsibility because they present considerable security and legal dangers. Choosing legitimate safe sources for software is your only method to protect your system and stay away from possible legal troubles.**

---

