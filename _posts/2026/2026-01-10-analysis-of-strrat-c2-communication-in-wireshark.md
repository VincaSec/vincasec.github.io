---
title: "Analysis of STRRAT C2 Communication in Wireshark"
date: 2026-01-10
categories: [Malware, Wireshark]
image:
  path: /assets/2026/STRRAT/rat.jpg
  alt: STRRAT C2 Network Traffic Analysis
---

## Introduction

As part of a practical exercise in analyzing malicious network traffic and identifying compromised systems, I analyzed a PCAP file downloaded from the [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/2024/07/30/index.html) website.

The goal of this analysis was to examine real-world network traffic using **Wireshark** and to distinguish legitimate network behavior from malicious activity by focusing on IP addresses, packet counts, protocols, and communication patterns.

---

## Network Overview

Within the captured network traffic, I identified two primary systems:

- **Workstation:** `DESKTOP-SKBR25F` (172.16.1.66)  
- **Domain Controller:** `WIRESHARK-WS-DC` (172.16.1.4)

These systems generated the majority of the observed traffic and were the main focus of the investigation.

![Wireshark](/assets/2026/STRRAT/rat21.png)

---

## DNS Traffic Analysis

I began by examining DNS traffic to identify the domains contacted by the internal systems. Queries to the following legitimate domains were observed:

- `microsoft.com`
- `bing.com`
- `msn.com`
- `officeapps.live.com`

In addition, DNS requests to the following domains stood out:

- `github.com`
- `repo1.maven.org`
- `objects.githubusercontent.com`

Although these services are legitimate, they are frequently used to host and distribute files or code. In the context of malware analysis, such platforms can be abused by attackers to download additional payloads or malicious modules, making them worth closer inspection.

![Wireshark](/assets/2026/STRRAT/rat8.png)

---

## HTTP Requests and External Services

Several HTTP requests were directed toward external IP addresses. One request targeted the file `/connecttest.txt`, which is commonly used by Windows systems to verify internet connectivity. This behavior appeared legitimate and aligned with documented Microsoft functionality.

[Microsoft Documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network)

Another HTTP request targeted the `/json/` endpoint on an external service, which was identified as `ip-api.com`. This service provides geolocation data based on IP addresses.

This behavior was suspicious, as malware often uses geolocation services to determine the physical location of infected systems. Such information can be used to filter victims, avoid certain regions, or tailor malicious activity based on geographic location.

[Security Boulevard](https://securityboulevard.com/2024/09/unmasking-malware-through-ip-tracking-how-attackers-exploit-ip-and-geo-location-data-to-target-your-network/)

![Wireshark](/assets/2026/STRRAT/rat18.png)

---

## LDAP Traffic Analysis

During the analysis of LDAP traffic, I applied the following Wireshark filter:

```bash
ldap contains "CN=Users"
```

This allowed me to extract information related to user accounts in Active Directory. Through this process, I identified the user Clark Collier, whose account activity originated from the workstation DESKTOP-SKBR25F.

Identifying the affected user is a critical step in incident response, as it helps determine the scope of compromise and potential lateral movement within the network.

![Wireshark](/assets/2026/STRRAT/rat20.png)

## IP Address Analysis

To better understand external communication, I generated a list of all IP addresses present in the PCAP file and sorted them by packet count. Most external IP addresses belonged to Microsoft services located in the United States.

Although the total amount of data exchanged with this IP address from Lithuania was relatively small (approximately 39 kB), the communication consisted of a relatively high number of packets (411 packets). This traffic pattern differs from that of legitimate services, which typically transfer larger amounts of data with fewer packets. A higher packet count combined with low data volume is characteristic of command-and-control communication, where small heartbeat messages and status updates are exchanged frequently rather than large payloads being transferred.

![Wireshark](/assets/2026/STRRAT/rat17.png)

## Payload Inspection and TCP Stream Analysis

While inspecting the hexadecimal representation of several packets, I noticed unusual and non-random data patterns. To better understand the content of this communication, I used the Follow TCP Stream feature in Wireshark.

This analysis revealed clear indicators of STRRAT malware activity. 

![Wireshark](/assets/2026/STRRAT/rat9.png)

![Wireshark](/assets/2026/STRRAT/rat10.png)

[corelight.com blog](https://corelight.com/blog/newsroom/news/strrat-malware)

[malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/jar.strrat)

[fortinet.com](https://www.fortinet.com/blog/threat-research/new-strrat-rat-phishing-campaign)

## STRRAT C2 Communication Details

The C2 communication included detailed system information transmitted by the compromised machine, such as:

- **Computer name:** DESKTOP-SKBR25F  
- **Username:** ccollier  
- **Operating system:** Windows 11 Pro 64-bit  
- **Active antivirus:** Windows Defender  
- **Estimated system location:** United States  

This information was transmitted as part of periodic **heartbeat messages** (`ping|STRRAT`) sent from the infected machine to the C2 server. These heartbeat messages serve to notify the attacker that the system is still active and connected, and they can also carry basic system details and status updates.

The communication also contained a field labeled **“Not Installed”**, which likely indicates that a specific STRRAT module or feature was not present on the system. A value of **1.6** was also observed, which most likely represents the STRRAT malware version.


---

## Base64-Encoded Data Analysis

Within the C2 traffic, I identified multiple **Base64-encoded strings**. After decoding them, the data revealed names of directories, applications, and files present on the system, including:

- `Documents`  
- `Home`  
- `Pictures`  
- `Program Manager`  

This indicates that the malware was actively enumerating the file system and collecting information about the user environment, which is typical behavior for remote access trojans (RATs).

![Wireshark](/assets/2026/STRRAT/rat11.png)

![Wireshark](/assets/2026/STRRAT/rat14.png)

![Base64](/assets/2026/STRRAT/rat16.png)

---

## Conclusion

This analysis proved to be highly valuable and educational. By examining network traffic across multiple protocols **DNS, HTTP, SMB, and LDAP**. I was able to observe normal enterprise network behavior while also identifying suspicious and malicious communications.

Tracking the STRRAT malware’s **C2 heartbeat messages** provided clear evidence of system compromise and demonstrated how attackers collect system, user, and file structure information from infected hosts. While most of the observed traffic was legitimate, a small number of external IP addresses and HTTP requests stood out as malicious.
