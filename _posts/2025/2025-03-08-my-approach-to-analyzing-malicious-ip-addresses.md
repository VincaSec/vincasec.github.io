---
title: "My Approach to Analyzing Malicious IP Addresses"
date: 2025-03-09 
categories: [Malware, OSINT]
image: https://miro.medium.com/v2/resize:fit:720/format:webp/1*mw8GRH4-AgfOZqXVYr6dVg.jpeg
alt: "wallpaper malware"
---

## Introduction

Hello everyone, in this Medium blog, I’m going to write about analyzing malicious traffic with a couple of tools that can be useful for further investigations. For this, I’ll start by using a random IP address I found online, which is known to be malicious. In my next blog, I’ll dive deeper into analyzing malicious traffic, focusing on well-known malware and their creators.

### WHOIS Lookup

I would go first to check the WHOIS database for more detailed information about the IP address. The WHOIS query provides insights into the ownership, registration details, and contact information associated with the IP.

**WHOIS Database:** 
![WHOIS](https://miro.medium.com/v2/resize:fit:720/format:webp/1*MRQBh3BC_aPSsQD-6vXIvQ.png)  


[whois.domaintools.com](https://whois.domaintools.com)


![WHOIS](https://miro.medium.com/v2/resize:fit:720/format:webp/1*lj8tq7MqRCp9rXAPjoTURg.png)  

The IP address I’ve been analyzing is associated with FPT Telecom, a major telecommunications provider in Vietnam. According to the WHOIS data, the netname is FPT-STATICIP-NET, and the IP is allocated as non-portable. The admin contact for this IP is Luong Duy Phuong, based in Vietnam, with a contact number of +84–28–73002222. The tech contact is listed as the Network Operation Center (NOC) at FPT Telecom, reachable at +84–28–73093388.

The IP range associated with this address is 42.112.20.0/24, and it is registered under AS18403, originating from Vietnam’s Internet Network Information Center (VNNIC). This allocation is managed by MAINT-VN-FPT, indicating that the IP belongs to FPT Telecom’s network infrastructure.

### Reverse IP Lookup

![WHOIS](https://miro.medium.com/v2/resize:fit:720/format:webp/1*7YMNGA0H-I4P5MBxU24Osw.png) 


[shodan.io](https://shodan.io) 

I would start off by doing a reverse IP lookup to help obtain more data about the IP address. This helps me check its history and see if any domain changes have ever occurred with it before. Secondly, I try resolving the IP address into a domain to gain further context. But in this case, I did not find any positive results via these means, which is sometimes the case with some malicious IPs that don’t have a clear history or domain association.

### Shodan and Censys

My next move would be to use tools like Shodan or Censys to gather more detailed information on the IP address. These allow me to scan the services of the IP and check for any potential vulnerabilities.

**Shodan**  
Shodan is a search engine for Internet-connected devices. It makes visible details like what ports are open on an IP address. For example, I can see if common ports like 443 (HTTPS), which is running OpenVPN Access Server CWS, 3128 (Proxy), which indicates a Squid proxy, and 6881 associated with BitTorrent protocol. As far as port 6881, which is the most common one to use for BitTorrent traffic, is concerned, having DHT nodes means the IP is very likely engaged in helping file sharing. The DHT nodes are part of the distributed network that helps other users find files or peers without relying on a central server. Ports 8000 appear to be running Nginx, an HTTP server, and 8001, 8080 are also HTTP alternate ports, possibly hosting web applications or services.

**DHT Nodes** 

![DHT Nodes](https://miro.medium.com/v2/resize:fit:424/format:webp/1*Nt4CTohYgpZBoq-IGa-D7g.png) 

What’s more, Shodan can even highlight vulnerable versions of services, for instance, allegedly squid proxy is vulnerable to CVE-2024–45802 and CVE-2024–25617, last time checked 2025–02–24.

**Note: While the device may not necessarily be affected by all the vulnerabilities identified, these risks are inferred based on the software and version information.**

### AbuseIPDB

![AbuseIPDB](https://miro.medium.com/v2/resize:fit:640/format:webp/1*APUttZihoe4rqah5oBEN0g.png)

[abuseipdb.com](https://abuseipdb.com)

My next step would be to use AbuseIPDB, a tool that allows me to check if the IP address is known for malicious activity. This website provides easy but useful information regarding the IP, including ISP, Usage Type, ASN (Autonomous System Number), Domain Name, Country, and City. By verifying the IP on AbuseIPDB, I can find out if it has been flagged for any malicious or suspicious usage, which will assist in confirming if this IP is utilized for any confirmed malicious activity.

![AbuseIPDB](https://miro.medium.com/v2/resize:fit:720/format:webp/1*lsFdFirjkCBttIM6nM442Q.png)

On AbuseIPDB, I can also view user reports and see comments on the IP address. The reports could include traffic logs or details on the malicious activity that has been detected with the IP. Through reading the comments, I can obtain information about how the IP has been involved in malicious activity, e.g., the type of attack or the malicious activity it has been linked to. This can provide a better indication of what kind of traffic is being generated, if it is hacking attempts, spam, or other forms of cybercrime.

### VirusTotal

![VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*kSeBRQMDWxEB0U3FqaM95w.png)

[virustotal.com](https://virustotal.com)

On VirusTotal, I can see whether the IP address has ever been flagged as malicious or suspicious by other antivirus engines. The website aggregates results from various security vendors, so I can see which ones have flagged the IP as a threat. If the IP is flagged by multiple antivirus vendors, the likelihood of it being used for something malicious is greater.

![VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*kSZUWoWJaM2eN3jYGvBKlQ.png)


The IP address appears to communicate with malware and other suspicious programs. I observed that there are multiple utorrent.exe files associated with this IP, which have been flagged as malicious. These files have different hashes compared to the official version from the uTorrent site, indicating they may have been tampered with or are part of a malicious campaign.


### iknowwhatyoudownloaded.com

![iknowwhatyoudownloaded](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Dkx8GQKlGB5hlVg96sQqaQ.png)
[iknowwhatyoudownloaded.com](https://iknowwhatyoudownloaded.com)

The website **iknowwhatyoudownloaded** collects data about torrent activity in two ways: by parsing torrent sites and by tracking the DHT (Distributed Hash Table) network. This allows them to track torrent downloads and provide data on the shared files.

To further investigate the IP address, I decided to check it on iknowwhatyoudownloaded. By entering the IP address, I can see the list of downloaded files that it is linked to, which can provide additional clues on its activity and potential links to malicious behavior.


### ThreatBook.io

![threatbook.io](https://miro.medium.com/v2/resize:fit:720/format:webp/1*yWxZlBxDe175GqmQYu2G9g.png)
[threatbook.io](https://threatbook.io)

![threatbook.io](https://miro.medium.com/v2/resize:fit:720/format:webp/1*oWrd5Wg_QTCSUP1a10KNnA.png)

I can get more detailed information about the malicious behavior for the IP address on **ThreatBook.io**. It provides attack pattern, target, and other threat-related information. It also gives me a history of attacks against the IP address, which allows me to understand the trend and the scope of attack.

### Conclusion

In conclusion, the investigation of this IP address reveals evidence of malicious activity. The IP is linked to suspicious services such as OpenVPN Access Server and Squid proxy, which are typically used to mask the attacker’s identity, bypass security controls, and facilitate encrypted communication for malicious purposes. OpenVPN can be abused by cybercriminals to hide their location and enable secret communication with malware or command-and-control servers, making it difficult to trace their activity. Similarly, Squid proxy can be employed to anonymize malicious traffic, bypass network security controls, and even serve as an attack launch point.

---