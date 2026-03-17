---
title: "Detected Malicious Activities Originating from Judicial Information System"
date: 2026-03-17
categories: [Security, Network, Incidents]

---

While researching Serbian ASN networks connected to government institutions, I analyzed certain IP addresses to see if they were compromised. My goal was to identify if infected devices were being used to launch attacks on other systems. I focused on network anomalies within the state infrastructure, as there were clear signs that these resources were acting as origin points for cyberattacks.

![POC](/assets/2026/judiciary/sud.png)

Using tools like AbuseIPDB and CrowdSec, I located one active IP address belonging to the judicial sector's network. By checking logs and the address history via AbuseIPDB, I found several Indicators of Compromise (IoC), specifically vulnerability scanning and brute-force attacks against WordPress sites. These findings suggest that a device behind a NAT (Network Address Translation) gateway within the judicial network is likely compromised, allowing malicious traffic to exit through a legitimate government IP.

![POC](/assets/2026/judiciary/sud1.png)

![POC](/assets/2026/judiciary/sud2.png)

