---
title: "Shodan Analysis: Public Utility Company – Exposed SQL and RDP Services"
date: 2025-05-08
categories: [Vulnerabilities, Leak]
---

During a recent reconnaissance using **Shodan**, the focus was on identifying open and potentially vulnerable services in Serbia, particularly on **TCP port 1433**, commonly used by **Microsoft SQL Server**. When exposed to the public internet without proper security measures, this port can be exploited for **brute-force attacks**, **known vulnerability exploitation**, and **harvesting of sensitive information** through **NTLM responses**.

The scan revealed several publicly accessible SQL Server instances, highlighting **insufficient network segmentation** and **a lack of proper firewall rules or access controls**. One instance, associated with a public IP address in Serbia, exposed:

![Shodan](https://i.postimg.cc/SN9Nbs5Z/kom1.png)

Additionally, **TCP port 3389 (RDP)** was also open on the same host, further increasing the risk surface. **Remote Desktop Protocol** services are a frequent target of automated attacks, and publicly exposing them, especially without additional layers of protection such as VPN, IP whitelisting, or multi-factor authentication, is widely considered poor security practice.

> 🛑 **It is a critical misstep to leave services such as SQL (port 1433) and RDP (port 3389) open to the public internet. These ports are high-value targets in automated scans and brute-force campaigns.**

Further investigation showed that a **subdomain such as `evidencija.target.com`** resolved to an IP address in the range **178.\*\*\*.\*\*\*.\*\*\* – 178.\*\*\*.\*\*\*.\*\*\***, which appears to belong to a public utility company based on WHOIS data. While the main domain `target.com` resolves elsewhere, this subdomain is the only one directly linked to the exposed IP range.

---

> 📌 **Recommendation:** Organizations, particularly in the public sector, should ensure that remote access and database services are not exposed to the public internet. Proper segmentation, access control lists (ACLs), and layered authentication mechanisms are essential to protecting sensitive systems.