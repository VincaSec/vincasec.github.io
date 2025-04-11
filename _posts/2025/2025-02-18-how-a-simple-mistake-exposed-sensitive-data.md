---
title: "How a Simple Mistake Exposed Sensitive Data"
date: 2025-02-19
categories: [Vulnerabilities, Leak]
image: https://miro.medium.com/v2/resize:fit:720/format:webp/1*hkw97lKyyJ6kW5jMTDH1mA.jpeg
alt: "wallpaper confidental data"
---

### Government Website Security Weakness

A security weakness exists on a government website that allows confidential labor dispute information to leak publicly. During the period from 2016 to 2022, the website exposed a file that disclosed information about labor disputes with party details such as names and addresses.

#### The file contained:

- Names and addresses of both individuals and companies involved in labor disputes
- Case numbers, case status updates, and related documents
- Other details about the type of dispute, such as monetary claims

Public accessibility should never extend to such a file containing 6,965 records. Certain entries contained obscure action codes that were encrypted, making them difficult to read at first glance but potentially revealing case information.

### How Did This Happen?

While the exact cause remains unclear, I suspect the error occurred when a file called “.DS_Store” was accidentally uploaded to the server. When macOS devices automatically generate the “.DS_Store” file they save folder display preferences together with file details.

The .DS_Store file exposed the names of protected sensitive files while it was stored on this server. Several JSON files stored private dispute data after being identified by the .DS_Store file. The disclosure of sensitive information occurred after public internet services noticed the security flaw during their scans of the detected file.

![LeakIX](https://miro.medium.com/v2/resize:fit:640/format:webp/1*CUXB8QMtVU9QPABuLK07_Q.png)  

### Why Is the “.DS_Store” File a Problem?

Although the “.DS_Store” file seems harmless it releases private file names and paths by mistake. The JSON files which contained sensitive dispute details got revealed through an unexpected JSON exposure incident.

### Conclusion

It’s a reminder of how a small error can suddenly lead to major crises. A single misconfigured file left far more personal data exposed than should have been. It indicates the relevance of being alert to data safety and not missing one such easy component, a system’s data.

Fortunately, once the issue was reported, the team behind the website took quick action to fix it. The exposed files were removed.

---