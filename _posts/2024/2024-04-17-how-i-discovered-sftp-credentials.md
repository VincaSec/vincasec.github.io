---
title: "How I Discovered SFTP Credentials from a Popular Electronics Store’s Webshop"
date: 2024-04-17 
categories: [Vulnerabilities, Leak]
image: https://miro.medium.com/v2/resize:fit:720/format:webp/1*jl0iPc9_cjHf6o75EEINsg.png
alt: "LeakIX"
---

I used website LeakIX to uncover exposed configuration files and credentials, to investigate a domain for security vulnerabilities. My goal was to identify any potential leaks or misconfigurations that could pose a risk. Entering the domain of a well-known electronics store, I quickly found several misconfigurations, including one that stood out: a subdomain named **dev.api.target.com**. I can’t write real name of domain because of privacy and security reasons, so I will use **target.com**.

### The Discovery

As I entered the domain of **target.com**, I found a subdomain named **dev.api.target.com** that appeared to be a development environment. What I found next raised significant concerns. Upon deeper investigation, LeakIX revealed that the **.vscode/sftp.json** file was publicly accessible at the URL:

![LeakIX](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Yi4yiY10ZCoZ_YnAZ3ItuQ.jpeg)  

Upon closer examination, LeakIX revealed a publicly accessible file at the URL http://dev.api.target.com/.vscode/sftp.json. This file, intended for Visual Studio Code’s SFTP configuration, contained sensitive credentials. Specifically, it exposed the SFTP host, protocol, username, password, port, remote path, and upload save settings. The presence of such details posed a significant security risk, as these credentials were verified to be valid by LeakIX.

The Secure File Transfer Protocol (SFTP) is a network protocol used to securely transfer files over a secure connection. Unlike the traditional FTP protocol, SFTP encrypts both the command and data channels, ensuring that all data, including credentials and files, are transmitted securely. SFTP is commonly used for accessing and managing files on remote servers in a secure manner.

![LeakIX](https://miro.medium.com/v2/resize:fit:720/format:webp/1*vFZ14T4CuBGmXbnwwfP53Q.jpeg)  

```
HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Wed, 13 Sep 2023 05:32:07 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 20
Connection: close
X-Powered-By: PHP/5.6.31
Set-Cookie: PHPSESSID=mf42n3b8kp2vnapoag9hj36m61; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Access-Control-Allow-Headers: origin, x-requested-with, content-type
Access-Control-Allow-Methods: PUT, GET, POST, DELETE, OPTIONS

Unauthorized access!
{
    "name": "------------",
    "host": "------------",
    "protocol": "sftp",
    "port": 2221,
    "username": "------------",
    "password": "------------",
    "remotePath": "/srv/------------",
    "uploadOnSave": true
}

```
### Preventive Measures for Securing Sensitive Files

To prevent such leaks, it’s crucial to implement several security measures. First and foremost, sensitive files like .vscode/sftp.json should not be accessible from the public internet. Ensuring proper file and directory permissions can help mitigate unauthorized access. Regular scans with tools like LeakIX can also help identify and address potential vulnerabilities before they are exploited. Additionally, using server-side protections, such as .htaccess rules, can further restrict access to sensitive files and configurations.

---