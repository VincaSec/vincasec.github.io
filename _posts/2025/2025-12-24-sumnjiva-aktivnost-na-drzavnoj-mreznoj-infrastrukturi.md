---
title: "Sumnjiva mrežna aktivnost sa IP adrese državnog ASN-a"
date: 2025-12-24
categories: [Security, Network, Incidents]
---

Tokom decembra primećena je sumnjiva aktivnost na mreži koja potiče sa IP adrese unutar jednog državnog ASN-a. Nekoliko nezavisnih bezbednosnih servisa označilo je ovu IP adresu kao malicioznu, zbog ponavljanih pokušaja automatizovanog pristupa udaljenim sistemima, što ukazuje na moguće pokušaje prijave ili skeniranja servera.


![Crowdsec](https://i.postimg.cc/ZnJjCwPn/rs.png)  

![Crowdsec](https://i.postimg.cc/xC6N3gDC/rs1.png)  

![Crowdsec](https://i.postimg.cc/Jn3Vfd4H/rs5.png) 

Analiza dostupnih podataka pokazuje da sa ove adrese tokom dužeg perioda dolazi do pokušaja pristupa mejl nalozima, uglavnom preko POP3 i IMAP servisa. Aktivnost nije izolovana ili kratkotrajna, već se ponavlja nedeljama, sa obrascima koji podsećaju na ponašanje kompromitovanih sistema ili uređaja zaraženih malverom.

![AbuseIPDB](https://i.postimg.cc/FKsLdw8T/rs2.png)

![AbuseIPDB](https://i.postimg.cc/G3YH2c94/rs3.png)


Pored toga, IP adresa je u različitim trenucima bila povezana sa većim brojem NAS uređaja koji koriste servise za daljinski pristup. Takvi uređaji često automatski kreiraju poddomene radi lakšeg povezivanja spolja, ali ukoliko nisu pravilno podešeni ili ažurirani, mogu postati izvor bezbednosnih problema, čak i bez znanja svojih vlasnika.

![VirusTotal](https://i.postimg.cc/4NSMSTb7/rs4.png)

Iako nije moguće sa sigurnošću utvrditi tačan uzrok ili konkretan uređaj iza ove aktivnosti, činjenica da je IP adresa dospela na više javnih bezbednosnih lista ukazuje na postojanje stvarnog i još nerešenog problema.

