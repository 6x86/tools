List heavily based on this from the great **[pwndefend](https://www.pwndefend.com/2020/07/22/learn-all-the-things)**.\
Just added some more detail and *(maybe)* useful links for the tools as some were unfamiliar to me.

# Open Source Intelligence Gathering Tools

**General read**\
https://en.wikipedia.org/wiki/Open-source_intelligence

**Whois**\
Query details of domain name/IP ownership \
https://en.wikipedia.org/wiki/WHOIS

**Nslookup**\
Name Server lookup \
https://en.wikipedia.org/wiki/Nslookup

**FOCA**\
Fingerprinting orgs with collected archives, find metadata in docs \
https://github.com/ElevenPaths/FOCA

**Maltego**\
*$COMMERCIAL$* - OSINT and graphical link tool \
https://www.maltego.com/
https://en.wikipedia.org/wiki/Maltego

**TheHarvester**\
Harvest email addresses\
https://github.com/laramies/theHarvester
https://tools.kali.org/information-gathering/theharvester

**Shodan**\
Search engine for devices\
https://www.shodan.io/

**Recon-ng**\
Recon framework\
https://github.com/lanmaster53/recon-ng
https://tools.kali.org/information-gathering/recon-ng

# Network and Vulnerability Scanning Tools

**Nmap**\
Network mapper, host discovery and port scanning, version and OS detection\
https://nmap.org/download.html
https://en.wikipedia.org/wiki/Nmap

**Nikto**\
Web server vuln scanner\
https://cirt.net/Nikto2
https://en.wikipedia.org/wiki/Nikto_(vulnerability_scanner)

**OpenVAS**\
Vuln assessment scanner\
https://www.openvas.org/
https://en.wikipedia.org/wiki/OpenVAS

**SQLMap**\
Automates detecting and exploiting SQL injection flaws\
https://github.com/sqlmapproject/sqlmap

**Nessus**\
*$COMMERCIAL$* - Another automated scanner\
https://www.tenable.com/products/nessus
https://en.wikipedia.org/wiki/Nessus_(software)

# Credential Testing Tools

**John**\
Password/hash cracking tool\
https://www.openwall.com/john/
https://en.wikipedia.org/wiki/John_the_Ripper

**Hashcat**\
Password/hash cracking tool\
https://hashcat.net/hashcat/
https://en.wikipedia.org/wiki/Hashcat

**Medusa**\
Modular login brute-forcer, parallel testing thread based\
https://github.com/jmk-foofus/medusa
https://www.hackingarticles.in/comprehensive-guide-on-medusa-a-brute-forcing-tool/

**THC-Hydra**\
Very fast logon cracker\
https://github.com/vanhauser-thc/thc-hydra
https://en.wikipedia.org/wiki/Hydra_(software)

**CeWL**\
Wordlist generator from URL\
https://github.com/digininja/CeWL/
https://tools.kali.org/password-attacks/cewl

**Cain and Abel**\
Password recovery tool for Windows.\
https://web.archive.org/web/20190603235413if_/http://www.oxid.it/cain.html
https://en.wikipedia.org/wiki/Cain_and_Abel_(software)

**Mimikatz**\
Extract plaintext passwords, hash, PIN and kerberos tickets from memory.  PTH, PTT, Golden tickets\
https://github.com/gentilkiwi/mimikatz
https://www.varonis.com/blog/what-is-mimikatz/

**Patator**\
Brute forcer\
https://github.com/lanjelot/patator
https://tools.kali.org/password-attacks/patator

**Dirbuster**\
Brute force directories and filenames on web servers\
https://sourceforge.net/projects/dirbuster/
https://tools.kali.org/web-applications/dirbuster

**W3AF**\
Identify and exploit SQL Injection\
http://w3af.org/download
https://en.wikipedia.org/wiki/W3af

# Debugging Tools

**OLLYDBG**\
http://www.ollydbg.de/download.htm
https://en.wikipedia.org/wiki/OllyDbg

**Immunity**\
https://www.immunityinc.com/products/debugger/
https://hydrasky.com/malware-analysis/immunity-debugger/

**Gdb**\
https://www.gnu.org/software/gdb/download/
https://en.wikipedia.org/wiki/GNU_Debugger

**WinDBG**\
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools
https://en.wikipedia.org/wiki/WinDbg

**IDA**\
https://www.hex-rays.com/products/ida/support/download_freeware/
https://en.wikipedia.org/wiki/Interactive_Disassembler

# Software Assurance Tools

**Spotbugs**\
Open-source static code analyser\
https://spotbugs.github.io
https://en.wikipedia.org/wiki/FindBugs

**FindBugs**\
Open-source static code analyser\
http://findbugs.sourceforge.net/
https://en.wikipedia.org/wiki/FindBugs

**FindSecBugs**\
Spotbugs plugin for java web app security audits\
https://find-sec-bugs.github.io/
https://medium.com/@suthagar23/findsecbugs-how-to-find-the-security-bugs-533a3362946c

**Peach**\
SmartFuzzer for generation and mutation based fuzzing\
http://community.peachfuzzer.com/WhatIsPeach.html

**AFL Fuzzy Lop**\
Brute force fuzzer\
https://github.com/google/AFL

**SonarQube**\
Static code analysis - Java, JavaScript, C#, Go, Python, etc\
https://www.sonarqube.org/downloads/
https://en.wikipedia.org/wiki/SonarQube

**YASCA**\
Yet Another Source Code Analyser\
http://scovetta.github.io/yasca/
https://en.wikipedia.org/wiki/Yasca

# Wireless Testing

**Aircrack-ng**\
Network detector, packet sniffer, WPA/2 cracker\
https://www.aircrack-ng.org/downloads.html
https://en.wikipedia.org/wiki/Aircrack-ng

**Kismet**\
Network detector, packet sniffer, Intrusion Detection System\
https://www.kismetwireless.net/downloads/
https://en.wikipedia.org/wiki/Kismet_(software)

**WiFite**\
Wireless network auditor\
https://github.com/derv82/wifite2
https://null-byte.wonderhowto.com/how-to/automate-wi-fi-hacking-with-wifite2-0191739/

**WiFi-Pumpkin**\
Framework for rogue access point attack\
https://github.com/P0cL4bs/wifipumpkin3
https://github.com/P0cL4bs/WiFi-Pumpkin-deprecated
https://kalilinuxtutorials.com/wifi-pumpkin-framework/

# Web Proxy Tools

**OWASP ZAP**\
Proxy server, application security scanner\
https://www.zaproxy.org/download/
https://en.wikipedia.org/wiki/OWASP_ZAP

**BURP Suite**\
Integrated platform for security testing of web applications\
https://portswigger.net/burp/communitydownload
https://tools.kali.org/web-applications/burpsuite
                

# Social Engineering Tools

**Socail Engineering Toolkit**\
https://github.com/trustedsec/social-engineer-toolkit

**BeEF**
Browser Exploitation Framework\
https://github.com/beefproject/beef
https://resources.infosecinstitute.com/beef-part-1/
                

# Remote Access Tools

**SSH**\
Secure SHell\
https://en.wikipedia.org/wiki/Secure_Shell

**Ncat**\
Netcat alternative\
https://nmap.org/ncat/
https://en.wikipedia.org/wiki/Netcat#ncat

**Netcat/nc**\
Read and write to network connections using TCP or UDP\
https://sourceforge.net/projects/nc110/
https://en.wikipedia.org/wiki/Netcat

**Proxychains**\
Tool to force any TCP connection through TOR or SOCKS/HTTP(S) proxy\
https://github.com/haad/proxychains
https://linuxhint.com/proxychains-tutorial/

# Network Tools

**Wireshark**\
Open-source packet analyser\
https://www.wireshark.org/download.html
https://en.wikipedia.org/wiki/Wireshark

**Hping**\
Tool to send custom TCP/IP packets, handles fragmentation and arbitrary packet size & content\
https://github.com/antirez/hping
https://en.wikipedia.org/wiki/Hping

# Mobile Tools

**Drozer**\
(formerly Mercury) is the leading security testing framework for Android\
https://github.com/FSecureLABS/drozer
https://resources.infosecinstitute.com/android-penetration-tools-walkthrough-series-drozer/

**APKX**\
APK Decompiler for the lazy\
https://github.com/b-mueller/apkx
https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05b-basic-security_testing

**APK Studio**\
IDE for reverse engineering Android application packages\
https://github.com/vaibhavpandeyvpz/apkstudio/releases
https://www.xda-developers.com/decompile-edit-and-recompile-in-one-tool-with-apk-studio/

# Misc Tools

**Powersploit**\
Collection of PowerShell modules used to aid pentest during all phases of an assessment\
https://github.com/PowerShellMafia/PowerSploit
https://powersploit.readthedocs.io/en/latest/

**Searchsploit**\
Search Exploit-DB for known vulns\
https://www.exploit-db.com/searchsploit

**Responder**\
LLMNR NBT-NS & MDNS poisoner, will answer specific NetBIOS NS queries based on name suffix\
https://github.com/SpiderLabs/Responder
https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/

**Impacket**\
Collection of Python classes for working with network protocols\
https://github.com/SecureAuthCorp/impacket
https://www.hackingarticles.in/impacket-guide-smb-msrpc/

**Empire C2**\
Post-exploit Windows exploitation framework\
https://github.com/EmpireProject/Empire
https://null-byte.wonderhowto.com/how-to/use-powershell-empire-getting-started-with-post-exploitation-windows-hosts-0178664/

**Metasploit**\
Grandaddy of pentest framework\
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
https://www.offensive-security.com/metasploit-unleashed/
