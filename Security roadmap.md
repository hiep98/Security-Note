LIST TRACK NEED TO COVER

# ***Practice lab platform***
redteam- offensive-pentest: tryhackme,hackthebox,vulnhub
web: pentesterlab,portswigger
Blueteam- secops - incident response - malware: tryhackme,cyberdefenders,blueteamlabs.online

# ***Security Operation (secops):***
## Theory,term,standard:
- MITRE att,shield, cyber kill chain 
- Defence in depth, hardening
- Threat modeling
- SOC
- Threat hunting

## Learn both theory and practice with tool, opensource:
-SIEM: Elk,splunk
-Endpoint Detection & Response (EDR): wazuh,osquery,fleet
-IDS,IPS: snort, suricata
-Threat Intelligence: MISP,the hive,cortex - it is high level to setup for beginner
-Orchestrating Security Operations: PatrOwl

## Advice:

You should implement the SIEM system yourself to understand the following:

- Components of the SIEM system

- Experience in searching keywords, building tables to track, monitoring based on how to detect attack behavior

- Deploying warning when detecting an attack behavior

- Deploy case detect, defense on SIEM under an attack scenario

- Simulator attack: Try to attack to see the ability to detect cases on SIEM, to evaluate the ability of SIEM I just built.

## Course reference:
https://tryhackme.com/path/outline/blueteam - highly recommend, it is cover secops,forensic,incident response with practice lab

https://www.cybrary.it/info/mitre-attack-defender/

https://education.splunk.com/free

https://www.learnsplunk.com/

https://academy.attackiq.com/

https://www.coursera.org/specializations/ibm-cybersecurity-analyst 

https://www.cyberwarfare.live/certified-purple-team-analyst 

## Other reference:

https://www.blueteamsacademy.com/

https://cyberdefenders.org/labs/

https://drive.google.com/file/d/1ZW8yQ7xCsJWd4bJ3R1np4cnOk-xVi1Zs/view

https://app.letsdefend.io/academy/ 

# ***DIGITAL FORENSIC AND INCIDENT RESPONSE***

    File & disk analysis 
    Windows forensics:Analyzing Windows artifacts
    Network forensic:Analyzing traffic capture files
    Log analysis
    Timeline analysis

We can follow course chfi, FOR308: Digital Forensics Essentials, FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics

Forensic tool: WinHex, regripper, tcpdump etc.
Other incident response tool: GRR, velociraptor


# Other track:
# PENTEST

Planning and Scoping Penetration Tests
Conducting Passive Reconnaissance
Conducting Active Reconnaissance
Analyzing Vulnerabilities
Exploit Network-Based Vulnerabilities
Exploiting Host-Based Vulnerabilities
Test Source Code and Compiled Apps
use Lateral Movement,Persistence,Anti-Forensics Techniques
Analyzing and Reporting Pen Test Results

Course reference:
https://www.pluralsight.com/paths/comptia-pentest-pt0-001

https://my.ine.com/CyberSecurity/learning-paths/a223968e-3a74-45ed-884d-2d16760b8bbd/penetration-testing-student

https://www.udemy.com/course/practical-ethical-hacking/


# WEB PENTEST
top 10 owasp: RCE, Injection (Command Injection, SQL Injection … ), SSRF, XXE, Insecure Deserialization, XSS (Cross-site scripting), CSRF (Cross Site Request Forgery), XS-Leaks (XS-Search), JSONP Leaks, CORS Misconfigurations, HTTP Desync Attacks, Web Cache Poisoning,Insecure Deserialization …
Audit / Secure Code Review
standard: ptes

Course reference: web-300 oswe, INE Web Application Penetration Testing
Document Reference: 
https://github.com/OWASP/www-project-web-security-testing-guide/tree/master/v41

# *Malware analysis*

Static Analysis Techniques - Study Guide


Differences Between a 32-bit and 64-bit Portable Executable
File Identification
Analyzing PE File Structures
Packed Malware Identification and Basic Analysis
From IOCs to YARA Rules
Obfuscated
TLS Callbacks and TRunPE
DLLs, Handles, etc. 
 
tools: ida,yara,x64dbg,...
