HTB 10. Netmon

1. `nmap -T4 -p- -A 10.10.10.152` shows port 21 (ftp) with anonymous login enabled and lists possibly the `C:` drive, port 80 (http) running `Indy httpd 18.1.37.13946`, and ports 135/139/445 (rpc) reveal machine is running `Microsoft Windows Server 2008 R2`, two webservers running on 5985 and 47001 both are 404s. Webpage probably in `/inetpub`.
2. Go to `10.10.10.152` and shows login. Google `PRTG Network Monitor default credentials` shows `prgtadmin:prgtadmin` that don't work. Google for `PRTG Network Monitor exploit` finds [
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution
](https://www.exploit-db.com/exploits/46527) which needs authentication.
3. Search for `prtg network monitor db file location` finds paths [How and where does PRTG store its data?](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data) to possibly find login credentials
4. `ftp 10.10.10.152` and `cd "Users\All Users\Application Data\"` is access denied. Try `cd "Users\All Users\Application Data\Paessler\PRTG Network Monitor"` which works.
5. Download the three configurations files. Opening the `PRTG Configuration.dat` and searching for `prtgadmin` (the default username) finds encrypted password. Test the `old` file which is encrypted too. Test the `old.back` which has the unencrypted password.
6. Login with credentials `prtgadmin:PrTg@admin2018`, which fails. Lets try `prtgadmin:PrTg@admin2019` since that was from a backup file from a year ago. This password works.
7. Open Burp Suite and intercept finds the cookie needed for the exploit find earlier.
8. Download [the exploit](https://www.exploit-db.com/exploits/46527) and run with `./exploit.sh -u http://10.10.10.152 -c "OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX"` to create admin user with credentials `pentest:P3nT3st!` on the computer not the webinterface.
9. Get [`impacket`](https://github.com/SecureAuthCorp/impacket). Try `psexec.py pentest:P3nT3st!@10.10.10.152` which works to gain a remote shell. Can also try `wmiexec.py` or `smbexec.py`.
10. psexec can only work with the following:
	* TCP port 445
	* The admin$ administrative share available
	* You know a local account’s credential
11. `psexec.py` is less likely to trigger antivirus than metasploit verion. But, both `wmiexec.py` and `smbexec.py` are the least likely to trigger antivirus.
