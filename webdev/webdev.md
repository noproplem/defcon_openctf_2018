# webdev

Visiting the webpage we are presented with a simple login form:

```
<html>
<head>
<title>login</title>
</head>
<body>
<h3>missing login/password</h3>
<form method="post">
<label for="login">login</label> <input type="text" name="login" /><br />
<label for="password">password</label> <input type="password" name="password" /><br />
<button type="submit">Login</button>
</form>
</body>
</html>
```

## sqlmap

We try logging in using credentials admin:admin and use burp to capture the
request. The login is not successful. Selecting the request, we can copy the
raw content to a file naming it login.req.

```
POST / HTTP/1.1
Host: webdev.openctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://webdev.openctf.com/
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

login=admin&password=admin
```

We start sqlmap running in the background to look for sql injections:

```
$ sqlmap --random-agent --level 5 --risk 3 --force-ssl -r login.req
```

## burp intruder

While sqlmap is running, we use burp to setup an intruder attack to brute force
the login credentials. Since we didn't leak any information about possible
usernames, we grab lists of default usernames and passwords from
https://github.com/danielmiessler/SecLists:

* Usernames/top-usernames-shortlist.txt
* Passwords/darkweb2017-top100.txt

## dirb

Having sqlmap and burp intruder running, we start dirb to look for files and
subdirectories to see if we can increase the attack surface:

```
$ dirb https://webdev.openctf.com/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Aug 12 17:13:54 2018
URL_BASE: https://webdev.openctf.com/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: https://webdev.openctf.com/ ----
+ http://webdev.openctf.com/index.php (CODE:200|SIZE:326)
+ http://webdev.openctf.com/favicon.ico (CODE:200|SIZE:3584)
```

## ???

Our background tasks of sqlmap, burp and dirb didn't return anything
interesting. sqlmap didn't find any potential sql injections, burp intruder
didn't find any valid logins and dirb found only index.php and favicon.ico.

One thing to note is that favicon.ico had an unusual file size of 3.5K.

## favicon.ico

We wget the favicon.ico and see that it's a tar archive containing two files:

```
$ wget https://webdev.openctf.com/favicon.ico
$ file favicon.ico
favicon.ico: POSIX tar archive
$ tar tf favicon.ico
index.php
wwwbackup.sh
```

We extract and view the files:

```
$ tar xvf favicon.ico
index.php
wwwbackup.sh
```

### wwwbackup.sh

```
#!/bin/sh

tar cf *

```

### index.php

```
<?php
$message = 'please login';

if ($_POST) {
  if ((!empty($_POST['login'])) && (!empty($_POST['password']))) {
    if ($_POST['login'] === 'scavengerhunt') {
      if ($_POST['password'] === "'; drop database dignity; --") {
        $message = hash_file('md5', 'favicon.ico');
      } else {
        $message = 'invalid password';
      }
    } else {
      $message = 'invalid login';
    }
  }
} else {
  $message = 'missing login/password';
}
?>
<html>
<head>
<title>login</title>
</head>
<body>
<h3><?php echo($message); ?></h3>
<form method="post">
<label for="login">login</label> <input type="text" name="login" /><br />
<label for="password">password</label> <input type="password" name="password" /><br />
<button type="submit">Login</button>
</form>
</body>
</html>
```

We use the username `scavengerhunt` and password `'; drop database dignity; --`
to login. When doing this we receive the string
`7c6515ecfe20b1004f89d46849bad893` from the server. This matches the md5sum
when hashing the file locally:

```
$ md5sum favicon.ico
7c6515ecfe20b1004f89d46849bad893  favicon.ico
```

Submitting the md5sum as the flag we receive our points!
