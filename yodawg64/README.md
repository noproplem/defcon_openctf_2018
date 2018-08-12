Solution to "yodawg64" by Mark Proxy
====================================

We are presented with a digital photo of a famous phrase afficionado
("rapper" in daily parlance), with no other clues or information
given.

Since the file is in JPEG format, we check for standard stego methods.

steghide shows file a file, and I was lucky to guess password,
`yodawg`.

```
$ steghide extract -p yodawg -sf yodawg100-b2c38d4297c0abf4e9414ce13fa900bbda3ab0e2
```

This gives us flag.7.64.64.64.64.64.64.64.64.64.64.64.64, which
strongly hints at the solution:

```
base64 -d flag.7.64.64.64.64.64.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64.64.64.64.64.64
base64 -d    flag.7.64.64.64.64.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64.64.64.64.64
base64 -d       flag.7.64.64.64.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64.64.64.64
base64 -d          flag.7.64.64.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64.64.64
base64 -d             flag.7.64.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64.64
base64 -d                flag.7.64.64.64.64.64.64.64 > flag.7.64.64.64.64.64.64
base64 -d                   flag.7.64.64.64.64.64.64 > flag.7.64.64.64.64.64
base64 -d                      flag.7.64.64.64.64.64 > flag.7.64.64.64.64
base64 -d                         flag.7.64.64.64.64 > flag.7.64.64.64
base64 -d                            flag.7.64.64.64 > flag.7.64.64
base64 -d                               flag.7.64.64 > flag.7.64
base64 -d                                  flag.7.64 > flag.7
```

Now we have a 7zip file:

```
$ 7z x flag.7
```

This gives flag.file, which is a tar file:

```
$ file flag.file
flag.file: gzip compressed data, last modified: Thu Apr 26 21:08:58 2018, from Unix, original size 10240
```

..which gives us a zip file:

````
$ tar -zxf flag.file
flag.zip
```

..which gives us even more base 64:

```
$ unzip flag.zip
Archive:  flag.zip
 extracting: flag64.txt
```

..which gives us the flag:

```
$ base64 -d flag64.txt

d0n7_w3_D0_th15_ev3ry_fu(kiNg_y34R_
```
