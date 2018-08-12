# Yodawg.txt

## Description:

Solved by noproplem
------------

This challenge consist of identifying and unpacking varies levels of different compression, encryption and encodings.

Challenge file:

```
yodawg.txt-0460c8c5e71fac37c166ceffbab81a5996be0cdf
MD5: 05504e1edbbde71ad2ec0bedcff66705
```

## Step 1

First we identify the initial packed format:

```
$>file yodawg.txt-0460c8c5e71fac37c166ceffbab81a5996be0cdf 

yodawg.txt-0460c8c5e71fac37c166ceffbab81a5996be0cdf: gzip compressed data, last modified: Fri Aug 10 04:13:01 2018, from Unix
```

## Step 2: Lets unpack the tar using the commandline:

```
$> tar xfv yodawg.txt-0460c8c5e71fac37c166ceffbab81a5996be0cdf

yodawg.txt
```

## Step 3

Identify the unpacked file

```
$>file yodawg.txt
yodawg.txt: ASCII text, with very long lines, with no line terminators
```

## Step 4

Since its ASCII we can print it

```
$>cat yodawg.txt

NTc1NzM4Njc1bjQ3NDYzMzVuNzk3NzY3NTM1MzQyNnM1bjU3NDY3OTVuNDM0MjM1NjI3OTQyNzM2MTU3NzQ2cDQ5NDc1Njc1NTkzMjM5Nm82MTU3MzU2cjQ5NDg0cjc2NDk0ODY0NnA0OTQ4NDIzMTY0NDM0MjY4NjI2OTQyNnA2MjZxNHI3NjVuNDc1NjZvNDk0NzMxNnA2MzMzNHI2ODVuMzI1NTY3NjE1NzM0Njc2NTU3Mzg2NzVuNTczNTZuNjIzMjUyNnA1bjQzNDI3NDVuNTg0cjduNTk1NzY0NnA0OTQ4NHI3NjQ5NDg2cDc2NDk0NzRyNjg2MjY5NDI2bzVuNTMzMTZwNjI2cTRyNzY1bjQ3NTU2NzY0MzI2ODcwNjI0NzU1Njc2NTU3Mzg2NzVuNDc1NTc0NW41NzM1Nm42MjMyNTI2cDRwNjczcTNx
```

## Step 5

It looks like all characters are in the default base64 alphabet.

```
$>base64 -d yodawg.txt

575738675n4746335n7977675353426s5n5746795n434235627942736157746p494756755932396o6157356r49484r764948646p49484231644342686269426p626q4r765n47566o4947316p63334r685n32556761573467655738675n57356n6232526p5n4342745n584r7n5957646p49484r7649486p7649474r686269426o5n53316p626q4r765n4755676432687062475567655738675n4755745n57356n6232526p4p673q3q

```

## Step 6
This looks interesting. The trick is to notice the small number of characters used (less than base64). Until the 'n' it actually looks like ascii encoded as hex bytes.

There are actually 5 wierd characters n, s, p, r, q, o. Wierd the only hex characters missing are a, b, c, d, e, f. So maybe the transformation between these characters are the key to decrypting this. Lets write a bruteforcer in python:

```
import string
import base64
from itertools import permutations

a = "575738675n4746335n7977675353426s5n5746795n434235627942736157746p494756755932396o6157356r49484r764948646p49484231644342686269426p626q4r765n47566o4947316p63334r685n32556761573467655738675n57356n6232526p5n4342745n584r7n5957646p49484r7649486p7649474r686269426o5n53316p626q4r765n4755676432687062475567655738675n4755745n57356n6232526p4p673q3q"

wierd = list("nsprqo")

for x in permutations(list("abcdef")):
	tmp = a
	for y in range(len(wierd)):
		tmp = tmp.replace(wierd[y], x[y])

	try:
		tmp = tmp.decode('hex')
		if all(x in string.printable for x in tmp):
			print tmp
	except:
		pass
```

Which gives strings like the following that looks like base64.:

```
WW8gZGF3ZywgSSBnZWFyZCB5byBsaWtkIGVuY29oaW5lIHLvIHdkIHB1dCBhbiBkbmLvZGVoIG1kc3LhZ2UgaW4geW8gZW5jb2RkZCBtZXLzYWdkIHLvIHkvIGLhbiBoZS1kbmLvZGUgd2hpbGUgeW8gZGUtZW5jb2RkKg==

WW8gZGF3ZywgSSBnZWFyZCB5byBsaWtkIGVuY29maW5lIHLvIHdkIHB1dCBhbiBkboLvZGVmIG1kc3LhZ2UgaW4geW8gZW5jb2RkZCBtZXLzYWdkIHLvIHkvIGLhbiBmZS1kboLvZGUgd2hpbGUgeW8gZGUtZW5jb2RkKg??
```

## Step 7

Lets modify the script to handle the base64 decoding:

```
import string
import base64
from itertools import permutations

a = "575738675n4746335n7977675353426s5n5746795n434235627942736157746p494756755932396o6157356r49484r764948646p49484231644342686269426p626q4r765n47566o4947316p63334r685n32556761573467655738675n57356n6232526p5n4342745n584r7n5957646p49484r7649486p7649474r686269426o5n53316p626q4r765n4755676432687062475567655738675n4755745n57356n6232526p4p673q3q"

wierd = list("nsprqo")

for x in permutations(list("abcdef")):
	tmp = a
	for y in range(len(wierd)):
		tmp = tmp.replace(wierd[y], x[y])

	try:
		tmp = tmp.decode('hex')
		tmp = base64.b64decode(tmp)
		if all(x in string.printable for x in tmp):
			print tmp
	except:
		pass

```

One of the decoded strings looks like the following:

```
Yo dawg, I heard yo like encoding so we put an encoded message in yo encoded message so yo can de-encode while yo de-encode.
```

## All done!

Good work - the flag checks out!, we are done :)
