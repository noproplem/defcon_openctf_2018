# Stegoxor

The challenge begins by supplying you with a picture (not screenshot) of a multi-monitor desktop.
The user has "computer management" open and several shortcuts to video games and misc. video game modding software, all of which proves to be red herrings when searching for clues.

The challenge previous to this one utilizes steghide, and after a bit of searching we decided to try the same technique on this challenge.

With ```steghide info <file>``` you can reveal whether embedded data is present in the given file or not. However, if the embedded data is password protected, this will yield no results.

The picture contains a tar ball consisting of two files, qr.xor and HACKER.txt. HACKER.txt proves to be "THE HACKER'S HANDBOOK" and qr.xor just identifies as data when running ```file``` on it. The name qr.xor is a possible hint that this might be QR code which needs to be Xor'd with something.

First we tried to do a single byte xor of {0x00, 0xff} on the .xor file since the HACKER.txt hints at this as being a common technique for obfuscating data. When we looked through the results, we noticed that the output which had been Xor'd with 0xff contained plaintext in certain sections of the file. This plaintext proved to be part of the HACKER.txt which lead us to xor the HACKER.txt with the qr.xor file.

Success! The result of this was a JPEG image of a QR code.

![First QR code](https://github.com/noproplem/defcon_openctf_2018/blob/master/stegoxor/images/qr1.jpg)

We scanned the QR code with https://zxing.org/w/decode.jspx and got the result:
```
iVBORw0KGgoAAAANSUhEUgAAAQsAAAELAQMAAAD0mzERAAAABlBMVEUAAAD///+l2Z/dAAAAAnRS
TlP//8i138cAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAacSURBVGiB7ZoxzrNIE4QHEUwGF0DiGmRc
CS6AzQXMlSabayBxAcgIkPt/CtvfbvBLm7S0yVrWK2yXxUxPd3VV+w32j4/wH+TfhuwhDPEKn0e3
TjEUpy25qVNrKRR+kMOuKV61bZbDaFfVb4etVVyH2BSZT/0gqXmcV6VFmaV2ObUc3hkzT77kCRnT
OqaNLYZw1aftQFI5n8Ed8rBmPBXcIhPg9hkagIeV5gux65HX0PGqXfI6dM1oYYq2pHL56wAcIOTL
mJv///wrpRwgPN5deWRehYlv9CyqfPbsu/xbkXhAchj6ZqIOQiAr37H5hHno7a0k9YOkbe/bI9ur
W4fAM0zdtoeNl0ofP8iRryo2A8eYuHm79+WR7Nm1ROIZ29kP8u5sPi/dNhFU27ttOcvP56/+E10f
iKWrJgHPq7Bmipzntsf2yWHm9ZGuwg+yd1SbvWKrQ0sN0S3S9u7XqafUmtEP8o5rbWtxNpMg5Zy2
V9A3jly+wvrwg+wdFAj/2TuwhIvDXDjPUOrZ2eIHsbwWRDQEKGQiNyMczN9yjwrz4Qch/d9hrfqm
Cs3Qc3QAN96Z+lCfTe0HeXfsuFxSu4e1JkNjORuJz6naMwZPSN/OnFjfKmVYVISr+DzUcPCv1Hwg
LAH+6yCPZlDul28CELdnJFnW2g9iVoqlQIXtGSCPUHXbEya2NfTfk3aBkCl1hqVIT9JQlQ3jWi71
pdg8HCFxI7rHSe9t57OdVQFcNIXR8LfZD/IOkmBICWhjPFtKnAv1Fsm0L3m4QAjtToLAVcb9uaZN
lVQ5ZcdyDj8InwyqXdo7iUkpQL3tcVLoENVPv3hAYIhd1cwSOE8yhawvF2uCUqad/SASFKppUXul
SJOhYVJbJrqt+UHYKP1K+87tq0NZkPishawE3hR+kD02VddUvQgjIMmTur2d6yMjANfREUIUE419
JSvNkOo0LpaDWqLO2sUPAicFiYi1CggKxBFkT8MM8gGuEHzGUyvi/ixEBGyZYLOWtc7flHKBkC90
J0mVdD1O1Tcschi00e5xLfwgltkrbyNb7CXaIMzUATINpv/1aR8ISYHXpA2qgeCcbg9KK+ZsXSFm
t6HZDrQSAhPelcqQInv2H971gcAcyNhFWS8RQeN6hfZWtXIejhDUK6q56sp3vIUttknVdoWOU/1s
2gmizzclCM4DrZc/XEIsWuz17AdB8s8y67R64Kgw0ofiW6XO7Kt3XSB74M5YNFrxWnXsEo1JNaNk
yZffAXhAcGlSSYFS4zzR6VpCkVlja6eZHwRFFsTuOsCRlmJ298lrEKP8BIEHxLQWkgWUWGpR+4Lp
6VdiDvODfNUEsexU2TjROhFvVoH9/UbXCUICbgZnRNFGkeTax6Rqs3M7/CCaEkUkM+GEaGV2qfJJ
DR+O/6zFB0JjPHC0mVe04qb4DD/kn7ZbyLhB5GUz+yNDkUu3ruSdc3tFXRR+kENUxCWBbOkkU+Aa
CLQB8ZfmB8FhyKmHuyWeFNwtKJL0y/BHNXtA8BaL2vt1Dx6kZe4SV5WHfjM/yC1VsDX4TlEvwX4k
kuWqTynN2RHSUWfstXxFXBp+mj7fagyGqUqffPGB3FMc7kka0vBZlEiRPEXXDLE0Pwj5gkdHY9b5
O5qaE/oC86Ekmh0hib5x4ThvFmyqUEKQmPhdUS9dIbfpFCFJoVcdLUvtd9eo8ktkLpC9/9YW+kWc
walGiru8B8ytJ0TJrpHkPfVvcACTto5sZ9M/ReYCwTMFHeOY4EIN9nY1Kwj+FtF+EEsfA4qswKiV
tKlXp7GrOjCC2g/y1s8JqBWZjBEXKM+h8T9bH8JaOEJQyvmSf0rSm3uQ76wiX8ITfGceLpC7X23S
XwHaIPfVjSeNrvGIP/PjA6FfqW+Ee/S+SIVtr14O/v3H23tA0Pu3jaaNbJbQsNjrTSPSey41+kHe
AWemwSfu1sRSVJ5mEvcZXrUnBN5lOUS3kclIGv+bGvJ25N8AzAVyj95hPihwzhq1IjDJF9i3OL/D
FR9IuCbq+FZksybxf6Y4VMBndugD4bFrEF5KxUhsfqK7vTpJs9EPouk77J41Knioq2hmiUHU3DqX
hx8EIh80dIfL9fMCCSKxqWFV+CPafCCpGVRkLKpEHFUUhOAQFdEtD1fIwyScp6gd6zeTpJ8UJo3c
vr/OeUGg28dtox8qazp/+4yqA7Tt6Ahhf3LqGrjOGYja/rOHjMUcix+EfNFwuvuMw/WjFk4X6r3/
QeBnuT0g//j4D/IvQ/4HjDOGabepG/IAAAAASUVORK5CYII=
```

This base64 encoded payload decodes to another image, this time a PNG of another, smaller QR code.

![Second QR code](https://github.com/noproplem/defcon_openctf_2018/blob/master/stegoxor/images/qr2.png)

The smaller QR code was scanned in a similar manner and the payload was an ANSi encoded data blob.

When rendering the ANSi blob in a terminal, another QR code appeared! This time in a much smaller format, which gave us a bit of trouble while trying to decode it.

![Micro QR](https://github.com/noproplem/defcon_openctf_2018/blob/master/stegoxor/images/microqr.png)

Turns out that this QR code was not compatible with previously used QR decoders since the format was completely different.
We looked up the different formats of QR codes and found that something called micro QR exists, and as you may guess, micro QR decoders exist as well!

The decoder that managed to correctly decode the QR code was: http://demo.leadtools.com/JavaScript/Barcode/index.html

Once decoded, a flag appeared!

```
st3go_i5_n3a7
```





