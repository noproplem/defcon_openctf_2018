#!/usr/bin/env python

import sys
import png

data = list(open(sys.argv[1]).read().decode("utf-8"))
blank = None
lines = []
line1 = line2 = ""
c = data.pop(0)
while data:
    if   c == "\n":
        if line1:
            lines.append(line1)
            lines.append(line2)
            line1 = line2 = ""
    elif c == u' ':
        line1 += "0"
        line2 += "0"
    elif c == u'\u2580':
        line1 += "1"
        line2 += "0"
    elif c == u'\u2584':
        line1 += "0"
        line2 += "1"
    elif c == u'\u2588':
        line1 += "1"
        line2 += "1"
    elif c == '\x1b':
        while data and data[0] in {'\x1b', "m", "0", "1", "2", "4", "3", "7", ";", "["}:
            #print repr(c)
            c = data.pop(0)
        
    else:
        print "Unknown char: %r" % c
        break
    if not data:
        break
    c = data.pop(0)

s = map(lambda x: map(lambda i: int(i), x), lines)

f = open(sys.argv[2], 'wb')
w = png.Writer(len(s[0]), len(s), greyscale=1, bitdepth=1)
w.write(f, s)
f.close()
