#!/usr/bin/env python

from pwn import *

CLOCKBLOCK = 29893

MARK = "\x1b[2J"

proc = process(["proxychains", "nc", "kajer.openctf.com", "13"])


proc.recvuntil(MARK)

it = 0

while True:
    print "Iteration [%d]" % it
    block = proc.recvuntil(MARK)
    with open("clock-%03d.dat" % it, "wb") as f:
        f.write(block)
    it += 1
    #proc.stdout.read(CLOCKBLOCK)
