#!/usr/bin/env python2
# pack_bpf.py
import sys
from struct import pack
# read in bpf from iptables rule
prog = sys.stdin.read()
s = map(int, prog.replace(',', ' ').split(' '))
for i in range(0, len(s), 4):
    sys.stdout.write(pack('<HBBI', *s[i:i+4]))