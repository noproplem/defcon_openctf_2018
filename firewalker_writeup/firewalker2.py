#!/usr/bin/env python2
from scapy.all import *
from struct import unpack

iface = 'enp0s31f6'
dst = "172.31.2.97"

'''
Add this to sender:
iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 27302 -j DROP
'''

def check1(pkt):
    '''
    tcp.dataofs != 5
    '''
    return (((ord(str(pkt)[0x20]) & 0xf0) >> 2) + 20) - 0x28 != 0

def check2(pkt):
    '''
    tcp.options[0].kind == MSS
    '''
    return (ord(str(pkt)[0x28]) == 2)

def check3(pkt):
    '''
    tcp.options[0].data == 1337
    '''
    d = str(pkt)
    A = unpack('>H', d[0x28+2:0x28+2+2])[0]
    # solve using Z3
    return ((A - 1461) & 0xffffffff) > 0xc0ffee and \
        (A % 2 == 1) and \
        (A % 3 == 2) and \
        (A % 5 < 4) and \
        (A % 11 > 2) and \
        (A % 17 > 9) and \
        (A % 23 < 5) and \
        (A % 42 > 30) and \
        (A % 61 > 50)

srcport = 9975 if len(sys.argv) == 1 else int(sys.argv[1])
i = IP(
    ihl = 5,
    dst = dst,
    )
t = TCP(
    dport = 15646,
    sport = srcport,
    flags = 'S',
    # check1
    dataofs = 7,
    )
# set a MSS option with the correct value, check2 and check3
options = Raw('\x02\x04'+'\x05\x39\x00\x00'+'\x00\x00')
p = i/t/options

assert check1(p), 'fails check1'
assert check2(p), 'fails check2'
assert check3(p), 'fails check3'

syn_ack = sr1(p, iface=iface)
syn_ack.show()

t = TCP(
    dport = 15646,
    sport = srcport,
    seq = syn_ack[TCP].ack,
    ack = syn_ack[TCP].seq + 1,
    flags = 'A',
    )
r = Raw("GET /flag-742c78b2.txt HTTP/1.1\r\nHost: {}:15646\r\n\r\n".format(dst))
p = i/t/r
replies = sr(p, iface=iface, multi=True, timeout=1)
for reply in replies[0]:
    reply[1].show()

t = TCP(
    dport = 15646,
    sport = srcport,
    seq = reply[1][TCP].ack,
    ack = reply[1][TCP].seq + 1,
    flags = 'F',
    )
p = i/t
final = sr1(p, iface=iface)
# final.show()
