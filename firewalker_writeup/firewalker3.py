#!/usr/bin/env python2
from scapy.all import *
from struct import unpack
import sys

iface = 'enp0s31f6'
dst = "172.31.2.97"
dst_port = 27302

'''
Add this to sender:
iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 27302 -j DROP
'''

def check1(pkt):
    '''160 < ip.ttl <= 195'''
    x = ord(pkt[0x8])
    return x <= 195 and x > 160

# IHL == 5
def check2(pkt): return ord(pkt[0]) & 15 == 5
# prot == 6 (TCP)
def check3(pkt): return ord(pkt[0x9]) == 6
# IP fragment offset == 0
def check4(pkt): 
    return unpack('>H', pkt[0x6:0x8])[0] & 8191 == 0

def check5(pkt):
    '''some TCP option with body #1321'''
    X = 4 * (ord(pkt[0]) & 0xf)
    return unpack('>H', pkt[X+0x16:X+0x16+2])[0] == 1321

def check6(pkt):
    '''tcp.flags == 0x2000'''
    X = 4 * (ord(pkt[0]) & 0xf)
    return unpack('>H', pkt[X+0xe:X+0xe+2])[0] == 8192

def check7(pkt):
    '''
    tcp
        .dataofs >> 4 == 11 (11 32-bit words header)
        .opts[0].kind == 2  (mss; check5)
        
        .opts[1].kind == 1  (no-op)
    '''
    X = 4 * (ord(pkt[0]) & 0xf)
    assert    ord(pkt[X+0xc]) >> 4 == 11
         # mss
    assert    ord(pkt[X+0x14]) == 2
    # noop (1 byte)
    assert    ord(pkt[X+0x18]) == 1
    # window scale (3 bytes)
    assert    ord(pkt[X+0x19]) == 3
    # no-ops
    assert    ord(pkt[X+0x1c]) == 1
    assert    ord(pkt[X+0x1d]) == 1
    # tcp timestamp (10 bytes)
    assert    ord(pkt[X+0x1e]) == 8
    # Selective Ack Permitted (2 bytes)
    assert    ord(pkt[X+0x28]) == 4
    # (somewhere in timestamp)
    assert    ord(pkt[X+0x20]) == 0
    return True


def check8(pkt):
    '''ip.flags & 0x40 == 1
       ip.flags & 0x80 == 0'''
    A = ord(pkt[0x6])
    return A & 64 != 0 and A & 128 == 0

def check9(pkt):
    '''
    tcp.dataofs == ip.total_length - ip.ihl
    '''
    TOTALLEN = M5 = unpack('>H', pkt[0x2:0x4])[0]
    IHL = X = 4 * (ord(pkt[0]) & 15)
    PAYLEN = M9 = TOTALLEN - IHL
    IHL = X = 4 * (ord(pkt[0]) & 15)
    A = 4*(ord(pkt[X+0xc]) >> 4)
    return A == PAYLEN

srcport = 9975 if len(sys.argv) == 1 else int(sys.argv[1])
i = IP(
    # check2
    ihl = 5,
    dst = dst,
    # check1
    ttl = 180,
    # check8
    flags = 'DF',
    # check4 implied by standard settings
    )
t = TCP(
    dport = dst_port,
    sport = srcport,
    # check6
    flags = 'S',
    # check7, and options below
    dataofs = 11,
    )
options = Raw(
    # check5 - this was changed during competition
    # mss
    '\x02\x04'+'\x05\x29' +
    
    # check7
    # nop
    '\x01' +
    # window scale
    '\x03\x03\x01' +
    # nops
    '\x01\x01' + 
    # timestamp
    '\x08\x0a' + '\x00'*8 +
    # sel ack
    '\x04\x02'
)
# check9
align = 11*4 - len(str(options)) - len(str(t))
print 'tcp opt alignment: {:#x}'.format(align)
pad = Raw('\x00'*align)
p = i/t/options/pad

sp = str(p)
assert check1(sp), 'fails check1'
assert check2(sp), 'fails check2'
assert check3(sp), 'fails check3'
assert check4(sp), 'fails check4'
assert check5(sp), 'fails check5'
assert check6(sp), 'fails check6'
assert check7(sp), 'fails check7'
assert check8(sp), 'fails check8'
assert check9(sp), 'fails check9'

syn_ack = sr1(p, iface=iface)
syn_ack.show()

t = TCP(
    dport = dst_port,
    sport = srcport,
    seq = syn_ack[TCP].ack,
    ack = syn_ack[TCP].seq + 1,
    flags = 'A',
    )
r = Raw("GET /flag-192ce834.txt HTTP/1.1\r\nHost: {}:{}\r\n\r\n".format(dst, dst_port))
p = i/t/r
replies = sr(p, iface=iface, multi=True, timeout=1)
for reply in replies[0]:
    reply[1].show()

t = TCP(
    dport = dst_port,
    sport = srcport,
    seq = reply[1][TCP].ack,
    ack = reply[1][TCP].seq + 1,
    flags = 'F',
    )
p = i/t
fin = sr1(p, iface=iface)
# fin.show()
