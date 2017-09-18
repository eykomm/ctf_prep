#!/usr/bin/python

import struct, socket

target_host = "192.168.1.7"

ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
a=ip2int("192.168.1.7")
a += 1
print a

int2ip = lambda n: socket.inet_ntoa(struct.pack('!I',n))
print(int2ip(a))