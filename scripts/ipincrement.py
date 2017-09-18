#!/usr/bin/python

import struct , socket
global target_host
target_host = "192.168.1.7"
def ip2int():
	global inte
	inte = struct.unpack('!L', socket.inet_aton(target_host))[0]
	print inte
	inte += 1
	print inte
	int2ip(inte)
def int2ip(inte):
	global ip
	ip = socket.inet_ntoa(struct.pack('!L' , inte))
	print ip

		
if __name__ == '__main__':
	for x in range (0, 3):
		ip2int()
		target_host = ip