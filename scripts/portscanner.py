#!/usr/bin/python

import socket

target_host = "192.168.1.7"
target_port = 21 

for x in range (0, 22):
	client = socket.socket(socket.AF_INET , socket.SOCK_STREAM)

	if client.connect_ex((target_host, target_port)):
		print "[*] Port: %d Further Info is in order" %target_port
	else:
		print "[*] Port: %d We're Live" %target_port
	target_port += 1