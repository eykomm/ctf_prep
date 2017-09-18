#!/usr/bin/python

import socket

target_host ='192.168.1.7'
target_port = 21 
for x in range (21 , 80):
	try:
		client = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
		client.connect ((target_host, target_port))
		response = client.recv(1024)
		target_port += 1	
		print "[*] Port:%d  " %target_port + response
	except:
		pass
		print "[*] Port:%d   Further Check!" %target_port
		target_port += 1