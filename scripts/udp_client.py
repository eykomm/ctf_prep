import socket
target_host=""
target_port=
#socket
client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#data
client.sendto("AAABBBCCC",(target_host,target_port))
#receive
data, addr=client.recvfrom(4096)
print data