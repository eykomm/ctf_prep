import socket
import sys
import getopt
import threading
import subprocess


PORT=12345
HOSTNAME= '127.0.0.1'

def netcat (text_to_send):
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOSTNAME, PORT))
	s.sendall(text_to_send)
	s.shutdown(socket.SHUT_WR)
	
	rec_data=[]
	while 1:
		data = s.recv(1024)
		if not data:
			break
		rec_data, append(data)
	s.close()
	return rec_data
if __name__ = '__main__':
	text_to_send=''
	text_recved=netcat(text_to_send)
	print text_recved[1]
	
def usage():
	print "Usage: netcat_awesome.py -t <HOST> -p <PORT>"
	print " -l --listen             Listen on HOST:PORT"
	print " -e --execte=file        Execute the given file"
	print " -c --command            Initialize a cmdshell"
	print " -u --upload=destination   Upload a file & write to dest"
	print
	print " Examples: "
	print " netcat_awesome.py -t localhost -p 500 -l -c"
	print " netcat_awesome.py -t localhost -p 500 -l -u=example.exe"
	print " echo 'AAA' | ./netcat_awesome.py -t localhost -p 5000"
	sys.exit(0)

LISTEN = False
COMMAND = False
UPLOAD = False
EXECUTE = ''
TARGET = ''
UP_DEST = ''
PORT = 0

def main()
	global LISTEN
	global PORT
	global EXECUTE
	global COMMAND
	global UP_DEST
	global TARGET
	
	if not len (sys.argv[1:]):
		usage
	try:
		opts, args= getopt.getopt(sys.argv[1:], "hle:t:p:cu", ["help", "LISTEN", "EXECUTE", "TARGET", "PORT", "COMMAND", "UPLOAD"])
	except getopt.GetoptError as err:
		print str(err)
		usage()
	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
		elif o in ('-l', '--listen'):
			LISTEN=True
		elif o in ('-e', '--execute'):
			EXECUTE=a
		elif o in ('-u', '--upload'):
			UP_DEST=a
		elif o in ('-t', '--target'):
			TARGET=a
		elif o in ('-p', '--port'):
			PORT=int(a)
		else:
			assert False, "Unhandled option"
#netcat client
	if no LISTEN and len(TARGET) and PORT>0:
		buffer=sys.stdin.read()
		client_sender(buffer)
#netcat server
	if LISTEN:
		if no len(TARGET):
			TARGET='0.0.0.0'
		server_loop()
if __name__=='__main__':
	main()
	
def client_sender(buffer)
	client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		client.connect((TARGET, PORT))
#test for received data
		if len(buffer):
			client.send(buffer)
		while True:
#wait data
			recv_len=1
			response=''
			while recv_len:
				data=client.recv(4096)
				recv_len=len(data)
				response += data
				if recv_len<4096
					break
			print response
#wait until no more data
			buffer = raw_input('')
			buffer += '\n'
			client.send(buffer)
	except:
		print '[*] Exception. Exiting!'
		client.close()

def server_loop():
	server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((TARGET, PORT))
	server.listen(5)
	
	while True:
		client_socket, addr = server.accept()
		client_thread = threading.Thread(target= client_handler, args=(client_socket))
		client_thread.start()
		
def client_handler(client_socket):
	global UPLOAD
	global EXECUTE
	global COMMAND
	
#check for upload
	
	if len(UP_DEST):
		file_buffer=''
#keep reading until no more
	
	while 1:
		data = client_socket.recv(1024)
		if data:
			file_buffer += data
		else:
			break
#try to write the bytes
		
	try:
		with open(UP_DEST, 'wb') as f:
			f.write(file_buffer)
			client_socket.send('File saved to %s\r\n' %UP_DEST)
	except:
		client_socket.send('Failed to save file to %s\r\n' %UP_DEST)
		
#check for cmd commmands
	if len(EXECUTE):
		output=run.command(EXECUTE)
		client_socket.send(output)
# go into a loop 

	if COMMAND:
		while True:
#show prompt
			client_socket.send('NETCAT: ')
			cmd_buffer=''
#scan for newline char 
			while '\n' not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)
#send the cmd output
			response= run_command(cmd_buffer)
			client_socket.send(response)

def run_command(command):
	command=command.restrip()
	print command
	try:
		output=subprocess.check_output (command, stderr=subprocess.STDOUT, shell=TRUE)
	except:
		output="Failed to execute command \n\r"
	return output 