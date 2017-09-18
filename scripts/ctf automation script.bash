#!/bin/bash
# simple automation script for ctf challenges
# testet on kali rolling, you´ll need a running guake terminal.

# prepare system

## todo not using if, use cases
echo "update system? [y/N]"
read UPD
if [ $UPD==y ]
 	then
		apt update
		apt upgrade
		apt dist-upgrade
		apt autoremove
		apt autoclean
	else
		echo "ok, next time then ...."
fi

#prepare metasploit
service postgresql start
msfdb init

# create new project
echo "new project name:"
read PROJ
mkdir /root/Desktop/$PROJ
cd /root/Desktop/$PROJ
guake -r $PROJ

# scan local network
echo "networkscan"
echo "ip range?"
read RANGE
echo "netmask?"
read MASK
guake -n k -r "netdiscover" -e "netdiscover -r $RANGE/$MASK"

# select a target
echo "target ip?"
read TIP

# port and service scans
guake -n k -r "nmap" -e "cd /root/Desktop/$PROJ && nmap -p- -A -T4 $TIP "
guake -n k -r "nmap_common" -e "cd /root/Desktop/$PROJ && nmap -p21,22,23,80,110,111,137,138,139,222,443,445,993,1309,1337,3128,3309,3389,4444,5901,8080 $TIP"

# check if web port 80 is open
WEB=$(nmap -p80 $TIP |grep open |cut -d " " -f 1 |cut -d "/" -f 1)
if [ $WEB -eq 80 ];
	then
		# web vuln scans if port 80 is open
		guake -n k -r "nikto" -e "cd /root/Desktop/$PROJ && nikto -h http://$TIP"
		guake -n k -r "dirb" -e "cd /root/Desktop/$PROJ && dirb http://$TIP /usr/share/wordlists/dirb/big.txt"
		guake -n k -r "curl" -e "cd /root/Desktop/$PROJ && curl -v -X PUT http://$TIP && curl -v http://$TIP/robots.txt"
	else
		echo "port 80 seems closed .... :("
fi

# check if ftp port is open
FTP=$(nmap -p21 $TIP |grep open |cut -d " " -f 1 |cut -d "/" -f 1)
if [ $WEB -eq 21 ];
  then
    # ftp auxiliary scanning and brute forcing
    # TODO
  else
    echo "port 21 seems closed .... :("

# start local webserver and msfconsole
guake -n k -r "websrv" -e "cd /root/Desktop/$PROJ && python -m SimpleHTTPServer 8000"
guake -n k -r "msfc" -e "cd /root/Desktop/$PROJ && msfconsole"

# start some basic tools
echo "start some useful t00lz? [y/N]"
read ANS
	if [ $ANS==y ];
		then
			dirbuster &
			wireshark &
			burpsuite &
			firefox http://$TIP &
			keepnote &
		else
			echo "ok, manually then :)"
	fi
