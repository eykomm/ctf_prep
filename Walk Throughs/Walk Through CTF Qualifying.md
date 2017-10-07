# Write Up CTF17 Qualifying CODE UniBw 
by LBr && Nick Team `() ( ;:);`

## scoreboard (not part of the challenge)
login doesn´t work > mailed the localos to fix it


## enumerating webpage

- nikto just gives an custom header but nothing interesting
- found /images/HERE.png (png comment: Created with by Peter Hillmann (UniBwM, FZ CODE, CTF2016)?)
- found /js/ dir
- found /templates/main.html (text on start page)
- browsing ip https://137.193.69.250/ gives a html page "just as i said"
- title of the page is "cd pub && more beer" < geek joke probably 

### burp interception
- authentication is base64 encoded user:pw

### Flag 1 in HERE.png
Flag_C7B3175D8E253F3802
got hint:
Next Level URL (the password is the flag from the previous level): /551AC341714FE4F9AAD3B435B51404EE/
