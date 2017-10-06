# Write Up CTF17 Qualifying CODE UniBw 
by LBr && Nick Team `() ( ;:);`

## enumerating webpage

- nikto just gives an custom header but nothing interesting
- found /images/HERE.png (png comment: Created with by Peter Hillmann (UniBwM, FZ CODE, CTF2016)?)
- found /js/ dir
- found /templates/main.html (text on start page)
- browsing ip https://137.193.69.250/ gives a html page "just as i said"
- title of the page is "cd pub && more beer"
### burp interception
- authentication is base64 encoded user:pw
