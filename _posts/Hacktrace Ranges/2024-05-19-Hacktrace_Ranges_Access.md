---
title : 'Hacktrace-Ranges: Access [Write-up]'
date : 2024-05-20 18.25 +0700           #DD-MM-YY hour timezone (+7 GMT)
categories : [Hacktrace-Ranges, Offensive]
tags : [machine,pluck,cve-2020-29607,password cracking,wget]
# author: 1                             # for single entry
---

## Getting Started

![Desktop View](/assets/img/hacktrace/access/Access_machine.png){: .center }

This is my first machine in hacktrace ranges, but I've already completed a few machines on hackthebox, so I should be able to complete this machine. Here is the machine details:

**Machine: Access**  
**Level: Easy**  
**OS: Linux**  
**IP: 10.1.2.157**



## Recon and Initial Steps

I began with an nmap scan:   
```terminal
❯ sudo nmap -sS -sV -sC 10.1.2.157
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-20 01:30 WIB
Nmap scan report for 10.1.2.157
Host is up (0.38s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000      1998572 Apr 19 03:51 sienna_eborchure.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.201.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
|_http-generator: pluck 4.7.13
| http-title: Vien'le - Vien'le
|_Requested resource was http://10.1.2.157/?file=vien-le
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.37 seconds
```
**Nmap Options**
- sS: Performs a TCP SYN scan
- sV: Enables service version detection
- sC: Enables the use of default scripts

**Key Findings**
- FTP port 21: vsftpd 3.0.3
- HTTP port 80: Apache httpd 2.4.59 ((Debian))

After doing nmap scan, i notice something interesting from FTP service. We can see here that anonymous ftp login is allowed and it's contains a pdf file

> ftp-anon: Anonymous FTP login allowed (FTP code 230)

That means i can access the ftp service using `anonymous` as username and password. But before that, i quickly check the webserver that running on port 80 `http://10.1.2.157/` and perform manual scanning

After observing the website for a while and scanning/searching some vuln, i haven't gotten the initial foothold yet. I also tried some LFI payload because i see that the website load a local file `http://10.1.2.157/?file=vien-le` but no luck :(


## Initial Foothold
I noticed the website using pluck-cms 4.7.13 and there is login.php page `http://10.1.2.157/login.php`. I quickly search on google for default creds and use it but it's incorrect, and also need to wait for few minutes after entering wrong password for 5 times.

![Desktop View](/assets/img/hacktrace/access/img1.png){: .center }

Searched for plunk 4.7.13 exploit using searchsploit but it need authentication

```terminal
❯ searchsploit pluck 4.7.13             
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Exploit Title                                                                                                                       |  Path
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)                                                                 | php/webapps/49909.py
------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Getting stuck, I stepped back and then tried to access ftp server using anonymous creds

```terminal
❯ ftp 10.1.2.157
Connected to 10.1.2.157.
220 (vsFTPd 3.0.3)
Name (10.1.2.157:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
❯ ftp> ls -lah
229 Entering Extended Passive Mode (|||47637|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        122          4096 Apr 19 03:52 .
drwxr-xr-x    2 0        122          4096 Apr 19 03:52 ..
-rw-r--r--    1 1000     1000      1998572 Apr 19 03:51 sienna_eborchure.pdf
226 Directory send OK.
❯ ftp> get sienna_eborchure.pdf
local: sienna_eborchure.pdf remote: sienna_eborchure.pdf
229 Entering Extended Passive Mode (|||45782|)
150 Opening BINARY mode data connection for sienna_eborchure.pdf (1998572 bytes).
100% |**************************************************************************************************************************|  1951 KiB  252.04 KiB/s    00:00 ETA
226 Transfer complete.
1998572 bytes received in 00:08 (240.81 KiB/s)
❯ ftp> exit
221 Goodbye.
```
I opened it and it was a normal brochure

![Desktop View](/assets/img/hacktrace/access/img2.png){: .center }

checked the metadata using exiftool

```terminal
❯ exiftool sienna_eborchure.pdf 
ExifTool Version Number         : 12.57
File Name                       : sienna_eborchure.pdf
Directory                       : .
File Size                       : 1999 kB
File Modification Date/Time     : 2024:04:19 10:51:52+07:00
File Access Date/Time           : 2024:05:21 02:46:46+07:00
File Inode Change Date/Time     : 2024:05:21 02:46:46+07:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.6
Linearized                      : No
Create Date                     : 2023:11:03 15:37:34-05:00
Modify Date                     : 2023:11:03 15:45:10-05:00
Has XFA                         : No
Language                        : en-US
XMP Toolkit                     : Image::ExifTool 12.57
Creator                         : your password is dcb76da384ae3028d6aa9b2ebcea01c9
Format                          : application/pdf
Producer                        : Adobe PDF Library 17.0
Trapped                         : False
Creator Tool                    : Adobe InDesign 19.0 (Macintosh)
Metadata Date                   : 2023:11:03 15:45:10-05:00
Derived From Document ID        : xmp.did:fb0632d3-6add-4b1a-b098-598e7a92fec5
Derived From Instance ID        : xmp.iid:eeff6700-f6c2-4d9e-978d-3266d2f18f41
Derived From Original Document ID: xmp.did:1550a558-fb22-481f-aacd-d74194ac9339
Derived From Rendition Class    : default
Document ID                     : xmp.id:acdd5a12-a4f7-48ec-9f41-b369a2ce03a0
History Action                  : converted
History Changed                 : /
History Parameters              : from application/x-indesign to application/pdf
History Software Agent          : Adobe InDesign 19.0 (Macintosh)
History When                    : 2023:11:03 15:37:34-05:00
Instance ID                     : uuid:d0e5e105-fcf6-474b-9773-f60431af9b81
Original Document ID            : xmp.did:1550a558-fb22-481f-aacd-d74194ac9339
Rendition Class                 : proof:pdf
Page Count                      : 22
```

And yes i got some progress, the metadata of `sienna_eborchure.pdf` contains a hashed password.

> dcb76da384ae3028d6aa9b2ebcea01c9

I ran hash-identifier to check the hash type,

```terminal
hash-identifier dcb76da384ae3028d6aa9b2ebcea01c9
```
the program identify MD5 for possible hashes. I saved the hashed password to pass.md5

```terminal
echo 'dcb76da384ae3028d6aa9b2ebcea01c9' > pass.md5 
```

Next step, i ran hashcat to crack the password

```terminal
hashcat -m 0 -a 0 pass.md5 /usr/share/wordlists/rockyou.txt
```
**Hashcat option**
- -m 0: To specifies the hash type (MD5)
- -a 0: To Specifies the attack mode (dictionary attack)

waiting... and then cracked!.

> dcb76da384ae3028d6aa9b2ebcea01c9:sayang

Using `sayang` as password to login at `http://10.1.2.157/login.php` resulted in succeed

![Desktop View](/assets/img/hacktrace/access/img3.png){: .center }


## Exploitation

Maecenas ullamcorper efficitur ligula, at venenatis justo gravida eget. Maecenas accumsan tincidunt nunc ac hendrerit. Morbi ipsum magna, efficitur non est eu, tristique pharetra erat. Nulla facilisi. In sodales eget risus ac lobortis. Ut eget accumsan lectus, non pharetra nunc. Quisque semper feugiat massa non laoreet. Ut a lorem ante. Duis viverra vel augue id commodo. Nullam ante turpis, lobortis ac laoreet at, blandit facilisis ante.

