# Level 0
## Level Goal
The password for the next level is stored in a file called **readme** located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.
## Commands
``` bash
$ cat readme
```
## Password
`ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

# Level 1
## Level Goal
The password for the next level is stored in a file called **-** located in the home directory
## Commands
```bash
$ cat ./-
```
## Password
`263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

# Level 2
## Level Goal
The password for the next level is stored in a file called `--spaces in this filename--` located in the home directory
## Commands
```bash
$ cat ./--spaces\ in\ this\ filename--
```
## Password
`MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

# Level 3
## Level Goal
The password for the next level is stored in a hidden file in the **inhere** directory.
## Commands
```bash
$ cd inhere/
$ cat ...Hiding-From-You
```
## Password
`2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

# Level 4
## Level Goal
The password for the next level is stored in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.
## Commands
```bash
$ cd inhere/
$ file ./-file0*
$ cat ./-file07
```
## Password
`4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

# Level 5
## Level Goal
The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:
- human-readable
- 1033 bytes in size
- not executable
## Commands
```bash
$ cd inhere/
$ du -ab | grep 1033
$ cat ./maybehere07/.file2
```
## Password
`HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`
# Level 6
## Level Goal
The password for the next level is stored **somewhere on the server** and has all of the following properties:
- owned by user bandit7
- owned by group bandit6
- 33 bytes in size
## Commands
```bash
# Este comando vai procurar apartir da root todos os ficheiros que pertencem ao user `bandit7`, e em todas as diretorias, vai executar o comando `ls -ls`, excluindo todos os erros do output. Apartir de dito output, procura apenas as linhas que contenham o número `33`
$ find / -user bandit7 -exec ls -ls {} \; 2>/dev/null | grep 33  
4 -rw-r----- 1 bandit7 bandit6 33 Oct 14 09:26 /var/lib/dpkg/info/bandit7.password  
4 -r-------- 1 bandit7 bandit7 33 Oct 14 09:25 /etc/bandit_pass/bandit7

$ cat /var/lib/dpkg/info/bandit7.password
```
## Password
`morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

# Level 7
## Level Goal
The password for the next level is stored in the file **data.txt** next to the word **millionth**
## Commands
```bash
$ cat data.txt | grep millionth
```
## Password
`dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

# Level 8
## Level Goal
The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once
## Commands
```bash
# O comando `uniq` só deteta linhas duplicadas se as mesmas estiverem adjacentes
$ cat data.txt | sort | uniq -u
```
## Password
`4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`

# Level 9
## Level Goal
The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, preceded by several ‘=’ characters.
## Commands
```bash
$ strings data.txt | grep "^="
```
## Password
`FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`


# Level 10
## Level Goal
The password for the next level is stored in the file **data.txt**, which contains base64 encoded data
## Commands
```bash
$ base64 -d data.txt
```
## Password
`dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`

# Level 11
## Level Goal
The password for the next level is stored in the file **data.txt**, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions
## Commands
```bash
$ cat data.txt | tr 'n-za-mN-ZA-M' 'a-zA-Z'
```
### Explicação
O comando `tr` faz a **tr**adução de output x para y.
Neste caso, o tipo de encriptação POT13 está a ser utilizado, onde as letras obedecem o seguinte layout:
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
## Password
`7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`

# Level 12
## Level Goal
The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)
## Commands
Foram feitos muitos comandos, mas foi basicamente assim que foi efetuado
```bash
# Ir para um ambiente na pasta tmp (para poder criar e apagar ficheiros)
$ mkdir /tmp/ciberseguros
$ cp file.txt /tmp/ciberseguros
$ cd /tmp/ciberseguros

# Descodificar o ficheiro hex
$ xxd -r file.txt data2.bin

# Apartir de agora, é corrido o comando `file` em cada etapa para descobrir o tipo de comando que foi utilizado para compactar o ficheiro
$ file data2.bin
data2.bin: gzip compressed data, was "data2.bin", last modified: Tue Oct 14 09:26:06 2025, max compression, from Unix, original size modulo 2^32 170798638

# Neste caso o ficheiro data2.bin foi compactado com o gzip, por isso:
$ mv data2.bin.gz
$ gzip -d data2.bin.gz

# Na próxima camada, o ficheiro foi compactado com...
$ file data2.bin  
data2.bin: bzip2 compressed data, block size = 900k

# ...Bunzip2, por isso fazemos:
$ mv data2.bin data2.bin.bz
$ bzip2 -d data2.bin.bz

# E por aí fora, no total é utlizado o `gzip`, `bzip2` e `tar`
# Um exemplo do uso do tar:
$ file data2.bin  
data2.bin: POSIX tar archive (GNU)
$ mv data2.bin data2.tar
$ tar xfv data2.tar
data5.bin

# No final, é nos dada a password em plaintext :)
```
## Password
`FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`

# Level 13
## Level Goal
The password for the next level is stored in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Look at the commands that logged you into previous bandit levels, and find out how to use the key for this level.
## Commands
```bash
# Ao dar login, é possivel observar a chave privada do user `bandit14`
# Sem entrar no user remoto
$ scp -P 2220 bandit13@bandit.labs.overthewire.org:sshkey.private .
$ ls -la | grep sshkey  
-rw-r-----   1 obi-wan obi-wan   1679 Dec  5 22:27 sshkey.private

# Agora basta editar as permissões do ficheirousar a chave para dar login com o `bandit14`
$ chmod 400 sshkey.private    
$ ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```
## Password
`MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS` (obtido com o `bandit14`)

# Level 14
## Level Goal
The password for the next level can be retrieved by submitting the password of the current level to **port 30000 on localhost**.
## Commands
```bash
# Primeiro sacamos a pass do bandit14, agora que temos acesso
$ cat /etc/bandit_pass/bandit14  
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

# Agora abrimos uma ligação com a porta 30000 utilizando o `nc`, e enviamos a password do `bandit14`
$ nc bandit.labs.overthewire.org 30000  
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS  
Correct!  
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```
## Password
`8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo`

# Level 15
## Level Goal
The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL/TLS encryption.
**Helpful note:** Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage.
## Commands
```bash
$ ncat --ssl bandit.labs.overthewire.org 30001  
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo  
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```
## Password
`kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx`

# Level 16
## Level Goal
The credentials for the next level can be retrieved by submitting the password of the current level to **a port on localhost in the range 31000 to 32000**. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.
**Helpful note:** Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage.
## Commands
``` bash
# Corremos o nmap para descobrir as portas abertas do range dado, e que serviço é que estão a correr (o nmap meio que dá cheat das portas, já que nos diz que porta é que vai receber a informação)
$ nmap -sV -p 31000-32000 localhost  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-05 23:08 UTC    
Nmap scan report for localhost (127.0.0.1)  
Host is up (0.00017s latency).  
Not shown: 996 closed tcp ports (conn-refused)  
PORT      STATE SERVICE     VERSION  
31046/tcp open  echo  
31518/tcp open  ssl/echo  
31691/tcp open  echo  
31790/tcp open  ssl/unknown  
31960/tcp open  echo  
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.  
org/cgi-bin/submit.cgi?new-service :  
SF-Port31790-TCP:V=7.94SVN%T=SSL%I=7%D=12/5%Time=69336602%P=x86_64-pc-linu  
SF:x-gnu%r(GenericLines,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x2  
SF:0current\x20password\.\n")%r(GetRequest,32,"Wrong!\x20Please\x20enter\x  
SF:20the\x20correct\x20current\x20password\.\n")%r(HTTPOptions,32,"Wrong!\  
SF:x20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")%r(RTS  
SF:PRequest,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20  
SF:password\.\n")%r(Help,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x  
SF:20current\x20password\.\n")%r(FourOhFourRequest,32,"Wrong!\x20Please\x2  
SF:0enter\x20the\x20correct\x20current\x20password\.\n")%r(LPDString,32,"W  
SF:rong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\.\n")  
SF:%r(SIPOptions,32,"Wrong!\x20Please\x20enter\x20the\x20correct\x20curren  
SF:t\x20password\.\n");  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 155.44 seconds

# E basta ligar por `ncat`
$ ncat --ssl bandit.labs.overthewire.org 31790  
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx  
Correct!  
-----BEGIN RSA PRIVATE KEY-----  
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ  
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ  
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu  
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW  
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX  
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD  
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl  
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd  
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC  
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A  
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama  
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT  
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx  
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd  
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt  
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A  
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi  
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg  
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu  
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni  
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU  
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM  
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b  
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3  
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=  
-----END RSA PRIVATE KEY-----

# Como é uma chave privada, metemos isso dentro de um ficheiro `.private` e ligamos-nos ao próximo bandit
ssh -i sshkey.private bandit17@bandit.labs.overthewire.org -p 2220
```
## Password
`EReVavePLFHtFlFsjn3hyzMlvSuSAcRD`  (obtido com o `bandit17`)

# Level 17
## Level Goal
There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new**
**NOTE:** if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19
## Commands
```bash
$ diff passwords.old passwords.new
```
### Explanation
O comando `diff` compara dois ficheiros e mostra as diferenças entre eles. Vamos analisar o output:
```bash
42c42
```
Isto significa que a linha 42 foi **alterada** (c = change/changed) em ambos os ficheiros.
```bash
< pGozC8kOHLkBMOaL0ICPvLV1IjQ5F1VA
```
O símbolo `<` indica o conteúdo no **ficheiro antigo** (`passwords.old`). A password na linha 42 era `pGozC8kOHLkBMOaL0ICPvLV1IjQ5F1VA`.
```bash
---
```
Este separador visual distingue o conteúdo antigo do novo.
```bash
> x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
```
O símbolo `>` indica o conteúdo no **ficheiro novo** (`passwords.new`). A password na linha 42 agora é `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`.
## Password
`x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`

# Level 18
## Level Goal
The password for the next level is stored in a file **readme** in the homedirectory. Unfortunately, someone has modified **.bashrc** to log you out when you log in with SSH.
## Commands
```bash
$ ssh bandit18@bandit.labs.overthewire.org -p 2220 -t sh
```
## Password
`cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8`

# Level 19
## Level Goal
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.
## Commands
```bash
$ ./bandit20-do cat /etc/bandit_pass/bandit20
```
## Password
`0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO`

# Level 20
## Level Goal
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).
**NOTE:** Try connecting to your own network daemon to see if it works as you think
## Commands
```bash
# To make it a little bit harder, we'll only use one ssh session
# First we create the listener and put it on the background
$ nc -lvnp 4444 &
[1] 35
Listening on 0.0.0.0 4444

# Then we start the `suconnect` executable and put it on the background
$ ./suconnect 4444 &  
[2] 36
Connection received on 127.0.0.1 43248 # this is from `nc`

# And now, we put our listener on the background, to be able to interact with it:
$ jobs  
[1]+  Stopped                 nc -lvnp 4444  
[2]-  Running                 ./suconnect 4444 &  
$ fg 1  
nc -lvnp 4444  
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO # Input password from bandit20
Read: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO # Output from `suconnect`
Password matches, sending next password  
EeoULMCra2q0dSkYj561DX7s1CpBuOBt # Password for bandit21
```
## Password
`EeoULMCra2q0dSkYj561DX7s1CpBuOBt`

# Level 21
## Level Goal
A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.
## Commands
```bash

```
## Password


# Level 
## Level Goal

## Commands
```bash

```
## Password

# Level 
## Level Goal

## Commands
```bash

```
## Password

# Level 
## Level Goal

## Commands
```bash

```
## Password