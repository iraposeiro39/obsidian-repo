# Overview
smbclient é um cliente para o protocolo SMB (**S**erver **M**essage **B**lock).
Com ele é possivel aceder a shares que utilizam esse mesmo protocolo.

# Comandos Básicos
## Aceder a um server
```
smbclient //<ip>/<share> -U <user>%<pass> -p <port>
```

## Listar shares num server
Nota: existe uma ferramenta que faz o mesmo, mas melhor: [[enum4linux]]
### Com user
```
smbclient --list=<ip> -U <user>%<pass>
```
### Anonymous
```
smbclient --list=<ip> --no-pass
```

## Correr comandos no server
```
smbclient //<ip>/<share> -U <user>%<pass> --command "<command>"
```

Um exemplo prático disto seria fazer download/upload dum ficheiro de uma share.
Por exemplo, digamos que queremos sacar o ficheiro "passwords.txt" da pasta "vault", com o user loki:
```
smbclient //192.168.1.1/Shares -U "loki%User_!23" --directory vault --command "get passwords.txt"
```

# SMB Syntax
A maior parte dos comandos são parecidos com linux, mas aqui estão uns quantos que são diferentes
 - `get <file>` Download Ficheiro
 - `put <file>` Upload Ficheiro
 - `rename <file> <renamed-file>` - Trocar nome de um ficheiro
 - `lcd <dir>` - Trocar para uma pasta local
 - `mget *.txt` - Download de todos os ficheiros com a extensão .txt
 - `mput *.png` - Upload de todos os ficheiros com a extensão .png
 - `del <file>` - Apagar ficheiros

# Listar ficheiros
Ao listar ficheiros, somos deparados com:
```
smb: \> ls
  .                                   D        0  Tue Apr 21 07:08:23 2020
  ..                                  D        0  Tue Apr 21 06:49:56 2020
  .cache                             DH        0  Tue Apr 21 07:08:23 2020
  .profile                            H      807  Tue Apr 21 07:08:23 2020
  .sudo_as_admin_successful           H        0  Tue Apr 21 07:08:23 2020
  .bash_logout                        H      220  Tue Apr 21 07:08:23 2020
  .viminfo                            H      947  Tue Apr 21 07:08:23 2020
  Working From Home Information.txt      N      358  Tue Apr 21 07:08:23 2020
  .ssh                               DH        0  Tue Apr 21 07:08:23 2020
  .bashrc                             H     3771  Tue Apr 21 07:08:23 2020
  .gnupg                             DH        0  Tue Apr 21 07:08:23 2020

                12316808 blocks of size 1024. 7583720 blocks available

```

As informações que vemos nos ficheiros seguem a seguinte estrutura:

| file   | atributo(s) | size (B) | last modified            |
| ------ | ----------- | -------- | ------------------------ |
| .cache | DH          | 0        | Tue Apr 21 07:08:23 2020 |
## Atributos
Um ficheiros/diretoria pode ter vários atributos, alguns deles são:
- `N` - Normal (Sem atributos especiais)
- `A` - Archive (Ficheiro modificado recentemente e foi marcado para backup)
- `D` - Diretoria
- `H` - Hidden
- `R` - Read-Only
- `S` - System FIle