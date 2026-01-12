# Overview
Password bruteforce para mais de 50 protocolos como Telnet, RDP, SSH, FTP, HTTP, HTTPS e SMB.

# Exemplo
Aqui está um exemplo de um bruteforce:
```
hydra -t 4 -l labrego -P /usr/share/wordlists/rockyou.txt -vV 192.168.1.1 ftp
```
## Syntax

| ARG                     | FUNÇÃO                                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `hydra`                 | Corre o hydra                                                                                        |
| `-t <num>`              | Define o numero de ligações em paralelo, quanto mais alto, mais rápido, mas também gera mais tráfego |
| `-l <user>`             | Define o user que vai ser martelado                                                                  |
| `-P <path/to/wordlist>` | Define a wordlist (ficheiro com passwords) a usar                                                    |
| `-vV`                   | Define verbose para Very verbose, ou seja, mostra o login:pass de todas as combinações efetuadas     |
| `<Target IP>`           | IP da máquina alvo                                                                                   |
| `ftp`                   | Protocolo a usar                                                                                     |

