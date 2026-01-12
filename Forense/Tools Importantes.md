# EXTERRO FTK IMAGER
Serve para sacar/analisar dumps da memória da máquina e imagens de drives.
## Tips and Tricks
Quando fizeres uma imagem do disco, usa E01,é top :)
E faz as contas para teres 10 fragmentos do disco, é mais safe

# Volatility
Serve para analisar dumps de memória
## Módulos utilizados:
-f: ficheiro memdump
--profile: utliza-se para determinar o tipo de sistema do memdump (por exemplo, Win7SP0x86)
## Plugins Utilizados:
imageinfo: Mostra informações sobre o memdump (sistema, data, etc.)
pslist: Mostra os processos que estavam a correr no sistema
pstree: Mostra os processos, parent-processes e sub-processes
netscan: Mostra todas as ligações efetuadas pelo sistema
cmdline: Mostra os processos que foram iniciados e os seus argumentos
## Exemplos de comandos:
```
volatility.exe -f memdump.mem imageinfo
volatility.exe -f memdump.mem --profile=Win7SP0x86 pslist
```

# Volatility3
Serve para analisar dumps de memória (kali, advanced)
## Módulos utilizados:
-q: quiet, sem barra de progresso
-f: ficheiro de memória
## Plugins Utilizados:
windows.netscan.Netscan: Mostra todas as ligações efetuadas pelo sistema
windows.pstree.PsTree: Mostra os processos, parent-processes e sub-processes
windows.pslist.PsList: Mostra os processos que estavam a correr no sistema
windows.dlllist.DllList: Mostra todos os DLLs que foram carregados
windows.filescan.FileScan: Mostra todos os ficheiros que foram carregados para a memória
## Exemplos de comandos:
```
vol.py -q -f memdump.mem windows.pslist.PsList
vol.py -q -f memdump.mem windows.dlllist.DllList
```

# RegistryReport
Analisa HIVES de registro do Windows
## Registry Files
O RegistryReport trabalha com os seguintes ficheiros:
```
C:\Windows\system32\config\SAM
C:\Windows\system32\config\software
C:\Windows\system32\config\system
C:\Users\<user>\NTUSER.dat (opcional)
```
Depois basta criar um report e dar save do mesmo
Convém teres alguma aplicação para leres .rtf
## Cenas Importantes
Verifica sempre nos reports:
- Software
- Devices
- Users and User Groups
- Services