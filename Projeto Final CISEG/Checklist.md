# Checklist de Implementação
## Durham
### PfSense One & Two (Firewalls)

- [x] Configurar DHCP para rede 10.0.0.0/24 (mínimo 100 computadores)
- [x] Configurar redundância com failover usando CARP
- [ ] Configurar OpenVPN com autenticação RADIUS para acesso remoto
- [x] Configurar site-to-site OpenVPN para Oslo
- [x] Configurar IPSec para Brussels
- [x] Usar AES 256 bits (simétrica) e RSA 4096 bits (assimétrica)
- [x] Configurar Rotas estáticas
- [ ] Configurar IP blocklist a partir dos feeds do MISP
- [ ] Bloquear domínios .ru e .cn
- [ ] Instalar e configurar IDS/IPS (Snort ou Suricata) com todas as assinaturas gratuitas
- [ ] Deixar inicialmente em modo de monitorização

### Active Directory Domain Controller

- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar domínio arrow.internal
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar utilizadores nas OUs:
    - [x] Cyber: Nuno Romão, Rodrigo Oliveira, Tiago Cardoso
    - [x] Accounting: Maria da Fé, Fábia Berbigão
    - [x] HelpDesk: Fernando Ramires, Nuno Ramos
- [x] Criar GPO para forçar DNSSEC nos endpoints
- [ ] Instalar e configurar RADIUS
- [ ] Criar grupo de segurança vpn.users (com users tiago.cardoso, nuno.romao e rodrigo.oliveira)

### Active Directory Failover

- [x] Instalar Windows Server (mesma versão do DC principal)
- [x] Configurar como DC secundário
- [ ] Verificar replicação automática de utilizadores e serviços
- [ ] Testar autenticação com DC principal offline

### Windows Server Deployment Services / File Sharing

- [ ] Instalar Windows Server 2019/2022/2025
- [ ] Configurar WDS com Windows 10 ou 11 Professional
- [ ] Testar boot PXE dos endpoints
- [ ] Criar shared folders encriptadas:
    - [ ] Cyber: Nuno Romão, Rodrigo Oliveira, Tiago Cardoso
    - [ ] Accounting: Maria da Fé, Fábia Berbigão
    - [ ] HelpDesk: Fernando Ramires, Nuno Ramos
- [ ] Garantir encriptação SMB nas ligações

### Root Certification Authority (standalone)

- [ ] Instalar Windows Server 2019/2022/2025 (NÃO juntar ao domínio)
- [ ] Instalar Certificate Services como Root CA
- [ ] Estabelecer relação de confiança com PKI server
- [ ] NÃO emitir certificados directamente

### Public Key Infrastructure Server

- [ ] Instalar Windows Server 2019/2022/2025
- [ ] Instalar Certificate Services com web enrollment
- [ ] Configurar emissão automática de certificados para computadores e utilizadores AD
- [ ] Verificar hierarquia correcta dos certificados (PKI -> RootCA)
- [ ] Emitir certificados para todas as aplicações web

### Veeam Backup Server

- [ ] Instalar Windows Server 2019/2022/2025
- [ ] Instalar Veeam Backup
- [ ] Configurar backup de desktops das workstations dos auditores
- [ ] Configurar backup para Durham, Brussels e Oslo

### Zabbix Monitoring Server

- [ ] Instalar Rocky Linux ou RHEL
- [ ] Instalar e configurar Zabbix Server
- [ ] Enrollar todos os servidores de Durham, Brussels e Oslo
- [ ] Configurar monitorização de disponibilidade, performance e recursos

### Web Server IIS (DMZ - 192.168.10.0/24)

- [ ] Instalar Windows Server 2019/2022/2025
- [ ] Configurar IIS para [www.black.pt](http://www.black.pt) e [www.arrow.com](http://www.arrow.com)
- [ ] Usar apenas TLS 1.2 (obrigatório) e TLS 1.3 (opcional)
- [ ] Usar apenas ciphers fortes
- [ ] Activar HSTS
- [ ] Obter certificados válidos do PKI server
- [ ] Redireccionamento automático HTTP -> HTTPS
- [ ] Bloquear todas as portas excepto 80 e 443
- [ ] Ligar apenas ao WAF (rede 192.168.11.0/24)

### Web Application Firewall (DMZ)

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar ModSecurity com OWASP Core Rule Sets actualizados
- [ ] Configurar modo de bloqueio (NÃO DetectionOnly)
- [ ] Testar detecção e bloqueio de vulnerabilidades web

### Windows 10/11 Endpoints (PC01, PC02)

- [ ] Implementar Microsoft Security Baseline via GPO
- [ ] Bloquear command line, registry e control panel para não-admins
- [ ] Configurar background desktop padrão
- [ ] Instalar e configurar Sysmon (enviar logs para SIEM)
- [ ] Instalar Splunk Universal Forwarder ou Elastic Agent
- [ ] Instalar WAZUH agent
- [ ] Instalar Trellix Endpoint Security completo:
    - [ ] Endpoint Security
    - [ ] Threat Prevention
    - [ ] Web Control
    - [ ] Firewall
    - [ ] Adaptive Threat Protection
    - [ ] Data Loss Prevention
    - [ ] Drive Encryption
- [ ] Configurar DLP para bloquear impressão de documentos classificados
- [ ] Instalar Remote Server Administration Tools
- [ ] Permitir que todos os utilizadores Cyber + utilizador local desencriptem disco

---
## Brussels

### PfSense / OPNSense / Checkpoint

- [x] Configurar DHCP para rede 10.2.2.0/24
- [x] Configurar ligação IPSec com Durham
- [x] Configurar rotas e firewall rules
- [ ] Permitir acesso remoto VPN à rede ADM de Brussels

### Windows Server Core - Active Directory

- [x] Instalar Windows Server Core 2019/2022/2025
- [x] Configurar domínio black.internal
- [x] Configura os Forwarders
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar GPO para forçar DNSSEC nos endpoints

### MISP - Cyber Threat Intelligence Platform

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar MISP com feeds actualizados
- [ ] Activar feeds de IPs e domínios maliciosos
- [ ] Gerar blocklist para PfSense Durham
- [ ] Configurar feed customizado
- [ ] Integrar com Incident Management Platform
- [ ] Configurar forwarding de IOCs

### Incident Management Platform (TheHive)

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar TheHive
- [ ] Instalar Cortex e integrar com TheHive
- [ ] Activar analyzers VirusTotal e outros relevantes
- [ ] Criar template de caso para tipo de ataque específico
- [ ] Configurar ingestão automática de alertas do SIEM
- [ ] Configurar ingestão de alertas IDS/IPS
- [ ] Testar enriquecimento de indicadores

### Velociraptor Server

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar Velociraptor Server
- [ ] Instalar agente em todos os endpoints Windows
- [ ] Verificar conectividade de todas as redes

### SIEM (Splunk ou Elastic)

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar Splunk ou Elastic
- [ ] Configurar integração AlienVault OTX (API key)
- [ ] Configurar integração AbuseCH (API key)
- [ ] Configurar recepção de logs Sysmon dos Windows
- [ ] Configurar recepção de logs Suricata do IDS
- [ ] Instalar agentes em todos os servidores e clientes

### iRedMail Server ou Exchange (DMZ - 192.168.20.0/24)

- [ ] Instalar Linux ou Windows
- [ ] Instalar iRedMail ou Exchange
- [ ] Escolher e configurar domínio de e-mail
- [ ] Configurar DNS público:
    - [ ] DKIM
    - [ ] DMARC
    - [ ] SPF
    - [ ] MX records
    - [ ] A records
- [ ] Testar acesso via Outlook e Thunderbird
- [ ] Notificar equipa de auditoria do domínio escolhido

### Intrusion Detection System

- [ ] Instalar Debian (recomendado)
- [ ] Instalar Suricata ou Snort
- [ ] Activar feeds (se Suricata):
    - [ ] et/open
    - [ ] malsilo/win-malware
    - [ ] stamus/lateral
    - [ ] tgreen/hunting
    - [ ] etnetera/aggressive
    - [ ] sslbl/ja3-fingerprints
    - [ ] sslbl/ssl-fp-blacklist
    - [ ] oisf/trafficid
- [ ] Enviar logs para SIEM

### PC03 (Endpoint Brussels)

- [x] Mete no domínio black.internal
- [x] Instala as RSAT Tools

---
## Oslo

### PfSense

- [x] Configurar DHCP para rede 10.3.3.0/24
- [x] Configurar ligação site-to-site OpenVPN com Durham
- [x] Configurar rotas e firewall rules

### Active Directory Domain Controller

- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar domínio defense.internal
- [x] Mete os forwarders
- [ ] Criar o user cybersqladmin
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar GPO para forçar DNSSEC nos endpoints


### Vulnerability Management (OpenVAS/Nessus + DefectDojo)

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+/Windows
- [ ] Instalar scanner (OpenVAS ou Nessus)
- [ ] Instalar DefectDojo
- [ ] Actualizar feeds de vulnerabilidades
- [ ] Configurar scan agendado regular
- [ ] Integrar scanner com DefectDojo
- [ ] Centralizar gestão de vulnerabilidades
- [ ] Gerar relatórios (máximo 1 mês de antiguidade)
- [ ] Validar falsos positivos
- [ ] Mitigar vulnerabilidades quando possível

### Trellix ePolicyOrchestrator

- [ ] Instalar Windows Server 2022
- [ ] Instalar SQL Server Enterprise 2019
- [ ] Criar utilizador cybersqladmin
- [ ] Instalar Trellix ePO
- [ ] Sincronizar com todos os domínios (Durham, Brussels, Oslo)
- [ ] Configurar deployment de:
    - [ ] Trellix Endpoint Security
    - [ ] Firewall
    - [ ] Web Control
    - [ ] Adaptive Threat Protection
    - [ ] Threat Prevention
    - [ ] Data Loss Prevention
    - [ ] Drive Encryption
- [ ] Configurar DLP para bloquear impressão de:
    - [ ] BLACK ARROW SECRET
    - [ ] BLACK ARROW TOP SECRET
    - [ ] BLACK ARROW
    - [ ] ARROW TOP SECRET
    - [ ] ARROW SECRET
- [ ] Configurar excepções firewall para deployment

### WAZUH - Security Configuration Assessment

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar WAZUH server
- [ ] Activar Vulnerability Management
- [ ] Instalar agente em todos endpoints e servidores
- [ ] Verificar SCA (máximo 212 falhas ou justificar por escrito)

### Apache Web Server (DMZ - 192.168.30.0/24)

- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar Apache2
- [ ] Configurar [www.defense.com](http://www.defense.com) e [www.disaster.com](http://www.disaster.com)
- [ ] Obter certificados digitais válidos
- [ ] Configurar ciphers fortes (lista recomendada fornecida)
- [ ] Usar TLS 1.2 e TLS 1.3
- [ ] Desactivar SSL3, TLS1.0, TLS1.1
- [ ] Activar HSTS
- [ ] Configurar página de erro customizada
- [ ] Activar X-Frame-Options
- [ ] Activar X-XSS-Protection
- [ ] Activar protecções de cookies (HttpOnly, Secure, SameSite)
- [ ] Alterar ServerTokens
- [ ] Desactivar Server Signatures
- [ ] Instalar ModSecurity com OWASP CRS em modo de bloqueio

### PC04 (Endpoint Oslo)

- [ ] Mete no domínio defense.internal
 ---

## Exercício de Simulação de Ataque e Resposta a Incidentes

### Emulação de Ataque

- [ ] Emular 1 técnica de cada táctica MITRE ATT&CK:
    - [ ] Initial Access
    - [ ] Execution
    - [ ] Discovery
    - [ ] Command and Control
    - [ ] Exfiltration
    - [ ] Impact
- [ ] Garantir geração de telemetria
- [ ] Criar regra customizada Suricata/Snort para detectar uma técnica

### Gestão do Incidente

- [ ] Verificar que alertas são triggados (EDR, NDR, SIEM, IDS/IPS)
- [ ] Verificar ingestão de alertas no case management
- [ ] Demonstrar handling: triage, investigação, contenção, erradicação, recovery
- [ ] Apresentar playbook formal de resposta a incidentes
- [ ] Mapear para MITRE ATT&CK framework
- [ ] Classificar segundo taxonomia RNCSIRT
- [ ] Entregar relatório 7 dias antes da apresentação

---

## Laptop01 & Kali Linux (Attacker)

- [ ] Configurar VPN remota para Durham
- [ ] Testar acesso às redes ADM
- [ ] Utilizar para testes de penetração e simulações de ataque