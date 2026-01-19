# Checklist de Implementação
Desativa o IPv6 em todas as máquinas Windows
Retira DNS das pfsenses das maquinas
Agrupar as merdas do wazuh
## Durham
### PfSense One & Two (Firewalls)

- [x] Fazer as VMs
- [x] Configurar DHCP para rede 10.0.0.0/24 (mínimo 100 computadores)
- [x] Configurar redundância com failover usando CARP
- [ ] Configurar OpenVPN com autenticação RADIUS para acesso remoto
- [x] Configurar site-to-site OpenVPN para Oslo
- [x] Configurar IPSec para Brussels
- [x] Usar AES 256 bits (simétrica) e RSA 4096 bits (assimétrica)
- [x] Configurar Rotas estáticas
- [x] Configurar certificação HTTPS
- [x] Configurar IP blocklist a partir dos feeds do MISP
- [ ] Bloquear domínios .ru e .cn
- [ ] Instalar e configurar IDS/IPS (Snort ou Suricata) com todas as assinaturas gratuitas
- [ ] Deixar inicialmente em modo de monitorização

### Active Directory Domain Controller

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar domínio arrow.internal
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar utilizadores nas OUs:
    - [x] Cyber: Nuno Romão, Rodrigo Oliveira, Tiago Cardoso
    - [x] Accounting: Maria da Fé, Fábia Berbigão
    - [x] HelpDesk: Fernando Ramires, Nuno Ramos
- [x] Criar GPO para forçar DNSSEC nos endpoints
- [x] Instalar e configurar RADIUS
- [x] Criar grupo de segurança vpn.users (com users tiago.cardoso, nuno.romao e rodrigo.oliveira)

### Active Directory Failover

- [x] Fazer a VM
- [x] Instalar Windows Server (mesma versão do DC principal)
- [x] Configurar como DC secundário
- [x] Verificar replicação automática de utilizadores e serviços
- [x] Testar autenticação com DC principal offline

### Windows Server Deployment Services / File Sharing

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar WDS com Windows 10 ou 11 Professional
- [x] Testar boot PXE dos endpoints
- [x] Criar shared folders encriptadas:
    - [x] Cyber: Nuno Romão, Rodrigo Oliveira, Tiago Cardoso
    - [x] Accounting: Maria da Fé, Fábia Berbigão
    - [x] HelpDesk: Fernando Ramires, Nuno Ramos
- [x] Garantir encriptação SMB nas ligações

### Root Certification Authority (standalone)

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025 (NÃO juntar ao domínio)
- [x] Instalar Certificate Services como Root CA
- [x] Estabelecer relação de confiança com PKI server
- [x] NÃO emitir certificados directamente

### Public Key Infrastructure Server

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Instalar Certificate Services com web enrollment
- [x] Configurar emissão automática de certificados para computadores e utilizadores AD
- [x] Verificar hierarquia correcta dos certificados (PKI -> RootCA)
- [x] Emitir certificados para todas as aplicações web

### Veeam Backup Server

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Instalar Veeam Backup
- [x] Configurar backup da pasta Desktop de TODAS as Workstations
	- [x] PC01 (DH)
	- [x] PC02 (DH)
	- [x] PC03 (BR)
	- [x] PC04 (OL)

### Zabbix Monitoring Server

- [x] Fazer a VM
- [x] Instalar Rocky Linux ou RHEL
- [x] Instalar e configurar Zabbix Server
- [x] Criar todas as entradas no zabbix
- [x] Enrollar todos os servidores de Durham, Brussels e Oslo
	- [x] DC01_DH
	- [x] DC02_DH
	- [x] WDS_DH
	- [x] RootCA_DH
	- [x] PKI_DH
	- [x] VEEAM_DH
	- [x] ADCore_BR
	- [x] MISP_BR
	- [x] IMP_BR
	- [x] Velociraptor_BR
	- [x] SIEM_BR
	- [x] AD_OL
	- [x] VulnMgmt_OL
	- [x] Trellix_OL
	- [x] Wazuh_OL
	- [x] DC01_BR
- [x] Configurar monitorização de disponibilidade, performance e recursos

### Web Server IIS (DMZ - 192.168.10.0/24)

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar IIS para [www.black.pt](http://www.black.pt) e [www.arrow.com](http://www.arrow.com)
- [x] Usar apenas TLS 1.2 (obrigatório) e TLS 1.3 (opcional)
- [x] Usar apenas ciphers fortes
- [x] Activar HSTS
- [x] Obter certificados válidos do PKI server
- [x] Redireccionamento automático HTTP -> HTTPS
- [x] Bloquear todas as portas excepto 80 e 443
- [x] Ligar apenas ao WAF (rede 192.168.11.0/24)

### Web Application Firewall (DMZ)

- [x] Fazer a VM
- [x] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [x] Instalar ModSecurity com OWASP Core Rule Sets actualizados
- [x] Configurar modo de bloqueio (NÃO DetectionOnly)
- [ ] Testar detecção e bloqueio de vulnerabilidades web

### Windows 10/11 Endpoints (PC01, PC02)

- [x] Fazer as VMs
- [x] Implementar Microsoft Security Baseline via GPO
- [x] Bloquear command line, registry e control panel para não-admins
- [x] Configurar background desktop padrão
- [ ] Instalar e configurar Sysmon (enviar logs para SIEM)
- [ ] Instalar Splunk Universal Forwarder ou Elastic Agent
- [x] Instalar WAZUH agent
- [ ] Instalar Trellix Endpoint Security completo:
    - [ ] Endpoint Security
    - [ ] Threat Prevention
    - [ ] Web Control
    - [ ] Firewall
    - [ ] Adaptive Threat Protection
    - [ ] Data Loss Prevention
    - [ ] Drive Encryption
- [x] Instalar Remote Server Administration Tools
- [ ] Permitir que todos os utilizadores do grupo Cyber possam desencriptar o disco ao ligar o pc

---
## Brussels

### PfSense / OPNSense / Checkpoint

- [x] Fazer a VM
- [x] Configurar DHCP para rede 10.2.2.0/24
- [x] Configurar ligação IPSec com Durham
- [x] Configurar rotas e firewall rules
- [x] Configurar certificação HTTPS
- [x] Permitir acesso remoto VPN à rede ADM de Brussels

### Windows Server Core - Active Directory

- [x] Fazer a VM
- [x] Instalar Windows Server Core 2019/2022/2025
- [x] Configurar domínio black.internal
- [x] Configura os Forwarders
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar GPO para forçar DNSSEC nos endpoints

### MISP - Cyber Threat Intelligence Platform

- [x] Fazer a VM
- [x] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [x] Instalar MISP com feeds actualizados
- [x] Activar feeds de IPs e domínios maliciosos
- [x] Gerar blocklist para PfSense Durham
- [ ] Integrar com Incident Management Platform
- [ ] Configurar forwarding de IOCs
- [ ] Configurar feed customizado

### Incident Management Platform (TheHive)

- [x] Fazer a VM
- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar TheHive
- [ ] Instalar Cortex e integrar com TheHive
- [ ] Activar analyzers VirusTotal e outros relevantes
- [ ] Criar template de caso para tipo de ataque específico
- [ ] Configurar ingestão automática de alertas do SIEM
- [ ] Configurar ingestão de alertas IDS/IPS
- [ ] Testar enriquecimento de indicadores

### Velociraptor Server

- [x] Fazer a VM
- [x] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [x] Instalar Velociraptor Server
- [x] Instalar agente em todos os endpoints Windows
	- [x] PC01
	- [x] PC02
	- [x] PC03
	- [x] PC04
- [x] Verificar conectividade de todas as redes

### SIEM (Splunk ou Elastic)

- [x] Fazer a VM
- [ ] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [ ] Instalar Splunk ou Elastic
- [ ] Configurar integração AlienVault OTX (API key)
- [ ] Configurar integração AbuseCH (API key)
- [ ] Configurar recepção de logs Sysmon dos Windows
- [ ] Configurar recepção de logs Suricata do IDS
- [ ] Instalar agentes em todos os servidores e clientes

### iRedMail Server ou Exchange (DMZ - 192.168.20.0/24)

- [ ] Fazer a VM
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

- [ ] Fazer a VM
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

- [x] Fazer a VM
- [x] Mete no domínio black.internal
- [x] Instala as RSAT Tools

---
## Oslo

### PfSense

- [x] Fazer a VM
- [x] Configurar DHCP para rede 10.3.3.0/24
- [x] Configurar ligação site-to-site OpenVPN com Durham
- [x] Configurar rotas e firewall rules
- [x] Configurar certificação HTTPS

### Active Directory Domain Controller

- [x] Fazer a VM
- [x] Instalar Windows Server 2019/2022/2025
- [x] Configurar domínio defense.internal
- [x] Mete os forwarders
- [x] Activar DNSSEC em todos os domínios e subdomínios
- [x] Criar GPO para forçar DNSSEC nos endpoints


### Vulnerability Management (OpenVAS/Nessus + DefectDojo)

- [ ] Fazer a VM
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

- [ ] Fazer a VM
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

- [x] Fazer a VM
- [x] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [x] Instalar WAZUH server
- [x] Activar Vulnerability Management
- [x] Instalar agente em todos endpoints e servidores
	- [x] DC01_DH
	- [x] DC02_DH
	- [x] WDS_DH
	- [x] RootCA_DH
	- [x] PKI_DH
	- [x] VEEAM_DH
	- [x] ADCore_BR
	- [x] MISP_BR
	- [x] IMP_BR
	- [x] Velociraptor_BR
	- [x] SIEM_BR
	- [x] AD_OL
	- [x] VulnMgmt_OL
	- [x] Trellix_OL
	- [x] Wazuh_OL
	- [x] DC01_BR
- [x] Verificar SCA (máximo 212 falhas ou justificar por escrito)

### Apache Web Server (DMZ - 192.168.30.0/24)

- [x] Fazer a VM
- [x] Instalar Debian 12+/Ubuntu 22.04+/RHEL 9+
- [x] Instalar Apache2
- [x] Configurar [www.defense.com](http://www.defense.com) e [www.disaster.com](http://www.disaster.com)
- [x] Obter certificados digitais válidos
- [x] Configurar ciphers fortes (lista recomendada fornecida)
- [x] Usar TLS 1.2 e TLS 1.3
- [x] Desactivar SSL3, TLS1.0, TLS1.1
- [x] Activar HSTS
- [x] Configurar página de erro customizada
- [x] Activar X-Frame-Options
- [x] Activar X-XSS-Protection
- [x] Activar protecções de cookies (HttpOnly, Secure, SameSite)
- [x] Alterar ServerTokens
- [x] Desactivar Server Signatures
- [x] Instalar ModSecurity com OWASP CRS em modo de bloqueio

### PC04 (Endpoint Oslo)

- [x] Fazer a VM
- [x] Mete no domínio defense.internal
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