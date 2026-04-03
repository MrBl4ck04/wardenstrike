# WardenStrike — Manual de Uso Completo
**AI-Powered Pentesting Framework | Warden Security**

---

## Índice

1. [Requisitos del sistema](#1-requisitos-del-sistema)
2. [Instalación](#2-instalación)
3. [Configuración inicial](#3-configuración-inicial)
4. [Conceptos clave](#4-conceptos-clave)
5. [Referencia de comandos completa](#5-referencia-de-comandos-completa)
6. [Flujos de trabajo por tipo de auditoría](#6-flujos-de-trabajo-por-tipo-de-auditoría)
7. [Integraciones](#7-integraciones)
8. [Módulo de IA](#8-módulo-de-ia)
9. [Claude Code Skills](#9-claude-code-skills)
10. [Knowledge Base](#10-knowledge-base)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Requisitos del sistema

### Sistema operativo
- Linux (recomendado: Kali Linux, Parrot OS, Ubuntu 22.04+)
- macOS 12+
- Windows 11 con WSL2

### Python
```bash
python3 --version  # Requiere 3.10+
```

### Go (para herramientas de recon)
```bash
go version  # Requiere 1.21+
# Instalar: https://golang.org/dl/
```

### Claude Code CLI (para skills)
```bash
# Instalar Claude Code:
npm install -g @anthropic-ai/claude-code
# o desde: https://claude.ai/code
```

---

## 2. Instalación

### Opción A — Instalación automática (recomendada)

```bash
# 1. Clonar el repositorio
git clone https://github.com/MrBl4ck04/wardenstrike.git
cd wardenstrike

# 2. Ejecutar instalador
chmod +x install.sh
./install.sh

# 3. Instalar herramientas de seguridad
chmod +x install_tools.sh
./install_tools.sh
```

### Opción B — Instalación manual

```bash
git clone https://github.com/MrBl4ck04/wardenstrike.git
cd wardenstrike

# Crear entorno virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias Python
pip install -e .
# o
pip install -r requirements.txt

# Copiar config de entorno
cp .env.example .env
```

### Verificar instalación

```bash
wardenstrike --version
wardenstrike status
```

---

## 3. Configuración inicial

### 3.1 Variables de entorno (.env)

Editar el archivo `.env` con tus claves:

```bash
nano .env
```

```env
# OBLIGATORIO para funciones de IA
ANTHROPIC_API_KEY=sk-ant-api03-...

# Burp Suite (si usas Burp Professional)
WARDENSTRIKE_BURP_URL=http://127.0.0.1:1337
WARDENSTRIKE_BURP_KEY=tu_api_key_de_burp

# OWASP ZAP
WARDENSTRIKE_ZAP_URL=http://127.0.0.1:8081
WARDENSTRIKE_ZAP_KEY=tu_api_key_zap

# APIs de Recon (opcionales pero recomendadas)
SHODAN_API_KEY=tu_clave_shodan
GITHUB_TOKEN=ghp_...
CHAOS_KEY=tu_clave_chaos_project_discovery
SECURITYTRAILS_KEY=...
```

### 3.2 Configuración avanzada (config/default.yaml)

```bash
nano config/default.yaml
```

Parámetros importantes:

```yaml
# Proxy a Burp Suite (para interceptar tráfico)
general:
  proxy: "http://127.0.0.1:8080"

# Modelo de IA
ai:
  model: "claude-sonnet-4-20250514"        # Análisis rápido
  report_model: "claude-opus-4-20250514"   # Reportes detallados

# Burp Suite
burpsuite:
  enabled: true
  api_url: "http://127.0.0.1:1337"
  api_key: "tu_api_key"
```

### 3.3 Configurar Burp Suite (Burp Professional)

1. Abrir Burp Suite → **User options** → **Misc**
2. Activar **REST API** en el puerto 1337
3. Generar API key y copiarla en `.env`
4. Verificar conexión:

```bash
wardenstrike burp status
# → Burp Suite is connected! Version: 2024.x.x
```

### 3.4 Configurar OWASP ZAP

```bash
# Iniciar ZAP en modo daemon con API
zaproxy -daemon -port 8081 -config api.key=zap_api_key_aqui
```

```bash
wardenstrike zap status
# → ZAP connected! Version: 2.14.x
```

### 3.5 Configurar Nessus

```yaml
# En config/default.yaml:
nessus:
  url: "https://localhost:8834"
  access_key: "tu_access_key"
  secret_key: "tu_secret_key"
```

### 3.6 Configurar Metasploit

```bash
# Iniciar MSFRPC
msfrpcd -P tu_password -S -a 127.0.0.1 -p 55553
```

```yaml
# En config/default.yaml:
metasploit:
  host: "127.0.0.1"
  port: 55553
  password: "tu_password"
  ssl: true
```

---

## 4. Conceptos clave

### Engagements (Compromisos)
Todo trabajo en WardenStrike ocurre dentro de un **engagement**. Esto permite:
- Separar targets y findings entre proyectos
- Generar reportes por cliente
- Mantener historial de auditorías

```bash
# Crear engagement
wardenstrike engage new "Cliente ABC - Web App" --platform hackerone --scope target.com

# Ver todos los engagements
wardenstrike engage list

# Cargar engagement existente
wardenstrike engage load 1

# Ver dashboard del engagement activo
wardenstrike engage dashboard
```

### Findings (Hallazgos)
Los findings se guardan en SQLite y tienen:
- **Severidad**: critical / high / medium / low / info
- **Tipo**: xss, sqli, ssrf, idor, etc.
- **Estado**: new / validated / reported / duplicate / invalid
- **Fuente**: la herramienta que lo encontró

```bash
wardenstrike findings                          # Todos los findings
wardenstrike findings --severity high          # Solo high
wardenstrike findings --type sqli              # Por tipo
wardenstrike findings --status new             # Por estado
```

---

## 5. Referencia de comandos completa

### 5.1 Gestión de engagements

```bash
wardenstrike engage new "Nombre"              # Crear engagement
  --platform hackerone|bugcrowd|intigriti|immunefi|private
  --scope target.com                          # Scope (repetir para múltiples)
  --url https://hackerone.com/programa        # URL del programa

wardenstrike engage list                      # Listar todos
wardenstrike engage load <ID>                 # Cargar por ID
wardenstrike engage dashboard                 # Dashboard del activo
```

### 5.2 Reconocimiento

```bash
wardenstrike recon <target>                   # Recon completo
  --quick                                     # Modo rápido (menos herramientas)

# Incluye:
# - Subdomain enumeration (subfinder, amass, crt.sh)
# - DNS resolution y live host detection (httpx)
# - Port scanning (nmap)
# - Web crawling (katana, gospider)
# - Directory fuzzing (ffuf)
# - Technology detection (wappalyzer)
# - JS analysis (linkfinder, secretfinder)
# - Parameter extraction
```

### 5.3 OSINT

```bash
wardenstrike osint <target>                   # OSINT básico
  --deep                                      # OSINT profundo (GitHub, breaches, Shodan)

# Básico incluye:
# - Certificate Transparency (crt.sh)
# - WHOIS + registrar info
# - ASN y rangos IP
# - Enumeración de emails (theHarvester)
# - Google dorks generados
# - Shodan dorks generados

# Con --deep agrega:
# - GitHub dorking (secretos filtrados)
# - Breach check (HIBP)
# - Shodan host lookup
# - Extracción de metadatos (metagoofil)
```

### 5.4 Vulnerabilidad Scanning

```bash
wardenstrike scan                             # Scan del engagement activo
  --targets https://target.com               # Targets específicos
  --type xss sqli ssrf                        # Tipos de vuln a testear

# Tipos disponibles: xss, sqli, ssrf, idor, rce, lfi, open_redirect,
# ssti, xxe, cors, csrf, jwt, oauth, graphql, nosql_injection,
# command_injection, path_traversal, subdomain_takeover
```

### 5.5 Cloud Security

```bash
# AWS
wardenstrike cloud aws                        # Scan con perfil default
  --profile <profile>                         # Perfil AWS CLI
  --region us-east-1                          # Región

# GCP
wardenstrike cloud gcp
  --project mi-proyecto-123                   # Project ID

# Azure
wardenstrike cloud azure
  --subscription <subscription-id>

# Multi-cloud (AWS + GCP + Azure en paralelo)
wardenstrike cloud all
  --aws-profile default
  --aws-region us-east-1
  --gcp-project mi-proyecto
  --azure-sub mi-suscripcion

# Qué analiza AWS:
# S3: ACLs públicas, policies públicas, encriptación, logging, website hosting
# IAM: MFA ausente, claves viejas, wildcard permissions, password policy
# EC2: SGs con puertos críticos expuestos, snapshots públicos, IMDSv2
# Lambda: secrets en env vars, resource policy pública, runtimes deprecados
# CloudTrail: logging desactivado, sin validación de logs
# RDS: instancias públicas, sin encriptación
# Secrets Manager: rotación desactivada
```

### 5.6 Active Directory / Interno

```bash
wardenstrike ad scan <domain>                 # Scan AD básico (anónimo)
  --dc 192.168.1.10                           # IP del Domain Controller
  --username john                             # Credenciales (opcional)
  --password Password123                      # para acceso autenticado
  --network 192.168.1.0/24                    # Para escaneo de red

# Con credenciales, ejecuta:
# - LDAP enum (usuarios, grupos, equipos, políticas)
# - Kerberoasting (GetUserSPNs.py)
# - ASREPRoasting (GetNPUsers.py)
# - Password policy (spray window)
# - SMB signing check (relay attacks)
# - CVE checks: Zerologon, PetitPotam, NoPac, PrintNightmare
# - BloodHound collection
# - LLMNR/NBT-NS check
# - IPv6 DNS takeover check (mitm6)
```

### 5.7 GraphQL

```bash
wardenstrike graphql <url>
  --header "Authorization: Bearer TOKEN"      # Headers extra
  --no-discover                               # No auto-descubrir endpoints

# Detecta y testea:
# - Introspección habilitada (schema disclosure)
# - Query batching (rate-limit bypass)
# - Depth bomb DoS
# - Field suggestions (schema leak sin introspección)
# - Acceso no autenticado a tipos sensibles
# - Inyección en argumentos
# - Mutations via GET (CSRF)
```

### 5.8 JWT Attacks

```bash
wardenstrike jwt <token>
  --endpoint https://api.target.com/me        # Endpoint para probar live
  --public-key rsa_pub.pem                    # Para ataque RS256→HS256

# Ejecuta:
# - alg:none bypass
# - RS256→HS256 algorithm confusion
# - Brute-force de secreto (150+ comunes + wordlist)
# - kid header injection (SQLi, path traversal)
# - jku/x5u SSRF token
# - Análisis de expiración y claims sensibles
```

### 5.9 OAuth / SAML

```bash
wardenstrike oauth <target>
  --client-id CLIENT_ID
  --redirect-uri https://app.com/callback
  --auth-endpoint https://auth.target.com/oauth/authorize

# Testea:
# - redirect_uri bypass (12+ variantes)
# - CSRF via state param ausente
# - Implicit flow deprecado
# - PKCE bypass
# - Scope escalation (admin, offline_access, etc.)
# - Tokens expuestos en URLs
```

### 5.10 Web3 / Smart Contracts

```bash
wardenstrike web3 audit Contract.sol
  --name "MiProtocolo"                        # Nombre del contrato
  --no-tools                                  # Saltar Slither/Mythril

# Analiza:
# 10 clases de bugs DeFi: reentrancy, access control, integer issues,
# oracle manipulation, flash loan, signature replay, proxy/upgrade,
# ERC4626 inflation, accounting desync, incomplete paths
# + Integración con Slither y Mythril
# + Templates de PoC en Foundry
```

### 5.11 Análisis de JavaScript

```bash
wardenstrike js-analyze <url_o_archivo>
  --no-ai                                     # Sin análisis de IA

# Detecta:
# - API keys, tokens, secrets hardcodeados
# - Endpoints ocultos y rutas de admin
# - Patrones de autenticación bypasseables
# - WebSocket endpoints
# - GraphQL queries y mutations
# - Source maps expuestos
```

### 5.12 Validación y Análisis con IA

```bash
wardenstrike analyze                          # Analiza findings con IA
wardenstrike validate                         # Validación 7-Question Gate
wardenstrike chains                           # Identifica exploit chains

# AI commands
wardenstrike ai chain                         # Construir exploit chains
wardenstrike ai cloud-analyze --provider AWS  # Análisis de cloud con IA
```

### 5.13 Reportes

```bash
# Reporte de finding específico
wardenstrike report finding <ID>
  --format markdown html pdf                  # Formatos de salida
  --platform hackerone|bugcrowd|intigriti     # Formato de plataforma
  --ai                                        # Generar con IA

# Executive summary del engagement
wardenstrike report summary
```

### 5.14 Monitoreo continuo

```bash
wardenstrike monitor run target.com target2.com
  --scope-file targets.txt                    # Archivo con targets

wardenstrike monitor alerts                   # Ver alertas
  --target target.com                         # Filtrar por target
  --severity high                             # Solo alta severidad
  --limit 50                                  # Últimas N alertas
```

### 5.15 Code Review con IA

```bash
wardenstrike code-review app.py
  --language python                           # Lenguaje (auto-detección por defecto)

# Detecta: SQLi, CMDi, XSS, SSRF, deserialización insegura,
# secrets hardcodeados, dependencias vulnerables, criptografía débil
```

### 5.16 Integraciones de escáneres

```bash
# Burp Suite
wardenstrike burp status                      # Verificar conexión
wardenstrike burp import                      # Importar findings de Burp
wardenstrike burp scan https://target.com     # Lanzar scan en Burp
wardenstrike burp scope <url> --add           # Agregar al scope
wardenstrike burp scope <url> --remove        # Remover del scope

# OWASP ZAP
wardenstrike zap status
wardenstrike zap import
wardenstrike zap scan https://target.com      # Spider + active scan

# Nessus
wardenstrike nessus status
wardenstrike nessus scan target.com --name "Scan Q1" --wait
wardenstrike nessus import <scan_id>          # Importar resultados

# Metasploit
wardenstrike msf status
wardenstrike msf correlate                    # Correlacionar findings con exploits MSF
```

### 5.17 Pipeline completo (Hunt)

```bash
wardenstrike hunt target.com                  # Pipeline completo
  --quick                                     # Modo rápido
  --recon-only                                # Solo recon
  --no-ai                                     # Sin análisis IA

# Ejecuta en orden:
# Fase 1: Recon (subdomain, ports, web, JS, params)
# Fase 2: Vulnerability Scanning (nuclei + módulos propios)
# Fase 3: AI Analysis (valida y prioriza)
# Fase 4: Exploit Chain Discovery
# Fase 5: Validation (7-Question Gate)
```

---

## 6. Flujos de trabajo por tipo de auditoría

### 6.1 Bug Bounty (Web)

```bash
# 1. Crear engagement para el programa
wardenstrike engage new "HackerOne - TargetCorp" \
  --platform hackerone \
  --scope target.com \
  --scope api.target.com \
  --url https://hackerone.com/targetcorp

# 2. OSINT inicial
wardenstrike osint target.com --deep

# 3. Recon completo
wardenstrike recon target.com

# 4. Análisis JS de todos los archivos encontrados
wardenstrike js-analyze target.com

# 5. Scan de vulnerabilidades
wardenstrike scan

# 6. GraphQL si hay API
wardenstrike graphql https://api.target.com/graphql

# 7. OAuth si hay SSO
wardenstrike oauth https://target.com \
  --client-id CLIENT_ID \
  --redirect-uri https://target.com/callback

# 8. JWT si hay tokens JWT
wardenstrike jwt <token_capturado>

# 9. Validar y construir chains
wardenstrike validate
wardenstrike ai chain

# 10. Generar reporte para plataforma
wardenstrike report finding <ID> --platform hackerone --ai
```

### 6.2 Auditoría Web Externa (Empresa)

```bash
# 1. Crear engagement
wardenstrike engage new "ClienteXYZ - Pentest Externo Q1 2025" \
  --platform private \
  --scope app.clientexyz.com

# 2. OSINT + Recon completo
wardenstrike osint clientexyz.com --deep
wardenstrike recon clientexyz.com

# 3. Scan exhaustivo
wardenstrike scan --type xss sqli ssrf idor ssti xxe rce lfi

# 4. GraphQL + JWT + OAuth
wardenstrike graphql https://api.clientexyz.com
wardenstrike jwt <token>
wardenstrike oauth https://clientexyz.com

# 5. Burp Suite para pruebas manuales
wardenstrike burp scope https://app.clientexyz.com --add
wardenstrike burp scan https://app.clientexyz.com
wardenstrike burp import                    # Importar lo encontrado por Burp

# 6. Code review si entregan código fuente
wardenstrike code-review app/controllers/ -l python

# 7. AI: validar, chains, priorizar
wardenstrike validate
wardenstrike ai chain
wardenstrike findings --severity critical

# 8. Reporte ejecutivo
wardenstrike report summary
wardenstrike report finding <ID> --format markdown html pdf --ai
```

### 6.3 Auditoría Cloud

```bash
# 1. Crear engagement
wardenstrike engage new "ClienteXYZ - AWS Cloud Audit"

# 2. Multi-cloud scan (o por proveedor)
wardenstrike cloud all \
  --aws-profile clientexyz-prod \
  --aws-region us-east-1

# O específico:
wardenstrike cloud aws --profile production --region us-east-1
wardenstrike cloud gcp --project clientexyz-prod
wardenstrike cloud azure --subscription xxxxxxxx-xxxx

# 3. Análisis IA de cloud
wardenstrike ai cloud-analyze --provider AWS

# 4. Correlacionar con Metasploit
wardenstrike msf correlate

# 5. Ver findings críticos
wardenstrike findings --severity critical

# 6. Reporte
wardenstrike report summary
```

**Qué buscar en cloud:**
- S3 buckets públicos con datos sensibles
- IAM roles con `*` en actions o resources
- EC2 sin IMDSv2 → vulnerable a SSRF + metadata creds theft
- Lambda con secrets en env vars
- Security Groups con SSH/RDP/BD expuesto a 0.0.0.0/0
- CloudTrail desactivado (sin auditoría)

### 6.4 Auditoría Interna / Active Directory

```bash
# 1. Crear engagement
wardenstrike engage new "ClienteXYZ - Internal Pentest" \
  --scope corp.local

# 2. Desde dentro de la red sin credenciales
wardenstrike ad scan corp.local --dc 192.168.1.10

# Busca automáticamente:
# - Anonymous LDAP bind
# - Null SMB sessions
# - Password policy (ventana de spray)
# - SMB signing (relay attacks)
# - LLMNR/NBT-NS (Responder)

# 3. Con credenciales bajas (post-phishing o spray exitoso)
wardenstrike ad scan corp.local \
  --dc 192.168.1.10 \
  --username john.doe \
  --password Password2024 \
  --network 192.168.1.0/24

# 4. Analiza paths con IA
wardenstrike ai cloud-analyze  # reutilizar el AI para análisis

# 5. Ver attack paths
wardenstrike findings --type internal_ad_kerberos
wardenstrike findings --severity critical

# 6. Reporte
wardenstrike report summary
```

**Secuencia típica AD:**
```
1. Password spray (sin lockout) → credenciales básicas
2. GetUserSPNs → Kerberoasting → crack offline
3. Credenciales de servicio → acceso a sistemas
4. BloodHound → path visual a DA
5. Exploit chain: creds → ACL abuse / delegation → DA
```

### 6.5 Bug Bounty Web3

```bash
# 1. Verificar kill signals antes de invertir tiempo
# - TVL > $500K en DeFiLlama?
# - Código verificado en Etherscan?
# - Programa activo en Immunefi?

# 2. Crear engagement
wardenstrike engage new "Immunefi - ProtocolXYZ" \
  --platform immunefi

# 3. Auditar contrato
wardenstrike web3 audit ./contracts/Protocol.sol \
  --name ProtocolXYZ

# 4. Revisar output del checklist DeFi
# 5. Desarrollar PoC en Foundry con template generado
# 6. Calcular impacto (TVL × % drenado)

# 7. Reporte para Immunefi
wardenstrike report finding <ID> --platform immunefi --ai
```

### 6.6 Monitoreo continuo de programas Bug Bounty

```bash
# Configurar targets a monitorear
cat > targets.txt << EOF
target.com
api.target.com
https://app.target.com
EOF

# Primer run (establece baseline)
wardenstrike monitor run --scope-file targets.txt

# Configurar cron (cada 4 horas)
echo "0 */4 * * * cd /opt/wardenstrike && wardenstrike monitor run --scope-file targets.txt" | crontab -

# Ver alertas del día
wardenstrike monitor alerts --severity high

# Ver toda la historia de un target
wardenstrike monitor alerts --target target.com --limit 100
```

---

## 7. Integraciones

### 7.1 Burp Suite Professional

**Setup completo:**
```
1. Burp Suite → User options → Misc → REST API Service
   - Activar: ✓
   - Port: 1337
   - Generate API key → copiar
2. Editar .env:
   WARDENSTRIKE_BURP_URL=http://127.0.0.1:1337
   WARDENSTRIKE_BURP_KEY=<tu_key>
3. En config/default.yaml:
   burpsuite:
     enabled: true
     auto_import: true
   general:
     proxy: "http://127.0.0.1:8080"
```

**Flujo de trabajo:**
```bash
# Agregar targets al scope de Burp
wardenstrike burp scope https://target.com --add

# Lanzar scan activo desde WardenStrike
wardenstrike burp scan https://target.com https://api.target.com

# Importar todo lo que Burp encontró
wardenstrike burp import

# Ver findings importados
wardenstrike findings --tool_source burp
```

### 7.2 Metasploit Framework

```bash
# Iniciar MSFRPC
msfrpcd -P password123 -S -a 127.0.0.1

# En .env o config:
# metasploit.password = "password123"

# Verificar
wardenstrike msf status

# Correlacionar findings con exploits disponibles
wardenstrike msf correlate
# → "2 findings have Metasploit modules!"
# → CVE-2021-44228 (Log4Shell) → 3 modules available
```

### 7.3 Nessus / Tenable

```bash
# En config/default.yaml:
# nessus.url = "https://localhost:8834"
# nessus.access_key = "xxx"
# nessus.secret_key = "xxx"

# Verificar
wardenstrike nessus status

# Crear y lanzar scan
wardenstrike nessus scan 192.168.1.0/24 --name "Internal Q1" --wait

# Importar resultado al engagement
wardenstrike nessus import 42
# → Imported 87 findings from Nessus scan 42
```

---

## 8. Módulo de IA

La IA (Claude) se usa en múltiples etapas. Requiere `ANTHROPIC_API_KEY` en `.env`.

### Modelos usados

| Tarea | Modelo | Por qué |
|---|---|---|
| Análisis de findings | claude-sonnet-4 | Rápido, preciso |
| Generación de reportes | claude-opus-4 | Mayor calidad de escritura |
| Code review | claude-sonnet-4 | Balance costo/calidad |

### Capacidades de IA

```bash
# 1. Validar si un finding es real (7-Question Gate)
wardenstrike validate

# 2. Construir exploit chains
wardenstrike ai chain
# → "XSS-to-ATO chain: steal session via XSS on /profile → use cookie → admin panel → IDOR → data dump"

# 3. Analizar recon data y priorizar
wardenstrike analyze
# → "Priority targets: api.target.com (Node.js + GraphQL), auth.target.com (OAuth)"

# 4. Análisis cloud con paths de escalada
wardenstrike ai cloud-analyze --provider AWS
# → "Critical chain: Public S3 → env file → DB_PASS → RDS admin → full data dump"

# 5. Code review automático
wardenstrike code-review app.py
# → Line 47: SQL Injection in user_id parameter (CWE-89)

# 6. Generar reporte profesional
wardenstrike report finding 5 --ai --platform hackerone
# → Genera reporte completo con CVSS, PoC, impacto, remediación
```

### Prompts especializados internos

| Prompt | Uso |
|---|---|
| `vuln_analyzer` | Validar y caracterizar una vulnerabilidad |
| `exploit_chain` | Conectar hallazgos en cadenas |
| `report_writer` | Reportes para bug bounty platforms |
| `js_analyzer` | Análisis de JavaScript |
| `recon_analyzer` | Priorizar attack surface |
| `triage` | 7-Question Gate |
| `cloud_auditor` | Blast radius y escalada cloud |
| `ad_analyst` | Paths a Domain Admin |
| `api_auditor` | IDOR, mass assignment, business logic |
| `web3_auditor` | Smart contract bugs |
| `osint_analyst` | Inteligencia accionable |
| `pentest_report_writer` | Reportes enterprise |
| `exploit_chain_builder` | Kill chains MITRE ATT&CK |
| `code_reviewer` | Security code review |

---

## 9. Claude Code Skills

Los slash commands se instalan en `~/.claude/commands/` y se usan dentro de la CLI de Claude Code.

### Instalación de skills
```bash
# El install.sh los copia automáticamente
./install.sh

# O manual:
cp claude/commands/* ~/.claude/commands/
```

### Uso dentro de Claude Code
```bash
# Iniciar Claude Code en el directorio del engagement
cd /ruta/a/mi/engagement
claude

# Luego dentro de la sesión:
/hunt target.com
/recon target.com
/cloud-audit aws
/ad-audit corp.local
/api-audit https://api.target.com
/osint target.com --deep
/web3-audit Contract.sol
/pentest-report web
/monitor run
/scope asset.target.com
/triage
/validate
/report
/chain
```

### Skills disponibles

| Skill | Descripción |
|---|---|
| `/hunt` | Pipeline completo de bug bounty |
| `/recon` | Recon + subdomain enum + nuclei |
| `/cloud-audit` | Auditoría AWS/GCP/Azure |
| `/ad-audit` | Auditoría Active Directory |
| `/api-audit` | REST + GraphQL security audit |
| `/osint` | OSINT collection e inteligencia |
| `/web3-audit` | Smart contract audit |
| `/pentest-report` | Generar reporte enterprise |
| `/monitor` | Monitoreo continuo |
| `/scope` | Verificar si target está en scope |
| `/triage` | 7-Question Gate rápido |
| `/validate` | Validación completa |
| `/report` | Escribir reporte bug bounty |
| `/chain` | Construir exploit chain |
| `/web2-vuln-classes` | Referencia de 20 clases de vulns |
| `/security-arsenal` | Payloads, bypass tables, wordlists |

---

## 10. Knowledge Base

Ubicada en `wardenstrike/knowledge/`:

### Payloads

```
knowledge/payloads/
├── xss.txt          # XSS (reflected, stored, DOM, bypass WAF)
├── sqli.txt         # SQLi (error, blind, time-based, OOB)
├── ssrf.txt         # SSRF (cloud metadata, internal, bypass)
├── xxe.txt          # XXE (file read, SSRF, blind, OOB)
├── ssti.txt         # SSTI (Jinja2, Twig, FreeMarker, Velocity, ERB)
├── cmd_injection.txt# CMDi (Linux, Windows, bypass de filtros)
├── lfi.txt          # LFI/Path Traversal (Linux, Windows, PHP wrappers)
├── nosqli.txt       # NoSQLi (MongoDB, Redis, CouchDB)
└── open_redirect.txt# Open Redirect (bypass de whitelist)
```

### Dorks

```
knowledge/dorks/
├── google_dorks.txt  # 60+ dorks de Google con {target}
├── github_dorks.txt  # 40+ dorks de GitHub con {target}
└── shodan_dorks.txt  # 30+ dorks de Shodan con {target}
```

### Bypass

```
knowledge/bypass/
└── waf_bypass.txt    # WAF bypass techniques
```

### Uso de payloads desde CLI

Los payloads se cargan automáticamente por los módulos relevantes. También puedes referenciarlos:

```bash
# Ver payloads XXE
cat wardenstrike/knowledge/payloads/xxe.txt

# Google dorks para un target (los genera wardenstrike osint)
wardenstrike osint target.com
# → Los dorks aparecen en el output listos para usar

# O directo:
grep -v "^#" wardenstrike/knowledge/dorks/google_dorks.txt | \
  sed 's/{target}/target.com/g'
```

---

## 11. Troubleshooting

### WardenStrike no encuentra las herramientas

```bash
# Ver qué herramientas están instaladas
wardenstrike status

# Instalar herramientas faltantes
./install_tools.sh

# Instalar manualmente una herramienta
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Error de API key de Anthropic

```bash
# Verificar que está configurada
echo $ANTHROPIC_API_KEY

# Si usas .env, cargarla:
source .env
export $(cat .env | grep -v "^#" | xargs)

# Test directo
wardenstrike analyze  # Debería usar la IA
```

### No conecta con Burp Suite

```bash
# Verificar que Burp tiene la REST API activa
# User options → Misc → REST API Service → Running?

# Probar conexión directamente
curl http://127.0.0.1:1337/v0.1/burp/versions \
  -H "Authorization: Bearer TU_API_KEY"

# En WardenStrike
wardenstrike burp status
```

### No conecta con Metasploit

```bash
# Iniciar MSFRPC correctamente
msfrpcd -P password -S -a 127.0.0.1 -p 55553

# O desde msfconsole:
load msgrpc Pass=password ServerHost=127.0.0.1 SSL=true

# Instalar pymetasploit3
pip install pymetasploit3

wardenstrike msf status
```

### Error en cloud scan AWS

```bash
# Verificar credenciales
aws sts get-caller-identity --profile default

# Si hay error de permisos, el scan continuará con lo que pueda
# Los findings indicarán qué servicios fueron accesibles

# Para scan completo necesitas:
# - SecurityAudit policy (AWS managed)
# - O ReadOnlyAccess
```

### Base de datos corrupta

```bash
# La DB está en data/wardenstrike.db
# Hacer backup:
cp data/wardenstrike.db data/wardenstrike.db.bak

# Si está corrupta, eliminar y reiniciar:
rm data/wardenstrike.db
wardenstrike status  # Re-crea la DB
```

### Logs y debug

```bash
# Modo verbose
wardenstrike --verbose recon target.com

# Los logs están en:
tail -f data/wardenstrike.log  # Si existe
```

---

## Flujo de trabajo rápido (TL;DR)

```bash
# 1. Instalar
git clone https://github.com/MrBl4ck04/wardenstrike.git && cd wardenstrike
./install.sh && ./install_tools.sh
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

# 2. Nuevo engagement
wardenstrike engage new "MiAuditoria" --scope target.com

# 3. Atacar
wardenstrike hunt target.com          # Todo automático
# o módulo a módulo:
wardenstrike recon target.com
wardenstrike scan
wardenstrike ai chain

# 4. Reportar
wardenstrike findings
wardenstrike report finding 1 --ai --platform hackerone
```

---

*WardenStrike v1.0 | Warden Security | Solo para uso autorizado en ethical hacking y bug bounty*
