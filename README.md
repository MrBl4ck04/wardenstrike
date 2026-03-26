# WardenStrike

**AI-Powered Pentesting Framework** by [Warden Security](https://github.com/warden)

```
 __        ___    ____  ____  _____ _   _
 \ \      / / \  |  _ \|  _ \| ____| \ | |
  \ \ /\ / / _ \ | |_) | | | |  _| |  \| |
   \ V  V / ___ \|  _ <| |_| | |___| |\  |
    \_/\_/_/   \_\_| \_\____/|_____|_| \_|

 ____ _____ ____  ___ _  _______
/ ___|_   _|  _ \|_ _| |/ / ____|
\___ \ | | | |_) || || ' /|  _|
 ___) || | |  _ < | || . \| |___
|____/ |_| |_| \_\___|_|\_\_____|
```

WardenStrike transforms Claude AI into a complete pentesting co-pilot. It orchestrates 20+ security tools, integrates with Burp Suite & OWASP ZAP, and uses AI for intelligent vulnerability analysis, exploit chain discovery, and professional report generation.

## Features

### Core
- **Full Hunting Pipeline**: Recon → Scan → Analyze → Validate → Report
- **AI-Powered Analysis**: Claude-driven vulnerability validation, triage (7-Question Gate), and exploit chain discovery
- **Session Management**: SQLite database tracking engagements, targets, findings
- **Smart Deduplication**: Hash-based finding dedup across all sources

### Integrations
- **Burp Suite**: REST API — launch scans, import findings, manage scope, proxy traffic
- **OWASP ZAP**: Spider, Ajax spider, active scan, alert import, authentication config
- **Nuclei**: Template-based scanning with severity filtering
- **20+ Tools**: subfinder, amass, httpx, nmap, katana, gau, ffuf, dalfox, sqlmap, gospider...

### Reconnaissance (7 Phases)
- Subdomain enumeration (5 sources: subfinder, amass, crt.sh, wayback, chaos)
- HTTP probing with tech detection
- Port scanning with service/version detection
- Web crawling and URL discovery
- Technology fingerprinting & WAF detection
- **AI-Powered JavaScript Analysis** (50+ patterns + deep AI analysis)
- AI recon correlation and attack prioritization

### Vulnerability Scanning
- Nuclei template scanning (CVEs, misconfigs, exposures)
- XSS scanning (dalfox)
- SQL injection (sqlmap)
- CORS misconfiguration detection
- Open redirect testing
- Directory & parameter fuzzing (ffuf, arjun)
- Security header analysis

### Validation (4 Gates)
1. **Scope Check**: Verify target is in program scope
2. **Reproducibility**: Automated replay and verification
3. **AI Triage**: 7-Question Gate assessment
4. **Duplicate Check**: Cross-reference against known findings

### Reporting
- **Formats**: Markdown, HTML (dark theme), JSON, AI-generated
- **Platforms**: HackerOne, Bugcrowd, Intigriti, Immunefi
- **Executive Summaries**: Engagement-level overview reports
- **CVSS 3.1**: Automatic scoring and vector generation

## Quick Start

```bash
# Clone & install
git clone https://github.com/YOUR_ORG/wardenstrike.git
cd wardenstrike
bash install.sh

# Install security tools
bash install_tools.sh

# Configure
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY and other keys

# Check environment
wardenstrike status

# Create engagement & hunt
wardenstrike engage new "BugBounty-Target" --platform hackerone --scope target.com
wardenstrike hunt target.com
```

## Commands

| Command | Description |
|---------|-------------|
| `wardenstrike status` | Check environment and tool status |
| `wardenstrike engage new <name>` | Create new engagement |
| `wardenstrike engage list` | List all engagements |
| `wardenstrike engage dashboard` | Show engagement dashboard |
| `wardenstrike recon <target>` | Run recon pipeline |
| `wardenstrike scan` | Run vulnerability scanning |
| `wardenstrike analyze` | AI analysis of findings |
| `wardenstrike validate` | Multi-gate validation |
| `wardenstrike chains` | Find exploit chains |
| `wardenstrike findings` | List all findings |
| `wardenstrike report finding <id>` | Generate report for a finding |
| `wardenstrike report summary` | Executive summary |
| `wardenstrike hunt <target>` | Full pipeline (recon→report) |
| `wardenstrike burp status` | Check Burp Suite connection |
| `wardenstrike burp import` | Import findings from Burp |
| `wardenstrike burp scan <urls>` | Launch Burp scan |
| `wardenstrike zap status` | Check ZAP connection |
| `wardenstrike zap import` | Import alerts from ZAP |
| `wardenstrike zap scan <url>` | Run full ZAP scan |
| `wardenstrike js-analyze <url>` | Analyze JavaScript for security issues |

## Burp Suite Integration

1. Open Burp Suite Professional
2. Go to **Settings → Suite → REST API**
3. Enable the API and note the URL/key
4. Configure in `.env`:
   ```
   WARDENSTRIKE_BURP_URL=http://127.0.0.1:1337
   WARDENSTRIKE_BURP_KEY=your_api_key
   ```
5. Test: `wardenstrike burp status`

## Architecture

```
wardenstrike/
├── wardenstrike/
│   ├── cli.py              # CLI (Click + Rich)
│   ├── config.py            # YAML/env configuration
│   ├── core/
│   │   ├── engine.py        # Orchestration engine
│   │   ├── ai_engine.py     # Claude API (6 specialized prompts)
│   │   └── session.py       # SQLite DB (SQLAlchemy)
│   ├── integrations/
│   │   ├── burpsuite.py     # Burp Suite REST API
│   │   ├── zap.py           # OWASP ZAP API
│   │   └── nuclei.py        # Nuclei wrapper
│   ├── modules/
│   │   ├── recon/           # 6 recon modules
│   │   ├── scanner/         # Vuln scanner + fuzzer
│   │   └── exploit/         # Exploit validator (4 gates)
│   ├── reporting/           # Multi-format reports
│   ├── knowledge/           # Payloads, bypass techniques
│   └── utils/               # HTTP client, logger, helpers
├── claude/                  # Claude Code integration
├── config/default.yaml      # 150+ config options
└── install.sh               # One-line installer
```

## Requirements

- Python 3.10+
- Required tools: subfinder, httpx, nmap, nuclei
- Optional: amass, gau, katana, ffuf, dalfox, sqlmap, gospider, arjun...
- API key: Anthropic (Claude) for AI features

## License

MIT License - Warden Security

## Disclaimer

This tool is designed for authorized security testing only. Always obtain proper authorization before testing any target. The authors are not responsible for misuse.
