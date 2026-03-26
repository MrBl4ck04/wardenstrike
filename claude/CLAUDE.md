# WardenStrike - AI-Powered Pentesting Framework

## Overview
WardenStrike is an AI-powered pentesting and bug bounty framework. It integrates Claude for intelligent vulnerability analysis, Burp Suite/ZAP for scanning, and 20+ security tools into a unified workflow.

## Architecture
- `wardenstrike/cli.py` - Main CLI (Click-based)
- `wardenstrike/core/engine.py` - Orchestration engine
- `wardenstrike/core/ai_engine.py` - Claude API integration
- `wardenstrike/core/session.py` - SQLite database (SQLAlchemy)
- `wardenstrike/integrations/` - Burp Suite, ZAP, Nuclei
- `wardenstrike/modules/recon/` - Subdomain, portscan, webprobe, crawler, tech detection, JS analysis
- `wardenstrike/modules/scanner/` - Vulnerability scanner, fuzzer
- `wardenstrike/modules/exploit/` - Exploit validation
- `wardenstrike/reporting/` - Multi-format report generation

## Key Commands
```
wardenstrike status              # Check environment
wardenstrike engage new <name>   # Create engagement
wardenstrike recon <target>      # Run recon pipeline
wardenstrike scan                # Vulnerability scanning
wardenstrike analyze             # AI analysis of findings
wardenstrike validate            # Multi-gate validation
wardenstrike chains              # Find exploit chains
wardenstrike findings            # List findings
wardenstrike report finding <id> # Generate report
wardenstrike hunt <target>       # Full pipeline
wardenstrike burp import         # Import from Burp Suite
wardenstrike zap import          # Import from ZAP
wardenstrike js-analyze <url>    # JS security analysis
```

## Development Guidelines
- Python 3.10+, async where possible
- All tools check availability before running (graceful fallback)
- Findings are deduped by hash before storage
- AI analysis is optional (works without ANTHROPIC_API_KEY, just no AI features)
- Proxy support throughout for Burp/ZAP interception
