"""
WardenStrike - AI Engine
Claude-powered analysis for vulnerability assessment, exploit chaining, and report generation.
"""

import json
from typing import Any

import anthropic

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("ai_engine")


SYSTEM_PROMPTS = {
    "vuln_analyzer": """You are an expert penetration tester and vulnerability analyst.
Your job is to analyze potential security findings and provide:
1. Confirmation if the vulnerability is real or a false positive
2. Severity assessment with CVSS 3.1 score and vector
3. Real-world impact analysis
4. Steps to exploit (for authorized testing)
5. Remediation recommendations

Be precise, technical, and evidence-based. If uncertain, say so.
Always respond in valid JSON format when asked.""",

    "exploit_chain": """You are an expert at identifying exploit chains in web applications.
Given a set of individual findings, identify how they can be combined to achieve greater impact.
Consider: privilege escalation paths, data exfiltration chains, authentication bypass combinations,
SSRF-to-RCE chains, XSS-to-account-takeover, etc.
Rate each chain by feasibility and impact.""",

    "report_writer": """You are a professional security report writer for bug bounty programs.
Write clear, concise, and impactful vulnerability reports that:
1. Have a compelling title
2. Clearly describe the vulnerability
3. Provide step-by-step reproduction instructions
4. Demonstrate real business impact (not just theoretical)
5. Include remediation advice
6. Follow the specific platform's preferred format

Use professional language. Be direct. Focus on impact.""",

    "js_analyzer": """You are a JavaScript security analyst specializing in bug bounty hunting.
Analyze JavaScript code to find:
1. Hardcoded API keys, tokens, and secrets
2. Hidden API endpoints and admin routes
3. Authentication/authorization bypass opportunities
4. Client-side security controls that can be bypassed
5. Insecure data handling or storage
6. Debug/development code left in production
7. Potential IDOR patterns in API calls
8. WebSocket endpoints and protocols
9. GraphQL queries and mutations
10. Sensitive business logic exposed client-side

For each finding, explain the security impact and how to exploit it.""",

    "recon_analyzer": """You are a reconnaissance analyst for penetration testing.
Analyze reconnaissance data and:
1. Identify the most promising attack vectors
2. Prioritize targets by likelihood of vulnerability
3. Suggest specific vulnerability classes to test based on technology stack
4. Identify misconfigurations and exposure points
5. Map the attack surface and highlight interesting patterns
6. Correlate findings from different recon tools""",

    "triage": """You are a vulnerability triage specialist for bug bounty programs.
Evaluate findings and determine:
1. Is this a valid, exploitable vulnerability?
2. Is it in scope for the program?
3. What is the correct severity rating?
4. Is this likely a duplicate of commonly reported issues?
5. What is the estimated bounty range?
6. Should the hunter invest time writing a full report?

Apply the 7-Question Gate:
- Is it reproducible?
- Is it in scope?
- Is the impact real (not theoretical)?
- Can you demonstrate it in under 5 minutes?
- Would a reasonable security team fix this?
- Is it likely a duplicate?
- Is the report quality sufficient?""",
}


class AIEngine:
    """Interface to Claude API for security analysis tasks."""

    def __init__(self, config: Config):
        self.config = config
        api_key = config.get("ai", "api_key")
        if not api_key:
            api_key = None  # Will use ANTHROPIC_API_KEY env var
        self.client = anthropic.Anthropic(api_key=api_key)
        self.default_model = config.get("ai", "model", default="claude-sonnet-4-20250514")
        self.report_model = config.get("ai", "report_model", default="claude-opus-4-20250514")
        self.max_tokens = config.get("ai", "max_tokens", default=8192)

    def _call(self, system: str, prompt: str, model: str | None = None, max_tokens: int | None = None, json_mode: bool = False) -> str:
        """Make a call to Claude API."""
        model = model or self.default_model
        max_tokens = max_tokens or self.max_tokens

        messages = [{"role": "user", "content": prompt}]

        if json_mode:
            system += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no code blocks, just raw JSON."

        try:
            response = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=messages,
            )
            return response.content[0].text
        except anthropic.APIError as e:
            log.error(f"AI API error: {e}")
            return json.dumps({"error": str(e)}) if json_mode else f"Error: {e}"

    def analyze_vulnerability(self, finding: dict) -> dict:
        """Analyze a potential vulnerability finding."""
        prompt = f"""Analyze this potential security finding:

Title: {finding.get('title', 'Unknown')}
Type: {finding.get('vuln_type', 'Unknown')}
URL: {finding.get('url', 'N/A')}
Endpoint: {finding.get('endpoint', 'N/A')}
Method: {finding.get('method', 'N/A')}
Parameter: {finding.get('parameter', 'N/A')}
Payload: {finding.get('payload', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')}
Tool Source: {finding.get('tool_source', 'N/A')}

Respond in JSON with these fields:
{{
    "is_valid": true/false,
    "confidence": "high/medium/low",
    "severity": "critical/high/medium/low/info",
    "cvss_score": 0.0,
    "cvss_vector": "CVSS:3.1/...",
    "cwe_id": "CWE-XXX",
    "analysis": "detailed analysis",
    "impact": "business impact description",
    "exploitation_steps": ["step1", "step2"],
    "remediation": "how to fix",
    "false_positive_indicators": ["reason1"],
    "additional_tests": ["test to confirm"]
}}"""

        result = self._call(SYSTEM_PROMPTS["vuln_analyzer"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Failed to parse AI response", "raw": result}

    def find_exploit_chains(self, findings: list[dict]) -> dict:
        """Identify potential exploit chains from multiple findings."""
        findings_summary = "\n".join(
            f"- [{f.get('severity', '?').upper()}] {f.get('title', '?')} at {f.get('url', '?')} ({f.get('vuln_type', '?')})"
            for f in findings
        )

        prompt = f"""Given these individual findings from a penetration test, identify potential exploit chains:

{findings_summary}

Respond in JSON:
{{
    "chains": [
        {{
            "name": "Chain name",
            "description": "How the chain works",
            "findings_used": [indices],
            "combined_severity": "critical/high/medium",
            "combined_cvss": 0.0,
            "feasibility": "high/medium/low",
            "impact": "What an attacker achieves",
            "steps": ["step1", "step2"]
        }}
    ],
    "recommendations": ["prioritized recommendations"]
}}"""

        result = self._call(SYSTEM_PROMPTS["exploit_chain"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Failed to parse", "raw": result}

    def generate_report(self, finding: dict, platform: str = "hackerone") -> str:
        """Generate a professional bug bounty report."""
        prompt = f"""Generate a professional bug bounty report for {platform.upper()} platform.

Finding details:
Title: {finding.get('title', '')}
Type: {finding.get('vuln_type', '')}
Severity: {finding.get('severity', '')}
CVSS: {finding.get('cvss_score', '')} {finding.get('cvss_vector', '')}
CWE: {finding.get('cwe_id', '')}
URL: {finding.get('url', '')}
Endpoint: {finding.get('endpoint', '')}
Method: {finding.get('method', '')}
Parameter: {finding.get('parameter', '')}
Payload: {finding.get('payload', '')}
Evidence: {finding.get('evidence', '')}
Description: {finding.get('description', '')}
Impact: {finding.get('impact', '')}
Steps to Reproduce: {finding.get('steps_to_reproduce', '')}

Generate a complete, submission-ready report in markdown format.
Include: Summary, Severity Justification, Steps to Reproduce, Impact, Remediation, References."""

        return self._call(SYSTEM_PROMPTS["report_writer"], prompt, model=self.report_model)

    def analyze_javascript(self, js_content: str, source_url: str = "") -> dict:
        """AI-powered JavaScript security analysis."""
        # Truncate very large files
        if len(js_content) > 100_000:
            js_content = js_content[:100_000] + "\n... [TRUNCATED]"

        prompt = f"""Analyze this JavaScript file for security issues.
Source URL: {source_url}

```javascript
{js_content}
```

Respond in JSON:
{{
    "endpoints": [{{"path": "/api/...", "method": "GET/POST", "auth_required": true/false, "params": [], "notes": ""}}],
    "secrets": [{{"type": "api_key/token/password", "value": "...", "severity": "critical/high/medium", "context": ""}}],
    "vulnerabilities": [{{"type": "xss/idor/auth_bypass/etc", "description": "", "severity": "", "code_snippet": "", "exploitation": ""}}],
    "interesting_patterns": [{{"pattern": "", "description": "", "security_relevance": ""}}],
    "hidden_features": [{{"feature": "", "endpoint": "", "description": ""}}],
    "attack_surface_summary": "overall analysis and recommended next steps"
}}"""

        result = self._call(SYSTEM_PROMPTS["js_analyzer"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Failed to parse", "raw": result}

    def analyze_recon_data(self, recon_data: dict) -> dict:
        """Analyze reconnaissance results and prioritize attack vectors."""
        prompt = f"""Analyze this reconnaissance data and provide attack prioritization:

Subdomains found: {len(recon_data.get('subdomains', []))}
Sample subdomains: {recon_data.get('subdomains', [])[:30]}

Live hosts: {len(recon_data.get('live_hosts', []))}
Technologies detected: {json.dumps(recon_data.get('technologies', {}), indent=2)[:3000]}

Open ports: {json.dumps(recon_data.get('ports', {}), indent=2)[:2000]}

URLs discovered: {len(recon_data.get('urls', []))}
Sample URLs: {recon_data.get('urls', [])[:30]}

JS Files: {len(recon_data.get('js_files', []))}
Parameters found: {recon_data.get('parameters', [])[:30]}

Respond in JSON:
{{
    "priority_targets": [{{"target": "", "reason": "", "suggested_tests": [], "estimated_severity": ""}}],
    "attack_vectors": [{{"vector": "", "targets": [], "likelihood": "high/medium/low", "tools": []}}],
    "interesting_findings": [{{"finding": "", "significance": ""}}],
    "technology_risks": [{{"tech": "", "known_issues": [], "cves_to_check": []}}],
    "recommended_workflow": ["step1", "step2"],
    "estimated_scope_quality": "rich/moderate/limited"
}}"""

        result = self._call(SYSTEM_PROMPTS["recon_analyzer"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Failed to parse", "raw": result}

    def triage_finding(self, finding: dict, program_info: dict | None = None) -> dict:
        """Triage a finding through the 7-Question Gate."""
        prompt = f"""Triage this potential vulnerability:

Finding: {json.dumps(finding, indent=2, default=str)}
Program Info: {json.dumps(program_info or {}, indent=2)}

Apply the 7-Question Gate and respond in JSON:
{{
    "gate_results": {{
        "reproducible": true/false,
        "in_scope": true/false,
        "real_impact": true/false,
        "demo_under_5min": true/false,
        "team_would_fix": true/false,
        "likely_duplicate": true/false,
        "report_quality_sufficient": true/false
    }},
    "gate_passed": true/false,
    "gates_failed": ["list of failed gates"],
    "recommendation": "submit/improve/skip",
    "estimated_severity": "critical/high/medium/low",
    "estimated_bounty_range": "$X - $Y",
    "improvement_suggestions": ["suggestion1"],
    "duplicate_risk_assessment": "description"
}}"""

        result = self._call(SYSTEM_PROMPTS["triage"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Failed to parse", "raw": result}
