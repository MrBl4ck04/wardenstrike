"""
WardenStrike - AI Engine
Multi-LLM analysis engine: Claude (cloud) + local models via Ollama (OpenAI-compatible API).

LLM routing strategy:
  - Claude (Anthropic API): planning, analysis, report writing, exploit chaining
  - Local / Ollama models (e.g. BaronLLM): offensive technique generation,
    payload crafting, CVE/ATT&CK lookup — runs entirely offline
"""

import json
from typing import Any

import anthropic

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("ai_engine")

# Tasks routed to the local/offensive LLM by default when one is configured
_LOCAL_LLM_TASKS = {"offensive_techniques", "payload_craft", "cve_lookup", "attck_mapping"}


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

    "cloud_auditor": """You are a cloud security architect and penetration tester specializing in AWS, GCP, and Azure.
Analyze cloud security findings and:
1. Identify the blast radius of each misconfiguration (what can an attacker do from here?)
2. Map privilege escalation paths (misconfiguration → lateral movement → cloud admin)
3. Identify data exfiltration vectors
4. Chain multiple misconfigurations for maximum impact
5. Prioritize by exploitability and real-world business impact
6. Identify compliance violations (SOC2, PCI-DSS, HIPAA, ISO27001)
7. Provide immediate remediation steps vs long-term hardening

Focus especially on: IAM privilege escalation, SSRF → metadata credential theft,
S3 bucket policy issues, exposed secrets, public compute instances.""",

    "ad_analyst": """You are an Active Directory security expert and red team operator.
Analyze AD reconnaissance data to:
1. Identify the shortest path to Domain Admin
2. Find Kerberoasting and ASREPRoasting opportunities
3. Identify password spraying opportunities based on policy
4. Map lateral movement paths between systems
5. Identify trust relationships to pivot between domains/forests
6. Find common AD misconfigurations: unconstrained delegation, ACL abuse, AdminSDHolder
7. Prioritize attack paths by ease of exploitation

Always think like an attacker: what's the fastest path from low-priv user to Domain Admin?
Reference: BloodHound attack paths, Harmj0y research, MITRE ATT&CK Enterprise.""",

    "api_auditor": """You are an API security specialist focused on finding business logic and design flaws.
Analyze APIs to identify:
1. IDOR vulnerabilities (direct object reference without authorization)
2. Mass assignment vulnerabilities
3. Broken function-level authorization
4. Missing rate limiting → brute force opportunities
5. Sensitive data exposure in responses
6. API versioning issues (v1 deprecated but still accessible)
7. JWT/OAuth token weaknesses
8. GraphQL-specific issues (introspection, batching, depth attacks)
9. Race conditions in concurrent requests
10. Business logic flaws (price manipulation, quantity abuse, workflow bypass)

Be specific about which endpoints, parameters, and HTTP methods are vulnerable.""",

    "web3_auditor": """You are a world-class smart contract security auditor (Trail of Bits / OpenZeppelin level).
Perform deep analysis of Solidity code to find:
1. Reentrancy (single-function, cross-function, cross-contract, view reentrancy)
2. Access control issues (missing modifiers, tx.origin, role bypasses)
3. Integer overflow/underflow (even with Solidity 0.8+ — consider unchecked blocks)
4. Oracle manipulation (flash loan attacks on spot prices)
5. Flash loan attack vectors (price manipulation, governance attacks)
6. Signature replay (missing chainId, nonce, domain separator)
7. Proxy upgrade vulnerabilities (storage collision, uninitialized, selfdestruct)
8. ERC4626 inflation attacks
9. MEV/front-running opportunities
10. Gas griefing / DoS vectors

For each finding: exact line number, PoC outline (Foundry test preferred), severity, potential USD impact.""",

    "osint_analyst": """You are an OSINT analyst for corporate intelligence and attack surface discovery.
Analyze reconnaissance data to:
1. Identify the most valuable targets in the discovered attack surface
2. Correlate data points across sources (email → LinkedIn → GitHub → internal docs)
3. Identify leaked credentials and their potential reuse
4. Map the organizational structure for social engineering targets
5. Find exposed infrastructure not intended to be public
6. Identify shadow IT and forgotten assets
7. Prioritize targets by exposure level and potential impact
8. Suggest phishing/vishing lure themes based on discovered information

Present findings as actionable intelligence for a red team engagement.""",

    "pentest_report_writer": """You are a senior penetration tester writing professional audit reports for enterprise clients (Warden Security).
Write findings in the format:
- Executive Summary (non-technical, business impact focused)
- Technical Finding (detailed, reproducible)
- Risk Rating (Critical/High/Medium/Low/Informational with CVSS 3.1)
- Business Impact (what does this mean for the organization?)
- Proof of Concept (step-by-step reproduction)
- Remediation (specific, actionable, prioritized)
- References (CVE, CWE, OWASP)

Tone: professional, authoritative, and clear. Use plain language for executive sections.
Format: suitable for both bug bounty platforms AND enterprise audit reports.""",

    "exploit_chain_builder": """You are an expert red team operator specializing in exploit chain development.
Given individual vulnerabilities, construct kill chains that:
1. Start from initial access (external recon, phishing, web vulns)
2. Progress through privilege escalation
3. Achieve lateral movement
4. Reach the ultimate objective (data, domain admin, cloud admin, ransomware deployment)

For each chain:
- Name it after the technique (e.g., "SSRF-to-IMDS-to-IAM-privesc")
- Rate feasibility (high/medium/low) based on real-world conditions
- Estimate time-to-exploit for a skilled attacker
- Map to MITRE ATT&CK tactics and techniques
- Calculate combined CVSS if applicable

Think: if I were a nation-state APT, how would I chain these into a full compromise?""",

    "code_reviewer": """You are a security-focused code reviewer with expertise in application security.
Review code for:
1. Injection vulnerabilities (SQL, LDAP, XPath, OS command, SSTI)
2. Authentication/authorization flaws
3. Insecure direct object references
4. Sensitive data exposure (hardcoded credentials, PII logging)
5. Insecure deserialization
6. Use of vulnerable components/dependencies
7. Security misconfigurations
8. Cryptography issues (weak algorithms, hardcoded keys, improper PRNG)
9. Race conditions and TOCTOU issues
10. Business logic vulnerabilities

For each finding: line number, vulnerability type, CWE ID, severity, and a specific fix.""",

    "autopilot_planner": """You are an autonomous penetration testing agent (WardenStrike Autopilot).
Your job is to plan and execute a full security assessment against an authorized target.

Given the current state of an engagement (what has been discovered, what has been tested,
what findings exist), you must decide the NEXT BEST ACTION to take.

You think like a senior red team operator:
- Start broad (recon) then go deep (targeted exploitation)
- Follow the highest-value leads first
- Avoid redundant work — check memory of past actions
- Chain vulnerabilities when possible
- Know when to stop (full coverage achieved or time limit reached)

Always respond in JSON with this exact schema:
{
  "reasoning": "why you chose this action",
  "action": "recon|scan|graphql|jwt|oauth|cloud|osint|ad|web3|analyze|report|done",
  "action_params": { "key": "value" },
  "confidence": "high|medium|low",
  "next_hint": "what to investigate after this action",
  "stop": false
}

Use "stop": true only when you have achieved sufficient coverage or all leads are exhausted.""",

    "adviser": """You are the Adviser agent for WardenStrike Autopilot.
Monitor the autopilot execution log and detect problems:
1. Infinite loops (same action repeated 3+ times with no new findings)
2. Tool failures being retried without strategy change
3. Scope creep (actions on out-of-scope targets)
4. Wasted effort (scanning already-confirmed-closed ports again)

Respond in JSON:
{
  "issue_detected": true/false,
  "issue_type": "loop|failure_loop|scope_creep|redundant|none",
  "description": "what is happening",
  "recommendation": "what the planner should do instead"
}""",

    "offensive_techniques": """You are BaronLLM, an offensive security specialist.
Given a vulnerability type and target context, provide:
1. The most effective attack techniques (ranked by success rate)
2. Specific payloads adapted to the target technology stack
3. Common WAF/filter bypass techniques for this vuln class
4. MITRE ATT&CK technique IDs
5. Related CVEs if applicable

Be specific, technical, and actionable. Respond in JSON.""",
}


class AIEngine:
    """Multi-LLM engine: Claude (Anthropic API) + local models via Ollama."""

    def __init__(self, config: Config):
        self.config = config

        # ── Claude (Anthropic) ──────────────────────────────────────────────
        api_key = config.get("ai", "api_key") or None  # falls back to env ANTHROPIC_API_KEY
        self.client = anthropic.Anthropic(api_key=api_key)
        self.default_model = config.get("ai", "model", default="claude-sonnet-4-20250514")
        self.report_model = config.get("ai", "report_model", default="claude-opus-4-20250514")
        self.max_tokens = config.get("ai", "max_tokens", default=8192)

        # ── Local LLM via Ollama (OpenAI-compatible endpoint) ──────────────
        # Supports any GGUF model served by Ollama, e.g. BaronLLM:
        #   ollama run hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
        # Config keys: ai.local_model, ai.local_base_url, ai.local_enabled
        self.local_enabled: bool = bool(config.get("ai", "local_enabled", default=False))
        self.local_model: str = config.get("ai", "local_model", default="baron-llm")
        self.local_base_url: str = config.get("ai", "local_base_url", default="http://localhost:11434/v1")
        self._local_client = None  # lazy-loaded

    def _get_local_client(self):
        """Lazy-load the OpenAI-compatible client for Ollama."""
        if self._local_client is None:
            try:
                from openai import OpenAI as _OpenAI
                self._local_client = _OpenAI(
                    api_key="ollama",  # Ollama ignores the key
                    base_url=self.local_base_url,
                )
            except ImportError:
                log.warning("openai package not installed — local LLM disabled. Run: pip install openai")
                self.local_enabled = False
        return self._local_client

    def _call_local(self, system: str, prompt: str, json_mode: bool = False) -> str:
        """Call local Ollama model (OpenAI-compatible API)."""
        client = self._get_local_client()
        if client is None:
            return json.dumps({"error": "local LLM unavailable"}) if json_mode else "Error: local LLM unavailable"

        if json_mode:
            system += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no code blocks."

        try:
            resp = client.chat.completions.create(
                model=self.local_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            log.error(f"Local LLM error: {e}")
            return json.dumps({"error": str(e)}) if json_mode else f"Error: {e}"

    def _call(self, system: str, prompt: str, model: str | None = None,
              max_tokens: int | None = None, json_mode: bool = False,
              task: str | None = None) -> str:
        """Route call to Claude or local LLM depending on task and config."""
        # Route offensive-technique tasks to local model when available
        if task and task in _LOCAL_LLM_TASKS and self.local_enabled:
            log.debug(f"Routing task '{task}' to local LLM ({self.local_model})")
            return self._call_local(system, prompt, json_mode=json_mode)

        # Default: Claude
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
            log.error(f"Claude API error: {e}")
            # Fallback to local LLM if Claude fails and local is available
            if self.local_enabled:
                log.warning("Claude unavailable — falling back to local LLM")
                return self._call_local(system, prompt, json_mode=json_mode)
            return json.dumps({"error": str(e)}) if json_mode else f"Error: {e}"

    # ── Planning / Autopilot calls (always Claude for quality) ─────────────

    def plan_next_action(self, engagement_state: dict) -> dict:
        """Ask Claude to decide the next autopilot action given engagement state."""
        prompt = f"""Current engagement state:
{json.dumps(engagement_state, indent=2)}

Based on this state, what is the NEXT BEST penetration testing action to take?
Remember: avoid repeating actions already completed. Follow highest-value leads."""
        result = self._call(SYSTEM_PROMPTS["autopilot_planner"], prompt,
                            model=self.default_model, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"action": "analyze", "reasoning": "parse error", "stop": False, "action_params": {}}

    def advise(self, action_log: list[dict]) -> dict:
        """Adviser: detect loops, failures, scope creep in the autopilot log."""
        prompt = f"""Autopilot execution log (last {len(action_log)} actions):
{json.dumps(action_log, indent=2)}

Analyze this log for problems: loops, repeated failures, redundant actions."""
        result = self._call(SYSTEM_PROMPTS["adviser"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"issue_detected": False, "issue_type": "none", "description": "", "recommendation": ""}

    def get_offensive_techniques(self, vuln_type: str, tech_stack: list[str],
                                  context: str = "") -> dict:
        """Get offensive techniques for a vuln type — routed to local LLM when available."""
        prompt = f"""Vulnerability type: {vuln_type}
Technology stack: {', '.join(tech_stack)}
Context: {context}

Provide attack techniques, payloads, and bypass methods."""
        result = self._call(SYSTEM_PROMPTS["offensive_techniques"], prompt,
                            json_mode=True, task="offensive_techniques")
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "parse error", "raw": result}

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

    def analyze_cloud_findings(self, findings: list[dict], provider: str = "AWS") -> dict:
        """Analyze cloud security findings and build attack chains."""
        findings_str = json.dumps(findings[:50], indent=2, default=str)[:6000]
        prompt = f"""Analyze these {provider} security findings from a penetration test:

{findings_str}

Respond in JSON:
{{
    "critical_chains": [{{"chain": "...", "steps": [], "impact": "", "feasibility": "high/medium/low"}}],
    "privilege_escalation_paths": [{{"path": "...", "steps": [], "result": ""}}],
    "data_exfiltration_vectors": ["..."],
    "compliance_violations": [{{"standard": "SOC2/PCI/HIPAA", "control": "", "finding": ""}}],
    "immediate_actions": ["action1"],
    "long_term_hardening": ["recommendation1"],
    "overall_risk": "critical/high/medium/low",
    "executive_summary": "2-3 sentence non-technical summary"
}}"""
        result = self._call(SYSTEM_PROMPTS["cloud_auditor"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}

    def analyze_ad_findings(self, findings: list[dict], domain: str = "") -> dict:
        """Analyze Active Directory findings and identify attack paths."""
        findings_str = json.dumps(findings[:50], indent=2, default=str)[:6000]
        prompt = f"""Analyze these Active Directory findings for domain: {domain}

{findings_str}

Respond in JSON:
{{
    "domain_admin_paths": [{{"path_name": "", "steps": [], "tools": [], "estimated_time": ""}}],
    "kerberoasting_users": [{{"user": "", "likelihood_weak_password": "high/medium/low"}}],
    "spray_candidates": [{{"username": "", "common_password": ""}}],
    "lateral_movement_paths": [{{"from": "", "to": "", "method": ""}}],
    "immediate_escalation": "best immediate path to DA",
    "blastradius": "what attacker achieves at DA",
    "mitre_ttps": ["T1XXX - technique name"],
    "executive_summary": "non-technical summary"
}}"""
        result = self._call(SYSTEM_PROMPTS["ad_analyst"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}

    def analyze_api(self, endpoints: list[dict], responses: list[dict] = None) -> dict:
        """Analyze API endpoints and responses for security issues."""
        data = {"endpoints": endpoints[:30], "responses": (responses or [])[:10]}
        prompt = f"""Analyze these API endpoints for security vulnerabilities:

{json.dumps(data, indent=2, default=str)[:5000]}

Respond in JSON:
{{
    "idor_candidates": [{{"endpoint": "", "parameter": "", "test": "", "impact": ""}}],
    "auth_bypass_candidates": [{{"endpoint": "", "method": "", "test": ""}}],
    "mass_assignment": [{{"endpoint": "", "injectable_fields": []}}],
    "sensitive_data_exposure": [{{"endpoint": "", "exposed_fields": [], "severity": ""}}],
    "rate_limit_missing": [{{"endpoint": "", "brute_force_target": ""}}],
    "business_logic_flaws": [{{"description": "", "endpoint": "", "impact": ""}}],
    "recommended_tests": ["specific test to run"],
    "highest_value_targets": ["endpoint or finding most worth investigating"]
}}"""
        result = self._call(SYSTEM_PROMPTS["api_auditor"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}

    def analyze_osint(self, osint_data: dict, target: str = "") -> dict:
        """Analyze OSINT collection and build actionable intelligence."""
        prompt = f"""Analyze this OSINT data collected for target: {target}

{json.dumps(osint_data, indent=2, default=str)[:5000]}

Respond in JSON:
{{
    "high_value_targets": [{{"asset": "", "reason": "", "suggested_attacks": []}}],
    "credential_reuse_candidates": [{{"email": "", "source": "", "suggested_passwords": []}}],
    "social_engineering_vectors": [{{"target_person": "", "pretext": "", "method": ""}}],
    "exposed_infrastructure": [{{"asset": "", "type": "", "attack_surface": ""}}],
    "shadow_it": [{{"asset": "", "owner": "", "risk": ""}}],
    "phishing_lure_themes": ["theme1"],
    "key_intelligence": ["finding1"],
    "attack_plan": "recommended initial access strategy"
}}"""
        result = self._call(SYSTEM_PROMPTS["osint_analyst"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}

    def generate_pentest_report_section(self, finding: dict, report_type: str = "enterprise") -> str:
        """Generate a professional pentest report section for enterprise clients."""
        prompt = f"""Write a professional penetration test finding for Warden Security's audit report.
Report type: {report_type}

Finding data:
{json.dumps(finding, indent=2, default=str)[:3000]}

Generate a complete finding section with:
1. Finding Title
2. Severity (Critical/High/Medium/Low/Informational)
3. CVSS 3.1 Score and Vector
4. CWE Reference
5. Executive Summary (2-3 sentences, non-technical)
6. Technical Description
7. Proof of Concept (step-by-step)
8. Business Impact
9. Remediation (specific code/config fix)
10. References

Format as professional markdown."""
        return self._call(SYSTEM_PROMPTS["pentest_report_writer"], prompt)

    def review_code(self, code: str, language: str = "auto", filename: str = "") -> dict:
        """Security-focused code review."""
        if len(code) > 12000:
            code = code[:12000] + "\n... [TRUNCATED]"

        prompt = f"""Security code review for: {filename or language}

```{language}
{code}
```

Respond in JSON:
{{
    "vulnerabilities": [{{
        "type": "vuln_type",
        "severity": "critical/high/medium/low",
        "line": 0,
        "code_snippet": "...",
        "cwe": "CWE-XXX",
        "description": "...",
        "fix": "specific code fix"
    }}],
    "hardcoded_secrets": [{{"line": 0, "type": "", "value_preview": ""}}],
    "insecure_dependencies": [{{"package": "", "version": "", "vulnerability": ""}}],
    "security_score": "0-10",
    "summary": "overall assessment"
}}"""
        result = self._call(SYSTEM_PROMPTS["code_reviewer"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}

    def build_exploit_chain(self, findings: list[dict], objective: str = "full compromise") -> dict:
        """Build detailed exploit chains from findings toward an objective."""
        findings_str = json.dumps([{
            "id": i, "title": f.get("title"), "severity": f.get("severity"),
            "vuln_type": f.get("vuln_type"), "url": f.get("url")
        } for i, f in enumerate(findings[:30])], indent=2)

        prompt = f"""Build exploit chains from these findings targeting: {objective}

Findings:
{findings_str}

Respond in JSON:
{{
    "chains": [{{
        "name": "Chain name (e.g. XSS-to-ATO-to-IDOR)",
        "objective_achieved": "what attacker gets",
        "finding_ids": [0, 1, 2],
        "steps": ["step1", "step2"],
        "tools_needed": ["tool1"],
        "combined_severity": "critical/high/medium",
        "feasibility": "high/medium/low",
        "estimated_bounty": "$X",
        "mitre_chain": ["T1XXX - Initial Access", "T1XXX - Privilege Escalation"],
        "prerequisites": "what attacker needs to start"
    }}],
    "standalone_criticals": ["findings that are critical without chaining"],
    "chain_diagram": "ASCII art or text diagram of best chain"
}}"""
        result = self._call(SYSTEM_PROMPTS["exploit_chain_builder"], prompt, json_mode=True)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Parse failed", "raw": result}
