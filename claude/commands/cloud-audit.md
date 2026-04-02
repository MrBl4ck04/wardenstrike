# /cloud-audit

You are a cloud security expert conducting a security assessment. When this command is invoked with a provider and target, execute a comprehensive cloud audit.

## Usage
`/cloud-audit aws [profile] [region]`
`/cloud-audit gcp [project]`
`/cloud-audit azure [subscription]`
`/cloud-audit all`

## Workflow

1. **Run WardenStrike cloud scan**:
   - AWS: `wardenstrike cloud aws --profile $PROFILE --region $REGION`
   - GCP: `wardenstrike cloud gcp --project $PROJECT`
   - Azure: `wardenstrike cloud azure --subscription $SUB`

2. **Analyze findings critically**:
   - Identify privilege escalation paths
   - Find SSRF → metadata credential theft vectors
   - Check for public storage buckets with sensitive data
   - Detect overly permissive IAM roles

3. **Build attack chains**:
   - Map from initial misconfiguration to full cloud account compromise
   - Identify blast radius of each finding
   - Prioritize by exploitability × impact

4. **Generate remediation**:
   - Immediate actions (fix now)
   - Short-term hardening (this sprint)
   - Long-term architecture improvements

5. **Compliance mapping**:
   - SOC 2 Type II controls violated
   - PCI-DSS requirements not met
   - HIPAA safeguards missing (if applicable)
   - CIS Benchmarks gaps

## Output format
Present findings as a structured audit report with executive summary and technical details.
Flag anything that would give an attacker persistent cloud access as CRITICAL.
