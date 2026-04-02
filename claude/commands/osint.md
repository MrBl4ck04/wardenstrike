# /osint

OSINT collection and intelligence analysis for a target organization.

## Usage
`/osint target.com [--deep]`
`/osint "Company Name" [--deep]`

## Workflow

### Step 1: Passive Recon
`wardenstrike osint target.com`
- Certificate Transparency logs (crt.sh)
- WHOIS lookup and registrar info
- ASN and IP range enumeration
- DNS enumeration

### Step 2: Deep OSINT (--deep flag)
`wardenstrike osint target.com --deep`
- GitHub secret scanning
- Breach data check (HIBP)
- Shodan host enumeration
- Email harvesting (theHarvester)
- Metadata extraction (metagoofil)

### Step 3: Google Dorking
Use generated dorks from the output:
- Paste dorks into Google one by one
- Look for: exposed admin panels, config files, error messages, directory listings
- Document all findings

### Step 4: GitHub Dorking
Search on github.com/search:
- `"target.com" password`
- `"target.com" api_key`
- `"target.com" .env`
- Check all results for leaked credentials

### Step 5: Shodan Investigation
Use generated Shodan dorks:
- `hostname:target.com`
- Look for: exposed services, CVEs, default credentials
- Note all non-web ports (6379=Redis, 27017=MongoDB, etc.)

### Step 6: AI Intelligence Analysis
Run `wardenstrike ai` to build actionable intelligence from collected data.

## Key findings to escalate
- GitHub repos with credentials/API keys
- Exposed admin panels or dev environments
- Email addresses for phishing/password spraying
- Shodan hosts with known CVEs
- Shadow IT assets not in official scope
