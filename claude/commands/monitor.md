# /monitor

Set up and run continuous asset monitoring for ongoing engagements.

## Usage
`/monitor setup target.com`
`/monitor run [--targets-file scope.txt]`
`/monitor alerts [--severity high]`

## What gets monitored

### Every run
- New subdomains (CT logs + subfinder)
- New open ports (nmap/socket scan)
- TLS certificate changes and new SANs
- Technology stack changes (new headers)

### Content monitoring
- Page content hash changes
- New API endpoints appearing
- New JavaScript files
- Exposed tokens/keys in pages
- Internal IP addresses appearing
- New error messages

### High-value alerts (investigate immediately)
- New subdomain: could be new attack surface
- New port 6379/27017/9200: exposed database
- New port 22/3389: remote access opened
- Certificate changed: possible MitM or infrastructure change
- AWS key in page: critical credential leak
- JWT in URL: token exposure

## Recommended schedule

### Bug bounty
- Run every 4-6 hours
- Alert on: new subdomains, new ports, cert changes

### Enterprise audit (ongoing)
- Run every 1 hour for critical assets
- Run daily for broader scope
- Alert everything to SOC/security team

## Setup as cron
```bash
# Every 4 hours
0 */4 * * * wardenstrike monitor run --scope-file /opt/wardenstrike/scope.txt >> /var/log/wardenstrike/monitor.log 2>&1
```

## Alert response
1. New subdomain → immediately run `wardenstrike recon $new_subdomain`
2. New exposed port → run targeted scan + check for default creds
3. New JWT/key in page → capture immediately, assess scope
4. Certificate change → verify legitimacy with team
