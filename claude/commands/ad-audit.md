# /ad-audit

Active Directory security assessment command. Conducts comprehensive internal pentest assessment.

## Usage
`/ad-audit domain.local [dc_ip] [username] [password]`
`/ad-audit domain.local --anonymous`

## Workflow

### Phase 1: Unauthenticated Enumeration
- `wardenstrike ad scan domain.local --dc $DC_IP`
- LDAP anonymous bind check
- SMB null session enumeration
- Password policy extraction (safe spray window)
- LLMNR/NBT-NS check

### Phase 2: Authenticated Enumeration (with creds)
- `wardenstrike ad scan domain.local --dc $DC_IP --username $USER --password $PASS`
- Kerberoasting: `GetUserSPNs.py domain/user:pass -dc-ip $DC -request`
- ASREPRoasting: `GetNPUsers.py domain/ -dc-ip $DC -usersfile users.txt`
- BloodHound collection: all data for path analysis

### Phase 3: Vulnerability Checks
- Zerologon (CVE-2020-1472)
- PetitPotam (NTLM coerce)
- NoPac (CVE-2021-42278/42287)
- PrintNightmare (CVE-2021-1675)
- Unconstrained delegation
- ACL abuse opportunities

### Phase 4: Attack Path Analysis
Run `wardenstrike ai chain` to build chains toward Domain Admin.

### Phase 5: Reporting
- Document each attack path with steps
- Map to MITRE ATT&CK
- Provide remediation priority

## Key findings to highlight
- Any path to Domain Admin
- Kerberoastable accounts with weak passwords
- Accounts with no lockout + weak policy
- Critical CVEs in the environment
- Trust relationships to other domains
