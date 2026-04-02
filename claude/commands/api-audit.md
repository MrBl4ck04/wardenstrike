# /api-audit

Comprehensive REST API and GraphQL security assessment.

## Usage
`/api-audit https://api.target.com [--auth "Bearer TOKEN"]`

## Workflow

### Step 1: API Discovery
- `wardenstrike recon $TARGET --quick` (find API endpoints)
- Check for Swagger/OpenAPI: `/swagger.json`, `/openapi.json`, `/api-docs`
- Check for GraphQL: `wardenstrike graphql $TARGET`
- Enumerate API versions: v1, v2, v3, beta, internal

### Step 2: Authentication Testing
- `wardenstrike jwt $TOKEN` (if JWT-based)
- `wardenstrike oauth $TARGET --client-id $ID` (if OAuth)
- Test for missing auth on endpoints
- Test for horizontal privilege escalation (IDOR)

### Step 3: IDOR Testing
For each endpoint returning object IDs:
1. Note your own object ID (e.g., user/123)
2. Try sequential/predictable IDs (user/124, user/1)
3. Try GUIDs from other users if visible
4. Test PUT/DELETE/PATCH with other users' IDs

### Step 4: Mass Assignment
Test POST/PUT endpoints with extra fields:
- Add `"role": "admin"`, `"is_admin": true`, `"verified": true`
- Check if extra fields get persisted

### Step 5: Business Logic
- Price manipulation (change price in request)
- Quantity bypass (negative numbers, 0, very large)
- Workflow bypass (skip payment step, skip verification)
- Race conditions (concurrent requests)

### Step 6: AI Analysis
`wardenstrike ai chain` to correlate API findings into ATO chains.

## Common API chains
- IDOR → account takeover → admin access
- Auth bypass → data exfiltration
- Mass assignment → privilege escalation
- Rate limit bypass → credential brute force
