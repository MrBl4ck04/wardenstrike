# /web3-audit

Smart contract security audit for DeFi protocols and NFT projects.

## Usage
`/web3-audit Contract.sol`
`/web3-audit ./contracts/ --name ProtocolName`

## Pre-audit Kill Signals
Stop and don't waste time if:
- TVL < $500K (not worth auditing for bug bounty)
- No verified source code on Etherscan
- Single-owner multisig (centralized, likely won't fix)
- Obvious fork with zero changes
- No active Immunefi program

## Audit Workflow

### Step 1: Static Analysis
`wardenstrike web3 audit Contract.sol --name ContractName`

### Step 2: 10 Bug Class Checklist
Run through each class manually:
1. **Accounting desync** — spot balance vs internal tracking
2. **Access control** — missing modifiers, tx.origin, role checks
3. **Incomplete paths** — early returns skipping checks
4. **Off-by-one** — boundary conditions in comparisons
5. **Oracle manipulation** — spot price → TWAP preferred
6. **ERC4626 inflation** — virtual shares protection
7. **Reentrancy** — CEI pattern, reentrancy guard
8. **Flash loan** — invariant checks before/after
9. **Signature replay** — nonce, chainId, domain separator
10. **Proxy/upgrade** — storage collision, timelock, auth

### Step 3: Tool Confirmation
- Slither: `slither Contract.sol --print human-summary`
- Mythril: `myth analyze Contract.sol`

### Step 4: PoC Development (Foundry)
Generate PoC template: shown in audit output
Test: `forge test -vvvv --match-test testVulnerability`

### Step 5: Impact Assessment
- Calculate maximum extractable value (MEV)
- Estimate protocol TVL at risk
- Document affected user funds

### Immunefi Severity Guide
- Critical: Direct theft of funds > $1M
- High: Temporary freeze of funds OR theft < $1M
- Medium: Contract DoS OR theft < $10K
- Low: Incorrect values, no direct loss
