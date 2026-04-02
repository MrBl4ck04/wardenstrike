"""
WardenStrike - Web3 / Smart Contract Analyzer
Detects: reentrancy, access control, integer overflow, oracle manipulation,
flash loan attacks, signature replay, proxy upgrade issues, ERC4626 bugs.
Static analysis + AI-powered deep audit.
"""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("web3")


@dataclass
class ContractFinding:
    bug_class: str
    severity: str
    description: str
    location: str = ""
    code_snippet: str = ""
    poc: str = ""
    remediation: str = ""
    impact_usd: str = ""


class ContractAnalyzer:
    """
    Smart contract security analyzer.
    Combines static pattern detection with AI analysis and tool integration.
    Covers the top 10 DeFi bug classes.
    """

    # Pre-audit kill signals (don't waste time if these are true)
    KILL_SIGNALS = [
        "TVL < $500K",
        "No verified source code",
        "Single-owner multisig",
        "No audit history",
        "Fork with no changes",
    ]

    # Reentrancy patterns
    REENTRANCY_PATTERNS = [
        (r"\.call\{value:", "External call with value before state update"),
        (r"\.send\(", "send() before state update"),
        (r"\.transfer\(", "transfer() usage — check ordering"),
        (r"\.call\(", "Low-level call — verify CEI pattern"),
    ]

    # Access control issues
    ACCESS_CONTROL_PATTERNS = [
        (r"tx\.origin", "tx.origin used for auth — phishing vulnerable"),
        (r"onlyOwner", "onlyOwner pattern — check owner transfer safety"),
        (r"selfdestruct\(", "selfdestruct present — check auth"),
        (r"delegatecall\(", "delegatecall — proxy storage collision risk"),
        (r"\.call\(abi\.encodeWithSignature", "Dynamic call — verify input validation"),
    ]

    # Integer/arithmetic issues
    MATH_PATTERNS = [
        (r"[*+]\s*\d", "Unchecked arithmetic — overflow potential"),
        (r"unchecked\s*{", "Unchecked block — verify no overflow"),
        (r"/ 0", "Division by zero risk"),
        (r"block\.timestamp", "Timestamp dependence — miner manipulation"),
        (r"block\.number", "Block number dependence"),
    ]

    # Oracle manipulation
    ORACLE_PATTERNS = [
        (r"getPrice\(\)", "Single oracle — flash loan price manipulation"),
        (r"\.latestRoundData\(\)", "Chainlink — check staleness/freshness"),
        (r"balanceOf\(address\(this\)\)", "Spot balance as price oracle — manipulable"),
        (r"reserve0|reserve1", "Uniswap reserves as price — TWAP preferred"),
    ]

    # Flash loan vulnerabilities
    FLASHLOAN_PATTERNS = [
        (r"flashLoan\(", "Flash loan receiver — check invariants"),
        (r"onFlashLoan\(", "Flash loan callback — verify caller"),
        (r"IERC3156FlashBorrower", "Flash loan interface — audit full flow"),
    ]

    # Signature replay
    SIGNATURE_PATTERNS = [
        (r"ecrecover\(", "ecrecover — check nonce/chainId to prevent replay"),
        (r"ECDSA\.recover\(", "ECDSA recover — verify nonce and domain separator"),
        (r"permit\(", "ERC20 permit — check deadline and nonce usage"),
        (r"EIP712", "EIP-712 — verify domain separator includes chainId"),
    ]

    # Proxy / upgrade
    PROXY_PATTERNS = [
        (r"delegatecall\(", "delegatecall — storage collision risk in proxy"),
        (r"_implementation\(\)", "Proxy implementation — check upgrade auth"),
        (r"upgradeTo\(", "Upgrade function — check timelock and access control"),
        (r"initialize\(", "Initializer — verify it can only be called once"),
        (r"UUPSUpgradeable", "UUPS proxy — check _authorizeUpgrade"),
    ]

    def __init__(self, config: Config, ai=None):
        self.config = config
        self.ai = ai
        self.findings: list[ContractFinding] = []

    def _add(self, bug_class, severity, description, location="", code_snippet="",
              poc="", remediation="", impact_usd=""):
        f = ContractFinding(bug_class, severity, description, location,
                            code_snippet, poc, remediation, impact_usd)
        self.findings.append(f)
        log.info(f"[Web3/{severity.upper()}] {bug_class}: {description[:80]}")

    # ─── Static Analysis ──────────────────────────────────────────

    def static_analyze(self, source_code: str, filename: str = "contract.sol") -> list[dict]:
        """Run static pattern analysis on Solidity source code."""
        results = []

        all_patterns = [
            ("Reentrancy", self.REENTRANCY_PATTERNS, "critical"),
            ("Access Control", self.ACCESS_CONTROL_PATTERNS, "critical"),
            ("Integer Issues", self.MATH_PATTERNS, "high"),
            ("Oracle Manipulation", self.ORACLE_PATTERNS, "high"),
            ("Flash Loan", self.FLASHLOAN_PATTERNS, "high"),
            ("Signature Replay", self.SIGNATURE_PATTERNS, "high"),
            ("Proxy/Upgrade", self.PROXY_PATTERNS, "high"),
        ]

        lines = source_code.split("\n")
        for bug_class, patterns, base_severity in all_patterns:
            for pattern, desc in patterns:
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        context = "\n".join(lines[max(0, i-2):i+3])
                        self._add(bug_class, base_severity,
                                  desc,
                                  location=f"{filename}:{i+1}",
                                  code_snippet=context.strip())
                        results.append({
                            "bug_class": bug_class,
                            "line": i + 1,
                            "description": desc,
                            "code": line.strip(),
                        })

        return results

    # ─── Slither integration ──────────────────────────────────────

    def run_slither(self, contract_path: str) -> list[dict]:
        """Run Slither static analyzer if available."""
        log.info(f"Running Slither on {contract_path}...")
        results = []

        try:
            out = subprocess.run(
                ["slither", contract_path, "--json", "-"],
                capture_output=True, text=True, timeout=120
            )
            if out.stdout:
                data = json.loads(out.stdout)
                for detector in data.get("results", {}).get("detectors", []):
                    severity_map = {
                        "High": "high",
                        "Medium": "medium",
                        "Low": "low",
                        "Informational": "info",
                        "Optimization": "info",
                    }
                    sev = severity_map.get(detector.get("impact", ""), "medium")
                    self._add(f"Slither: {detector.get('check', 'unknown')}",
                              sev,
                              detector.get("description", ""),
                              location=str(detector.get("elements", [{}])[0].get("source_mapping", {}).get("filename_relative", "")),
                              remediation=detector.get("markdown", ""))
                    results.append(detector)
        except FileNotFoundError:
            log.info("Slither not installed. Run: pip install slither-analyzer")
        except Exception as e:
            log.debug(f"Slither error: {e}")

        return results

    # ─── Mythril integration ──────────────────────────────────────

    def run_mythril(self, contract_path: str) -> list[dict]:
        """Run Mythril symbolic execution if available."""
        log.info(f"Running Mythril on {contract_path}...")
        results = []

        try:
            out = subprocess.run(
                ["myth", "analyze", contract_path, "-o", "json"],
                capture_output=True, text=True, timeout=300
            )
            if out.stdout:
                data = json.loads(out.stdout)
                for issue in data.get("issues", []):
                    sev_map = {"High": "critical", "Medium": "high", "Low": "medium"}
                    self._add(f"Mythril: {issue.get('title', 'unknown')}",
                              sev_map.get(issue.get("severity", ""), "medium"),
                              issue.get("description", ""),
                              location=f"{issue.get('filename', '')}:{issue.get('lineno', '')}",
                              code_snippet=issue.get("code", ""),
                              poc=issue.get("tx_sequence", ""))
                    results.append(issue)
        except FileNotFoundError:
            log.info("Mythril not installed. Run: pip install mythril")
        except Exception as e:
            log.debug(f"Mythril error: {e}")

        return results

    # ─── 10 DeFi Bug Class Checklist ─────────────────────────────

    def run_defi_checklist(self, source_code: str) -> dict:
        """
        Manual checklist for 10 DeFi bug classes.
        Returns assessment for each class.
        """
        checklist = {}

        # 1. Accounting desync
        has_balance_tracking = bool(re.search(r"totalSupply|totalAssets|totalDebt", source_code))
        checklist["accounting_desync"] = {
            "description": "Internal accounting vs real token balance mismatch",
            "detected": bool(re.search(r"balanceOf\(address\(this\)\)", source_code)),
            "risk": "Spot balance as accounting → flash loan desync",
        }

        # 2. Access control
        checklist["access_control"] = {
            "description": "Privileged function auth checks",
            "detected": bool(re.search(r"onlyOwner|onlyRole|require\(msg\.sender", source_code)),
            "missing": not bool(re.search(r"modifier.*only|AccessControl|Ownable", source_code)),
        }

        # 3. Incomplete execution paths
        checklist["incomplete_path"] = {
            "description": "Some execution paths skip critical checks",
            "patterns_found": [
                line.strip() for line in source_code.split("\n")
                if re.search(r"if\s*\(.*\)\s*return", line)
            ][:5],
        }

        # 4. Off-by-one
        checklist["off_by_one"] = {
            "description": "Boundary condition errors in comparisons",
            "patterns_found": [
                line.strip() for line in source_code.split("\n")
                if re.search(r"[<>]=?\s*\d+", line)
            ][:5],
        }

        # 5. Oracle manipulation
        checklist["oracle"] = {
            "description": "Price oracle manipulation via flash loans",
            "spot_oracle": bool(re.search(r"getReserves|balanceOf.*price|slot0", source_code)),
            "twap_used": bool(re.search(r"observe|TWAP|twap|price0CumulativeLast", source_code)),
        }

        # 6. ERC4626 inflation
        checklist["erc4626"] = {
            "description": "Vault share price inflation attack",
            "is_vault": bool(re.search(r"ERC4626|totalAssets|convertToShares|convertToAssets", source_code)),
            "has_virtual_shares": bool(re.search(r"_decimalsOffset|virtualShares|VIRTUAL", source_code)),
        }

        # 7. Reentrancy
        checklist["reentrancy"] = {
            "description": "State updated after external call",
            "external_calls": len(re.findall(r"\.call\{", source_code)),
            "reentrancy_guard": bool(re.search(r"nonReentrant|ReentrancyGuard|_reentrancyGuard", source_code)),
        }

        # 8. Flash loan
        checklist["flash_loan"] = {
            "description": "Flash loan attack surface",
            "has_flash_loan": bool(re.search(r"flashLoan|onFlashLoan|FLASH", source_code, re.I)),
            "invariant_checks": bool(re.search(r"require.*balance|assert.*total", source_code)),
        }

        # 9. Signature replay
        checklist["signature_replay"] = {
            "description": "Replay attacks via missing nonce/chainId",
            "ecrecover": bool(re.search(r"ecrecover", source_code)),
            "has_nonce": bool(re.search(r"nonce|_nonces|nonces\[", source_code)),
            "has_chainid": bool(re.search(r"chainId|CHAIN_ID|block\.chainid", source_code)),
        }

        # 10. Proxy/upgrade
        checklist["proxy"] = {
            "description": "Proxy upgrade and storage collision issues",
            "is_proxy": bool(re.search(r"delegatecall|_implementation|UUPSUpgradeable|TransparentUpgradeable", source_code)),
            "has_timelock": bool(re.search(r"TimelockController|timelock|delay", source_code)),
        }

        return checklist

    # ─── Foundry PoC template ─────────────────────────────────────

    def generate_poc_template(self, bug_class: str, contract_name: str = "VulnContract") -> str:
        """Generate a Foundry PoC template for a given bug class."""

        templates = {
            "reentrancy": f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract ReentrancyPoCTest is Test {{
    {contract_name} public target;
    AttackerContract public attacker;

    function setUp() public {{
        target = new {contract_name}();
        attacker = new AttackerContract(address(target));
        // Fund target
        vm.deal(address(target), 10 ether);
    }}

    function testReentrancy() public {{
        uint256 balanceBefore = address(target).balance;
        attacker.attack{{value: 1 ether}}();
        uint256 balanceAfter = address(target).balance;
        assertLt(balanceAfter, balanceBefore, "Reentrancy drained funds");
        console.log("Stolen:", balanceBefore - balanceAfter);
    }}
}}

contract AttackerContract {{
    {contract_name} public target;
    constructor(address _target) {{ target = {contract_name}(_target); }}
    function attack() external payable {{ target.withdraw{{value: msg.value}}(); }}
    receive() external payable {{
        if (address(target).balance >= 1 ether) {{
            target.withdraw();
        }}
    }}
}}""",
            "flash_loan": f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract FlashLoanPoCTest is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function testFlashLoanAttack() public {{
        uint256 balanceBefore = token.balanceOf(address(target));
        // 1. Take flash loan
        // 2. Manipulate price
        // 3. Exploit protocol
        // 4. Repay flash loan
        uint256 profit = token.balanceOf(address(this));
        console.log("Profit:", profit);
        assertGt(profit, 0, "Flash loan attack profitable");
    }}
}}""",
        }

        return templates.get(bug_class.lower(), f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

contract {bug_class.replace(' ', '')}PoCTest is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function testVulnerability() public {{
        // TODO: Implement PoC for {bug_class}
        // 1. Setup initial state
        // 2. Trigger vulnerability
        // 3. Assert impact
    }}
}}""")

    # ─── Full audit ───────────────────────────────────────────────

    async def audit(self, source_code: str = None, contract_path: str = None,
                    contract_name: str = "Target", use_tools: bool = True) -> dict:
        """
        Full smart contract security audit.
        Combines static analysis, tool integration, and AI review.
        """
        log.info("Starting smart contract audit...")
        self.findings.clear()

        if not source_code and contract_path:
            source_code = Path(contract_path).read_text()

        if not source_code:
            return {"error": "No source code provided"}

        results = {
            "contract_name": contract_name,
            "loc": len(source_code.split("\n")),
        }

        # Static analysis
        results["static_findings"] = self.static_analyze(source_code, contract_name + ".sol")

        # DeFi checklist
        results["defi_checklist"] = self.run_defi_checklist(source_code)

        # Tool integration
        if use_tools and contract_path:
            results["slither"] = self.run_slither(contract_path)
            results["mythril"] = self.run_mythril(contract_path)

        # AI deep audit
        if self.ai:
            try:
                ai_prompt = f"""Perform a deep security audit of this Solidity contract.
Focus on:
1. Reentrancy (including cross-function and cross-contract)
2. Access control bypasses
3. Integer overflow/underflow (even with SafeMath/Solidity 0.8+)
4. Oracle price manipulation (flash loan attacks)
5. Logic errors and edge cases
6. Front-running opportunities
7. Denial of service vectors
8. Gas griefing
9. Signature replay
10. Proxy upgrade safety

Contract:
```solidity
{source_code[:8000]}
```

Provide: vulnerability name, severity, code location, PoC outline, impact in USD if known."""

                results["ai_audit"] = self.ai._call(
                    "You are a world-class smart contract security auditor (ex-Trail of Bits, OpenZeppelin, Code4rena). "
                    "You find critical bugs that others miss. Be specific about code locations.",
                    ai_prompt
                )
            except Exception as e:
                log.debug(f"AI audit error: {e}")

        # Generate PoC templates for critical findings
        results["poc_templates"] = {}
        for f in self.findings:
            if f.severity == "critical" and f.bug_class not in results["poc_templates"]:
                results["poc_templates"][f.bug_class] = self.generate_poc_template(
                    f.bug_class, contract_name)

        results["findings"] = [vars(f) for f in self.findings]
        results["summary"] = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
            "medium": sum(1 for f in self.findings if f.severity == "medium"),
        }

        return results
