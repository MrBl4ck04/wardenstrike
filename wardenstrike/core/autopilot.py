"""
WardenStrike - Autopilot Agent
Autonomous penetration testing loop inspired by PentAGI's multi-agent architecture.

Flow:
  1. Build engagement state (what we know so far)
  2. Claude Planner decides next action (plan_next_action)
  3. Adviser checks for loops/failures
  4. Execute the action via the relevant module
  5. Save results to DB + episodic memory
  6. Repeat until done or max_iterations reached

Action space:
  recon | scan | graphql | jwt | oauth | cloud | osint | ad | web3 | analyze | report | done
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from wardenstrike.config import Config
from wardenstrike.core.memory import EpisodicMemory
from wardenstrike.utils.logger import get_logger

log = get_logger("autopilot")
console = Console()

MAX_ITERATIONS = 25          # hard ceiling to prevent runaway loops
ADVISER_CHECK_EVERY = 3      # run adviser every N actions
LOOP_DETECTION_WINDOW = 4    # actions to inspect for repeated patterns


class AutopilotAgent:
    """
    Autonomous pentesting agent that plans → executes → learns in a loop.

    Usage:
        agent = AutopilotAgent(config, engagement_id=1)
        asyncio.run(agent.run(target="example.com"))
    """

    def __init__(self, config: Config, engagement_id: int,
                 max_iterations: int = MAX_ITERATIONS,
                 scope: list[str] | None = None,
                 mode: str = "full"):
        self.config = config
        self.engagement_id = engagement_id
        self.max_iterations = max_iterations
        self.scope = scope or []
        self.mode = mode  # full | recon_only | web | cloud | internal

        # Use WardenStrikeEngine as the single source of truth for all actions
        # (avoids duplicating module instantiation logic and signature mismatches)
        from wardenstrike.core.engine import WardenStrikeEngine
        self.engine = WardenStrikeEngine(config)
        self.engine.load_engagement(engagement_id)

        self.ai = self.engine.ai
        self.db = self.engine.db
        self.memory = EpisodicMemory(config.get("session", "memory_db", default="./data/memory.db"))

        # Working memory for current run
        self._state: dict[str, Any] = {}
        self._action_log: list[dict] = []
        self._iteration = 0

    # ── State builder ──────────────────────────────────────────────────────

    def _build_state(self, target: str) -> dict:
        """Assemble current engagement state for the planner."""
        findings = self.db.get_findings(self.engagement_id)
        recon = self.db.get_recon_results(self.engagement_id)
        # Deduplicate recon by type
        recon_by_type: dict[str, list] = {}
        for r in recon:
            recon_by_type.setdefault(r.result_type, []).append(r.value)

        # Summarise findings by severity
        finding_summary = {}
        for f in findings:
            finding_summary.setdefault(f.severity, []).append({
                "title": f.title,
                "url": f.url,
                "vuln_type": f.vuln_type,
            })

        # What actions have already been completed?
        completed_actions = list({a["action"] for a in self._action_log if a.get("outcome") != "failure"})

        # Technology hints from recon
        tech_hints = [r.value for r in recon if r.result_type == "technology"]

        # Memory suggestions
        target_hint = ",".join(tech_hints[:5]) if tech_hints else target
        available = self._available_actions()
        memory_suggestions = self.memory.suggest_actions(target_hint, available)

        return {
            "target": target,
            "scope": self.scope,
            "mode": self.mode,
            "iteration": self._iteration,
            "max_iterations": self.max_iterations,
            "subdomains_found": recon_by_type.get("subdomain", [])[:20],
            "live_hosts": recon_by_type.get("url", [])[:20],
            "open_ports": recon_by_type.get("port", [])[:20],
            "technologies": tech_hints[:15],
            "js_files": recon_by_type.get("js_file", [])[:10],
            "endpoints": recon_by_type.get("endpoint", [])[:20],
            "findings_summary": finding_summary,
            "finding_count": len(findings),
            "known_targets": [t.domain for t in self.db.get_targets(self.engagement_id)],
            "completed_actions": completed_actions,
            "last_actions": [a["action"] for a in self._action_log[-5:]],
            "memory_suggestions": [
                {"action": s["action"], "historical_success_rate": s["success_rate"]}
                for s in memory_suggestions[:5]
            ],
        }

    def _available_actions(self) -> list[str]:
        """Return actions allowed for the current mode."""
        all_actions = ["recon", "scan", "graphql", "jwt", "oauth",
                       "cloud", "osint", "ad", "web3", "analyze", "report"]
        mode_filters = {
            "recon_only": ["recon", "osint"],
            "web":        ["recon", "scan", "graphql", "jwt", "oauth", "analyze", "report"],
            "cloud":      ["recon", "osint", "cloud", "analyze", "report"],
            "internal":   ["recon", "ad", "scan", "analyze", "report"],
            "full":       all_actions,
        }
        return mode_filters.get(self.mode, all_actions)

    # ── Action executor ────────────────────────────────────────────────────

    async def _execute(self, action: str, params: dict, target: str) -> dict:
        """Dispatch to the appropriate module and return a result dict."""
        try:
            if action == "recon":
                return await self._do_recon(target, params)
            elif action == "scan":
                return await self._do_scan(target, params)
            elif action == "graphql":
                return await self._do_graphql(target, params)
            elif action == "jwt":
                return await self._do_jwt(params)
            elif action == "oauth":
                return await self._do_oauth(target, params)
            elif action == "cloud":
                return await self._do_cloud(params)
            elif action == "osint":
                return await self._do_osint(target, params)
            elif action == "ad":
                return await self._do_ad(target, params)
            elif action == "web3":
                return await self._do_web3(target, params)
            elif action == "analyze":
                return await self._do_analyze()
            elif action == "report":
                return self._do_report()
            else:
                return {"status": "skipped", "reason": f"unknown action: {action}"}
        except Exception as e:
            log.error(f"Action '{action}' raised: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    async def _do_recon(self, target: str, params: dict) -> dict:
        quick = params.get("quick", self._iteration > 1)
        results = await self.engine.run_recon(target, quick=quick)
        return {"status": "success",
                "subdomains": len(results.get("subdomains", [])),
                "urls": len(results.get("urls", []))}

    async def _do_scan(self, target: str, params: dict) -> dict:
        targets_list = params.get("targets") or None  # None → engine reads from DB
        results = await self.engine.run_scan(targets=targets_list,
                                             vuln_types=params.get("vuln_types"))
        return {"status": "success", "findings": results.get("total_findings", 0)}

    async def _do_graphql(self, target: str, params: dict) -> dict:
        url = params.get("url", target)
        results = await self.engine.run_graphql_assessment(url, token=params.get("token", ""))
        return {"status": "success", "findings": results.get("findings_saved", 0)}

    async def _do_jwt(self, params: dict) -> dict:
        token = params.get("token", "")
        if not token:
            return {"status": "skipped", "reason": "no JWT token in state"}
        results = await self.engine.run_jwt_attacks(
            token, target_url=params.get("target_url", ""))
        return {"status": "success", "findings": results.get("findings_saved", 0)}

    async def _do_oauth(self, target: str, params: dict) -> dict:
        results = await self.engine.run_oauth_assessment(
            target, client_id=params.get("client_id", ""))
        return {"status": "success", "findings": results.get("findings_saved", 0)}

    async def _do_cloud(self, params: dict) -> dict:
        provider = params.get("provider", "all")
        results = await self.engine.run_cloud_assessment(provider=provider)
        total = sum(len(v) for v in results.values() if isinstance(v, list))
        return {"status": "success", "findings": total}

    async def _do_osint(self, target: str, params: dict) -> dict:
        results = await self.engine.run_osint(target, deep=params.get("deep", False))
        return {"status": "success", "data_points": results.get("total", 0)}

    async def _do_ad(self, target: str, params: dict) -> dict:
        results = await self.engine.run_ad_assessment(
            target=target,
            domain=params.get("domain", ""),
            username=params.get("username", ""),
            password=params.get("password", ""),
            dc_ip=params.get("dc_ip", ""),
        )
        return {"status": "success", "findings": results.get("findings_saved", 0)}

    async def _do_web3(self, target: str, params: dict) -> dict:
        results = await self.engine.run_web3_audit(
            target, contract_address=params.get("contract_address", ""))
        return {"status": "success", "findings": results.get("findings_saved", 0)}

    async def _do_analyze(self) -> dict:
        findings = self.db.get_findings(self.engagement_id)
        unanalyzed = [f for f in findings if not f.ai_analysis]
        for finding in unanalyzed[:10]:  # analyze up to 10 per iteration
            analysis = self.ai.analyze_vulnerability({
                "title": finding.title,
                "vuln_type": finding.vuln_type,
                "url": finding.url,
                "evidence": finding.evidence,
                "severity": finding.severity,
            })
            # Persist AI analysis back to finding
            with self.db.get_session() as session:
                from wardenstrike.core.session import Finding
                f = session.get(Finding, finding.id)
                if f:
                    f.ai_analysis = json.dumps(analysis)
                    session.commit()
        return {"status": "success", "analyzed": len(unanalyzed[:10])}

    def _do_report(self) -> dict:
        findings = self.db.get_findings(self.engagement_id)
        if not findings:
            return {"status": "skipped", "reason": "no findings to report"}
        eng = self.db.get_engagement(self.engagement_id)
        report = self.ai.generate_pentest_report_section(
            findings=[{
                "title": f.title, "severity": f.severity,
                "vuln_type": f.vuln_type, "url": f.url,
                "description": f.description, "evidence": f.evidence,
            } for f in findings],
            section="executive_summary",
            engagement_name=eng.name if eng else "engagement",
        )
        # Save report to file
        report_path = f"./data/autopilot_report_{self.engagement_id}.md"
        with open(report_path, "w") as fh:
            fh.write(f"# WardenStrike Autopilot Report\n\n{report}")
        return {"status": "success", "report_path": report_path}

    # ── Adviser ────────────────────────────────────────────────────────────

    def _check_for_loops(self) -> bool:
        """Simple local loop detection before calling the AI adviser."""
        if len(self._action_log) < LOOP_DETECTION_WINDOW:
            return False
        recent = [a["action"] for a in self._action_log[-LOOP_DETECTION_WINDOW:]]
        # All same action with failure outcome
        if len(set(recent)) == 1:
            outcomes = [a.get("outcome", "") for a in self._action_log[-LOOP_DETECTION_WINDOW:]]
            if all(o == "failure" for o in outcomes):
                return True
        return False

    async def _run_adviser(self) -> dict | None:
        """Run the AI adviser every ADVISER_CHECK_EVERY iterations."""
        if self._iteration % ADVISER_CHECK_EVERY != 0:
            return None
        advice = self.ai.advise(self._action_log[-10:])
        if advice.get("issue_detected"):
            console.print(Panel(
                f"[yellow]Adviser:[/yellow] {advice['issue_type']}\n"
                f"{advice['description']}\n"
                f"[bold]Recommendation:[/bold] {advice['recommendation']}",
                title="[yellow]Adviser Alert[/yellow]",
                border_style="yellow",
            ))
        return advice

    # ── Main loop ──────────────────────────────────────────────────────────

    async def run(self, target: str) -> dict:
        """Run the autonomous pentesting loop."""
        start_time = time.time()

        console.print(Panel(
            f"[bold green]WardenStrike Autopilot[/bold green]\n"
            f"Target: [cyan]{target}[/cyan]  |  Mode: [magenta]{self.mode}[/magenta]  |  "
            f"Max iterations: [yellow]{self.max_iterations}[/yellow]\n"
            f"LLM: Claude  {'+ Local (' + self.ai.local_model + ')' if self.ai.local_enabled else ''}",
            title="[bold]Autopilot Started[/bold]",
            border_style="green",
        ))

        # Ensure target exists in DB
        self.db.add_target(self.engagement_id, target)

        while self._iteration < self.max_iterations:
            self._iteration += 1

            # Build state
            state = self._build_state(target)

            # Get planner decision
            with console.status(f"[bold blue]Planning action {self._iteration}/{self.max_iterations}...[/bold blue]"):
                plan = self.ai.plan_next_action(state)

            action = plan.get("action", "analyze")
            params = plan.get("action_params", {})
            reasoning = plan.get("reasoning", "")
            confidence = plan.get("confidence", "medium")
            stop = plan.get("stop", False)

            # Print decision
            console.print(f"\n[bold]Step {self._iteration}[/bold] → "
                          f"[cyan]{action}[/cyan] "
                          f"[dim]({confidence} confidence)[/dim]")
            if reasoning:
                console.print(f"  [dim]Reason: {reasoning}[/dim]")

            if stop or action == "done":
                console.print("\n[bold green]Autopilot: coverage complete — stopping.[/bold green]")
                break

            # Check for loops (fast, local)
            if self._check_for_loops():
                console.print("[yellow]Loop detected locally — forcing 'analyze' pivot.[/yellow]")
                action = "analyze"
                params = {}

            # Execute action
            with console.status(f"[bold]Executing: {action}[/bold]"):
                result = await self._execute(action, params, target)

            outcome = "success" if result.get("status") == "success" else "failure"
            console.print(f"  Result: [{('green' if outcome == 'success' else 'red')}]{outcome}[/] — {result}")

            # Log action
            self._action_log.append({
                "iteration": self._iteration,
                "action": action,
                "params": params,
                "result": result,
                "outcome": outcome,
                "timestamp": datetime.utcnow().isoformat(),
            })

            # Update episodic memory
            tech_hint = ",".join(state.get("technologies", [])[:5]) or target
            finding_note = f"findings: {result.get('findings', 0)}" if "findings" in result else ""
            self.memory.record(
                action=action,
                target_hint=tech_hint,
                outcome=outcome,
                finding=finding_note,
                notes=reasoning,
                engagement=str(self.engagement_id),
            )

            # AI adviser check
            await self._run_adviser()

            # Brief pause to avoid hammering APIs
            await asyncio.sleep(1)

        # Final summary
        elapsed = time.time() - start_time
        findings = self.db.get_findings(self.engagement_id)
        stats = {}
        for f in findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1

        table = Table(title="Autopilot Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")
        table.add_row("Target", target)
        table.add_row("Iterations", str(self._iteration))
        table.add_row("Elapsed", f"{elapsed:.0f}s")
        table.add_row("Total Findings", str(len(findings)))
        for sev, cnt in sorted(stats.items()):
            table.add_row(f"  {sev.capitalize()}", str(cnt))
        table.add_row("Memory records", str(self.memory.summary().get("total", 0)))
        console.print(table)

        return {
            "target": target,
            "iterations": self._iteration,
            "elapsed_seconds": elapsed,
            "total_findings": len(findings),
            "findings_by_severity": stats,
            "action_log": self._action_log,
        }
