"""
WardenStrike - CLI Interface
Rich-powered command-line interface for the pentesting framework.
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm

from wardenstrike import __version__
from wardenstrike.config import Config
from wardenstrike.core.engine import WardenStrikeEngine
from wardenstrike.utils.logger import print_banner, console, get_logger

log = get_logger("cli")


def run_async(coro):
    """Helper to run async code from sync CLI commands."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def get_engine(ctx) -> WardenStrikeEngine:
    """Get or create engine from click context."""
    if "engine" not in ctx.obj:
        config_path = ctx.obj.get("config")
        config = Config(config_path)
        ctx.obj["engine"] = WardenStrikeEngine(config)
    return ctx.obj["engine"]


# ============================================================================
# Main CLI Group
# ============================================================================

@click.group()
@click.option("--config", "-c", type=click.Path(), help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.version_option(__version__, prog_name="WardenStrike")
@click.pass_context
def main(ctx, config, verbose):
    """WardenStrike - AI-Powered Pentesting Framework"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["verbose"] = verbose


# ============================================================================
# Status & Info
# ============================================================================

@main.command()
@click.pass_context
def status(ctx):
    """Show WardenStrike status and environment check."""
    print_banner()
    engine = get_engine(ctx)

    env = engine.check_environment()

    table = Table(title="Tool Status", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Type")

    from wardenstrike.core.engine import REQUIRED_TOOLS, OPTIONAL_TOOLS
    for tool, available in env["tools"].items():
        status_str = "[green]Installed[/green]" if available else "[red]Missing[/red]"
        tool_type = "Required" if tool in REQUIRED_TOOLS else "Optional"
        table.add_row(tool, status_str, tool_type)

    console.print(table)

    if env["missing_required"]:
        console.print(f"\n[red]Missing required tools: {', '.join(env['missing_required'])}[/red]")
        console.print("Run: [cyan]wardenstrike install-tools[/cyan] to install them")
    else:
        console.print("\n[green]All required tools installed![/green]")

    # Show active engagement
    eng = engine.engagement
    if eng:
        console.print(f"\n[bold]Active Engagement:[/bold] {eng.name} (ID: {eng.id})")
    else:
        console.print("\n[dim]No active engagement. Use 'wardenstrike engage new' to create one.[/dim]")

    # Burp/ZAP status
    burp_cfg = engine.config.section("burpsuite")
    zap_cfg = engine.config.section("zap")
    console.print(f"\n[bold]Integrations:[/bold]")
    console.print(f"  Burp Suite: {'[green]Enabled[/green]' if burp_cfg.get('enabled') else '[dim]Disabled[/dim]'}")
    console.print(f"  OWASP ZAP:  {'[green]Enabled[/green]' if zap_cfg.get('enabled') else '[dim]Disabled[/dim]'}")


# ============================================================================
# Engagement Management
# ============================================================================

@main.group()
def engage():
    """Manage pentesting engagements."""
    pass


@engage.command("new")
@click.argument("name")
@click.option("--platform", "-p", type=click.Choice(["hackerone", "bugcrowd", "intigriti", "immunefi", "private"]), default="private")
@click.option("--scope", "-s", multiple=True, help="In-scope domains (can specify multiple)")
@click.option("--url", help="Program URL")
@click.pass_context
def engage_new(ctx, name, platform, scope, url):
    """Create a new engagement."""
    engine = get_engine(ctx)
    eng = engine.create_engagement(
        name=name,
        platform=platform,
        scope=list(scope) if scope else [],
        program_url=url,
    )
    console.print(Panel(f"[green]Engagement created![/green]\n\nID: {eng.id}\nName: {eng.name}\nPlatform: {platform}\nScope: {', '.join(scope) if scope else 'Not set'}",
                       title="New Engagement"))


@engage.command("list")
@click.pass_context
def engage_list(ctx):
    """List all engagements."""
    engine = get_engine(ctx)
    engagements = engine.db.list_engagements()

    table = Table(title="Engagements", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Created")

    for eng in engagements:
        stats = engine.db.get_finding_stats(eng.id)
        table.add_row(
            str(eng.id), eng.name, eng.platform or "-",
            f"[green]{eng.status}[/green]" if eng.status == "active" else eng.status,
            str(stats["total"]),
            eng.created_at.strftime("%Y-%m-%d") if eng.created_at else "-",
        )

    console.print(table)


@engage.command("load")
@click.argument("engagement_id", type=int)
@click.pass_context
def engage_load(ctx, engagement_id):
    """Load an existing engagement."""
    engine = get_engine(ctx)
    eng = engine.load_engagement(engagement_id)
    if eng:
        console.print(f"[green]Loaded engagement: {eng.name}[/green]")
    else:
        console.print(f"[red]Engagement {engagement_id} not found[/red]")


@engage.command("dashboard")
@click.pass_context
def engage_dashboard(ctx):
    """Show engagement dashboard."""
    engine = get_engine(ctx)
    data = engine.dashboard()

    console.print(Panel(
        f"[bold]{data['engagement']['name']}[/bold] ({data['engagement']['platform']})\n"
        f"Status: {data['engagement']['status']}\n\n"
        f"Targets: {data['targets']['total']} total, {data['targets']['alive']} alive\n"
        f"Findings: {data['findings']['total']} total",
        title="Engagement Dashboard",
    ))

    if data["findings"]["by_severity"]:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Count")
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "cyan"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = data["findings"]["by_severity"].get(sev, 0)
            if count > 0:
                table.add_row(f"[{sev_colors.get(sev, 'white')}]{sev.upper()}[/{sev_colors.get(sev, 'white')}]", str(count))
        console.print(table)


# ============================================================================
# Recon
# ============================================================================

@main.command()
@click.argument("target")
@click.option("--quick", "-q", is_flag=True, help="Quick recon (fewer tools, faster)")
@click.pass_context
def recon(ctx, target, quick):
    """Run reconnaissance pipeline on a target."""
    print_banner()
    engine = get_engine(ctx)

    if not engine.engagement:
        console.print("[yellow]No active engagement. Creating one...[/yellow]")
        engine.create_engagement(f"recon_{target}", scope=[target])

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), console=console) as progress:
        task = progress.add_task("Running recon pipeline...", total=None)
        results = run_async(engine.run_recon(target, quick=quick))
        progress.update(task, completed=True)

    # Summary
    console.print(Panel(
        f"[bold]Recon Complete![/bold]\n\n"
        f"Subdomains: {len(results.get('subdomains', []))}\n"
        f"Live Hosts: {len(results.get('live_hosts', []))}\n"
        f"URLs: {len(results.get('urls', []))}\n"
        f"JS Files: {len(results.get('js_files', []))}\n"
        f"Parameters: {len(results.get('parameters', []))}",
        title=f"Recon Results: {target}",
        border_style="green",
    ))


# ============================================================================
# Scan
# ============================================================================

@main.command()
@click.option("--targets", "-t", multiple=True, help="Specific targets to scan")
@click.option("--type", "vuln_type", multiple=True, help="Specific vulnerability types")
@click.pass_context
def scan(ctx, targets, vuln_type):
    """Run vulnerability scanning pipeline."""
    print_banner()
    engine = get_engine(ctx)

    target_list = list(targets) if targets else None
    results = run_async(engine.run_scan(target_list, list(vuln_type) if vuln_type else None))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    console.print(Panel(
        f"[bold]Scan Complete![/bold]\n\n"
        f"Total findings: {len(results.get('findings', []))}",
        title="Scan Results",
        border_style="green",
    ))


# ============================================================================
# Analyze
# ============================================================================

@main.command()
@click.pass_context
def analyze(ctx):
    """Run AI analysis on findings."""
    engine = get_engine(ctx)
    results = engine.analyze_findings()
    valid = sum(1 for r in results if r["analysis"].get("is_valid"))
    console.print(f"\n[bold]Analysis: {valid}/{len(results)} validated[/bold]")


@main.command()
@click.pass_context
def chains(ctx):
    """Find exploit chains across findings."""
    engine = get_engine(ctx)
    results = engine.find_chains()

    chain_list = results.get("chains", [])
    if not chain_list:
        console.print("[yellow]No exploit chains identified[/yellow]")
        return

    for chain in chain_list:
        console.print(Panel(
            f"[bold]{chain.get('name', 'Unknown')}[/bold]\n\n"
            f"{chain.get('description', '')}\n\n"
            f"Severity: {chain.get('combined_severity', '?')}\n"
            f"Feasibility: {chain.get('feasibility', '?')}\n"
            f"Impact: {chain.get('impact', '')}",
            border_style="red",
        ))


# ============================================================================
# Validate
# ============================================================================

@main.command()
@click.pass_context
def validate(ctx):
    """Validate findings through the multi-gate system."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.modules.exploit.validator import ExploitValidator
    validator = ExploitValidator(engine.config, engine.db, engine.ai)
    results = run_async(validator.validate_all_new(eng.id))

    confirmed = sum(1 for r in results if r["overall"] == "confirmed")
    console.print(f"\n[bold]Validation: {confirmed}/{len(results)} confirmed[/bold]")


# ============================================================================
# Report
# ============================================================================

@main.group()
def report():
    """Generate security reports."""
    pass


@report.command("finding")
@click.argument("finding_id", type=int)
@click.option("--format", "-f", "formats", multiple=True, default=["markdown", "html"])
@click.option("--platform", "-p", type=click.Choice(["hackerone", "bugcrowd", "intigriti", "immunefi"]))
@click.option("--ai", is_flag=True, help="Generate AI-enhanced report")
@click.pass_context
def report_finding(ctx, finding_id, formats, platform, ai):
    """Generate report for a specific finding."""
    engine = get_engine(ctx)
    from wardenstrike.reporting.generator import ReportGenerator
    gen = ReportGenerator(engine.config, engine.db, engine.ai if ai else None)

    fmt_list = list(formats) + (["ai"] if ai else [])
    outputs = gen.generate(finding_id, formats=fmt_list, platform=platform)

    for fmt, path in outputs.items():
        console.print(f"  [green]{fmt}:[/green] {path}")


@report.command("summary")
@click.pass_context
def report_summary(ctx):
    """Generate executive summary for current engagement."""
    engine = get_engine(ctx)
    from wardenstrike.reporting.generator import ReportGenerator
    gen = ReportGenerator(engine.config, engine.db)
    eng = engine._require_engagement()
    path = gen.generate_executive_summary(eng.id)
    console.print(f"[green]Summary: {path}[/green]")


# ============================================================================
# Findings Management
# ============================================================================

@main.command()
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--type", "vuln_type", help="Filter by vulnerability type")
@click.option("--status", help="Filter by status")
@click.pass_context
def findings(ctx, severity, vuln_type, status):
    """List findings for the current engagement."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()
    results = engine.db.get_findings(eng.id, severity=severity, vuln_type=vuln_type, status=status)

    table = Table(title=f"Findings - {eng.name}", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=15)
    table.add_column("Title", max_width=40)
    table.add_column("URL", max_width=30)
    table.add_column("Status", width=12)
    table.add_column("Source", width=10)

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "cyan"}
    for f in results:
        sev_style = sev_colors.get(f.severity, "white")
        table.add_row(
            str(f.id),
            f"[{sev_style}]{(f.severity or '?').upper()}[/{sev_style}]",
            f.vuln_type or "?",
            f.title[:40],
            (f.url or "")[:30],
            f.status or "new",
            f.tool_source or "?",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(results)} findings[/dim]")


# ============================================================================
# Burp Suite Integration
# ============================================================================

@main.group()
def burp():
    """Burp Suite integration commands."""
    pass


@burp.command("status")
@click.pass_context
def burp_status(ctx):
    """Check Burp Suite connection."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.burpsuite import BurpSuiteClient
    client = BurpSuiteClient(engine.config)

    if client.is_connected():
        console.print("[green]Burp Suite is connected![/green]")
        version = client.get_version()
        if version:
            console.print(f"Version: {version}")
    else:
        console.print("[red]Cannot connect to Burp Suite[/red]")
        console.print(f"[dim]URL: {client.base_url}[/dim]")
        console.print("[dim]Make sure Burp is running with REST API enabled[/dim]")


@burp.command("import")
@click.pass_context
def burp_import(ctx):
    """Import findings from Burp Suite."""
    engine = get_engine(ctx)
    results = run_async(engine.import_from_burp())
    console.print(f"[green]Imported {len(results)} findings from Burp Suite[/green]")


@burp.command("scan")
@click.argument("urls", nargs=-1)
@click.pass_context
def burp_scan(ctx, urls):
    """Launch a Burp Suite scan."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.burpsuite import BurpSuiteClient
    client = BurpSuiteClient(engine.config)

    task_id = client.launch_scan(list(urls))
    if task_id:
        console.print(f"[green]Scan launched: {task_id}[/green]")
        if Confirm.ask("Wait for scan to complete?"):
            result = client.wait_for_scan(task_id)
            if result:
                console.print(f"[green]Scan completed: {result.get('scan_status')}[/green]")
    else:
        console.print("[red]Failed to launch scan[/red]")


@burp.command("scope")
@click.argument("url")
@click.option("--add/--remove", default=True)
@click.pass_context
def burp_scope(ctx, url, add):
    """Add or remove URL from Burp scope."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.burpsuite import BurpSuiteClient
    client = BurpSuiteClient(engine.config)

    if add:
        client.add_to_scope(url)
        console.print(f"[green]Added to Burp scope: {url}[/green]")
    else:
        client.remove_from_scope(url)
        console.print(f"[yellow]Removed from Burp scope: {url}[/yellow]")


# ============================================================================
# ZAP Integration
# ============================================================================

@main.group()
def zap():
    """OWASP ZAP integration commands."""
    pass


@zap.command("status")
@click.pass_context
def zap_status(ctx):
    """Check ZAP connection."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.zap import ZAPClient
    client = ZAPClient(engine.config)

    if client.is_connected():
        version = client.get_version()
        console.print(f"[green]ZAP connected! Version: {version}[/green]")
    else:
        console.print("[red]Cannot connect to ZAP[/red]")


@zap.command("import")
@click.pass_context
def zap_import(ctx):
    """Import alerts from OWASP ZAP."""
    engine = get_engine(ctx)
    results = run_async(engine.import_from_zap())
    console.print(f"[green]Imported {len(results)} findings from ZAP[/green]")


@zap.command("scan")
@click.argument("target_url")
@click.pass_context
def zap_scan(ctx, target_url):
    """Run a full ZAP scan (spider + active scan)."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.zap import ZAPClient
    client = ZAPClient(engine.config)

    console.print(f"[cyan]Starting full ZAP scan on {target_url}...[/cyan]")
    results = client.full_scan(target_url)
    console.print(f"[green]ZAP scan complete: {len(results['spider_urls'])} URLs, {len(results['alerts'])} alerts[/green]")


# ============================================================================
# JS Analysis
# ============================================================================

@main.command("js-analyze")
@click.argument("url_or_file")
@click.option("--ai/--no-ai", default=True, help="Enable AI analysis")
@click.pass_context
def js_analyze(ctx, url_or_file, ai):
    """Analyze JavaScript file(s) for security issues."""
    engine = get_engine(ctx)
    from wardenstrike.modules.recon.js_analyzer import JSAnalyzer
    analyzer = JSAnalyzer(engine.config, engine.ai if ai else None)

    if url_or_file.startswith("http"):
        results = run_async(analyzer.analyze_single(url_or_file))
    else:
        # Read from file (list of URLs)
        urls = Path(url_or_file).read_text().strip().split("\n")
        results = run_async(analyzer.run(urls, ai_analysis=ai))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    static = results.get("static", results)
    console.print(Panel(
        f"Endpoints: {len(static.get('endpoints', []))}\n"
        f"Secrets: {len(static.get('secrets', []))}\n"
        f"Vulnerabilities: {len(static.get('vulnerabilities', []))}\n"
        f"Auth Patterns: {len(static.get('auth_patterns', []))}\n"
        f"Source Maps: {len(static.get('source_maps', []))}",
        title="JS Analysis Results",
        border_style="cyan",
    ))

    # Show secrets if found
    for secret in static.get("secrets", []):
        console.print(f"  [red]SECRET[/red] [{secret['type']}] {secret['value']}")

    # Show endpoints
    for ep in static.get("endpoints", [])[:20]:
        console.print(f"  [cyan]ENDPOINT[/cyan] {ep['value']}")


# ============================================================================
# Hunt (Full Pipeline)
# ============================================================================

@main.command()
@click.argument("target")
@click.option("--quick", "-q", is_flag=True, help="Quick mode")
@click.option("--recon-only", is_flag=True, help="Only run recon")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis")
@click.pass_context
def hunt(ctx, target, quick, recon_only, no_ai):
    """Full hunting pipeline: recon → scan → analyze → validate."""
    print_banner()
    engine = get_engine(ctx)

    if not engine.engagement:
        engine.create_engagement(f"hunt_{target}", scope=[target])

    console.print(f"\n[bold cyan]Target: {target}[/bold cyan]\n")

    # Phase 1: Recon
    log.phase("HUNTING PHASE 1", "Reconnaissance")
    recon_results = run_async(engine.run_recon(target, quick=quick))

    if recon_only:
        console.print("[green]Recon complete. Use 'wardenstrike scan' to continue.[/green]")
        return

    # Phase 2: Vulnerability Scanning
    log.phase("HUNTING PHASE 2", "Vulnerability Scanning")
    scan_results = run_async(engine.run_scan())

    if no_ai:
        console.print("[green]Hunt complete (no AI analysis).[/green]")
        return

    # Phase 3: AI Analysis
    log.phase("HUNTING PHASE 3", "AI-Powered Analysis")
    analysis = engine.analyze_findings()

    # Phase 4: Exploit Chain Discovery
    log.phase("HUNTING PHASE 4", "Exploit Chain Discovery")
    chains_result = engine.find_chains()

    # Phase 5: Validation
    log.phase("HUNTING PHASE 5", "Validation")
    from wardenstrike.modules.exploit.validator import ExploitValidator
    validator = ExploitValidator(engine.config, engine.db, engine.ai)
    eng = engine._require_engagement()
    validation = run_async(validator.validate_all_new(eng.id))

    # Final Summary
    stats = engine.db.get_finding_stats(eng.id)
    confirmed = sum(1 for v in validation if v["overall"] == "confirmed")
    chain_count = len(chains_result.get("chains", []))

    console.print(Panel(
        f"[bold green]Hunt Complete![/bold green]\n\n"
        f"Target: {target}\n"
        f"Subdomains: {len(recon_results.get('subdomains', []))}\n"
        f"Live Hosts: {len(recon_results.get('live_hosts', []))}\n"
        f"Total Findings: {stats['total']}\n"
        f"Confirmed: {confirmed}\n"
        f"Exploit Chains: {chain_count}\n\n"
        f"[dim]Use 'wardenstrike findings' to see all findings[/dim]\n"
        f"[dim]Use 'wardenstrike report finding <ID>' to generate reports[/dim]",
        title="Hunt Summary",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
