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


# ============================================================================
# Cloud Security
# ============================================================================

@main.group()
def cloud():
    """Cloud security assessment (AWS / GCP / Azure)."""
    pass


@cloud.command("aws")
@click.option("--profile", "-p", default="default", help="AWS CLI profile")
@click.option("--region", "-r", default="us-east-1", help="AWS region")
@click.pass_context
def cloud_aws(ctx, profile, region):
    """Run AWS security assessment."""
    print_banner()
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.modules.cloud.cloud_engine import CloudEngine
    cloud_engine = CloudEngine(engine.config, engine.db, eng.id)

    console.print(f"[cyan]Starting AWS scan (profile={profile}, region={region})...[/cyan]")
    results = run_async(cloud_engine.scan_aws(profile, region))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]AWS Scan Complete![/bold]\n\n"
        f"Critical: [bold red]{summary.get('critical', 0)}[/bold red]\n"
        f"High: [red]{summary.get('high', 0)}[/red]\n"
        f"Medium: [yellow]{summary.get('medium', 0)}[/yellow]\n"
        f"Low: [blue]{summary.get('low', 0)}[/blue]\n\n"
        f"Total findings: {summary.get('total', 0)}",
        title="AWS Assessment Results", border_style="red"
    ))


@cloud.command("gcp")
@click.option("--project", "-p", help="GCP project ID")
@click.pass_context
def cloud_gcp(ctx, project):
    """Run GCP security assessment."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.modules.cloud.cloud_engine import CloudEngine
    cloud_engine = CloudEngine(engine.config, engine.db, eng.id)
    results = run_async(cloud_engine.scan_gcp(project))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]GCP Scan Complete![/bold] Total: {summary.get('total', 0)} findings",
        title="GCP Assessment", border_style="red"
    ))


@cloud.command("azure")
@click.option("--subscription", "-s", help="Azure subscription ID")
@click.pass_context
def cloud_azure(ctx, subscription):
    """Run Azure security assessment."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.modules.cloud.cloud_engine import CloudEngine
    cloud_engine = CloudEngine(engine.config, engine.db, eng.id)
    results = run_async(cloud_engine.scan_azure(subscription))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]Azure Scan Complete![/bold] Total: {summary.get('total', 0)} findings",
        title="Azure Assessment", border_style="red"
    ))


@cloud.command("all")
@click.option("--aws-profile", default="default")
@click.option("--aws-region", default="us-east-1")
@click.option("--gcp-project", default=None)
@click.option("--azure-sub", default=None)
@click.pass_context
def cloud_all(ctx, aws_profile, aws_region, gcp_project, azure_sub):
    """Run multi-cloud assessment (AWS + GCP + Azure) in parallel."""
    print_banner()
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.modules.cloud.cloud_engine import CloudEngine
    cloud_engine = CloudEngine(engine.config, engine.db, eng.id)

    console.print("[cyan]Starting multi-cloud assessment...[/cyan]")
    results = run_async(cloud_engine.scan_all(aws_profile, aws_region, gcp_project, azure_sub))

    combined = results.get("combined_summary", {})
    console.print(Panel(
        f"[bold]Multi-Cloud Scan Complete![/bold]\n\n"
        f"Providers scanned: {', '.join(combined.get('providers_scanned', []))}\n"
        f"Total findings: {combined.get('total_findings', 0)}\n"
        f"Failed: {', '.join(combined.get('providers_failed', [])) or 'none'}",
        title="Multi-Cloud Results", border_style="red"
    ))


# ============================================================================
# OSINT
# ============================================================================

@main.command()
@click.argument("target")
@click.option("--deep", "-d", is_flag=True, help="Deep OSINT (GitHub, breaches, Shodan)")
@click.pass_context
def osint(ctx, target, deep):
    """Run OSINT collection on a target domain/organization."""
    print_banner()
    engine = get_engine(ctx)

    if not engine.engagement:
        engine.create_engagement(f"osint_{target}", scope=[target])

    from wardenstrike.modules.osint.osint_engine import OSINTEngine
    eng = engine._require_engagement()
    osint_engine = OSINTEngine(engine.config, engine.db, eng.id)

    console.print(f"[cyan]Collecting OSINT for: {target}[/cyan]")
    results = run_async(osint_engine.run(target, deep=deep))

    console.print(Panel(
        f"[bold]OSINT Collection Complete![/bold]\n\n"
        f"Subdomains (CT logs): {len(results.get('subdomains_ct', []))}\n"
        f"Emails found: {len(results.get('emails', []))}\n"
        f"Google dorks ready: {len(results.get('google_dorks', []))}\n"
        f"Shodan dorks ready: {len(results.get('shodan_dorks', []))}\n"
        f"High-value findings: {results.get('summary', {}).get('high_severity', 0)}\n\n"
        f"[dim]WHOIS Registrar: {results.get('whois', {}).get('registrar', 'N/A')}[/dim]",
        title=f"OSINT Results: {target}", border_style="cyan"
    ))

    # AI analysis
    if engine.ai and results.get("raw_findings"):
        console.print("[cyan]Running AI intelligence analysis...[/cyan]")
        ai_intel = engine.ai.analyze_osint(results, target)
        if "attack_plan" in ai_intel:
            console.print(Panel(
                f"[bold]AI Recommended Attack Plan:[/bold]\n{ai_intel.get('attack_plan', '')}",
                border_style="yellow"
            ))


# ============================================================================
# Active Directory / Internal
# ============================================================================

@main.group()
def ad():
    """Active Directory and internal network assessment."""
    pass


@ad.command("scan")
@click.argument("domain")
@click.option("--dc", help="Domain Controller IP")
@click.option("--username", "-u", help="Domain username")
@click.option("--password", "-p", help="Domain password")
@click.option("--network", "-n", help="Network range for scanning (e.g. 192.168.1.0/24)")
@click.pass_context
def ad_scan(ctx, domain, dc, username, password, network):
    """Run Active Directory security assessment."""
    print_banner()
    engine = get_engine(ctx)

    if not engine.engagement:
        engine.create_engagement(f"ad_{domain}", scope=[domain])

    from wardenstrike.modules.internal.ad_engine import ADEngine
    eng = engine._require_engagement()
    ad_engine = ADEngine(engine.config, engine.db, eng.id)

    console.print(f"[cyan]Starting AD assessment: {domain}[/cyan]")
    results = run_async(ad_engine.run_full_scan(
        domain=domain, dc_ip=dc, username=username or "",
        password=password or "", network_range=network
    ))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]AD Assessment Complete![/bold]\n\n"
        f"Domain: {domain}\n"
        f"DC IP: {results.get('dc_ip', 'auto')}\n"
        f"Critical findings: [bold red]{summary.get('critical', 0)}[/bold red]\n"
        f"High findings: [red]{summary.get('high', 0)}[/red]\n"
        f"Attack paths identified: {len(summary.get('attack_paths', []))}\n\n"
        + ("\n".join(f"  → {p}" for p in summary.get('attack_paths', [])[:5]) if summary.get('attack_paths') else ""),
        title="AD Assessment Results", border_style="red"
    ))

    # AI analysis
    if engine.ai and results.get("findings"):
        console.print("[cyan]Running AI attack path analysis...[/cyan]")
        ai_results = engine.ai.analyze_ad_findings(results["findings"], domain)
        if ai_results.get("immediate_escalation"):
            console.print(Panel(
                f"[bold red]AI Identified Fastest Path to DA:[/bold red]\n"
                f"{ai_results.get('immediate_escalation', 'N/A')}",
                border_style="red"
            ))


# ============================================================================
# GraphQL Scanner
# ============================================================================

@main.command("graphql")
@click.argument("target_url")
@click.option("--header", "-H", multiple=True, help="Custom headers (e.g. 'Authorization: Bearer xxx')")
@click.option("--no-discover", is_flag=True, help="Don't auto-discover endpoints")
@click.pass_context
def graphql_scan(ctx, target_url, header, no_discover):
    """Run GraphQL security assessment."""
    engine = get_engine(ctx)

    from wardenstrike.modules.scanner.graphql import GraphQLScanner
    scanner = GraphQLScanner(engine.config, engine.ai)

    # Parse headers
    headers = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    console.print(f"[cyan]GraphQL scan: {target_url}[/cyan]")
    results = run_async(scanner.scan(target_url, headers=headers, discover=not no_discover))

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]GraphQL Scan Complete![/bold]\n\n"
        f"Endpoints tested: {summary.get('endpoints_tested', 0)}\n"
        f"Schema discovered: {'Yes' if results.get('schema_available') else 'No'}\n"
        f"Critical: [bold red]{summary.get('critical', 0)}[/bold red]\n"
        f"High: [red]{summary.get('high', 0)}[/red]\n"
        f"Total findings: {summary.get('total_findings', 0)}",
        title="GraphQL Results", border_style="cyan"
    ))

    for f in results.get("findings", [])[:10]:
        sev_color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(f.get("severity", ""), "white")
        console.print(f"  [{sev_color}][{f.get('severity','?').upper()}][/{sev_color}] {f.get('issue', '?')}")


# ============================================================================
# JWT Attacks
# ============================================================================

@main.command("jwt")
@click.argument("token")
@click.option("--endpoint", "-e", help="Endpoint to test token against")
@click.option("--public-key", help="RSA public key for confusion attack")
@click.pass_context
def jwt_attack(ctx, token, endpoint, public_key):
    """Analyze and attack a JWT token."""
    engine = get_engine(ctx)

    from wardenstrike.modules.scanner.jwt_attacks import JWTAttackSuite
    suite = JWTAttackSuite(engine.config, engine.ai)

    console.print("[cyan]Running JWT attack suite...[/cyan]")
    results = run_async(suite.test_token(token, endpoint, public_key))

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    console.print(Panel(
        f"Algorithm: [bold]{results.get('algorithm', '?')}[/bold]\n"
        f"Secret cracked: {'[bold red]YES - ' + str(results.get('secret_found')) + '[/bold red]' if results.get('secret_found') else '[green]No[/green]'}\n"
        f"alg:none tokens crafted: {len(results.get('none_tokens', []))}\n"
        f"kid attacks: {len(results.get('kid_attacks', []))}\n"
        f"Total issues: {results.get('summary', {}).get('total_issues', 0)}",
        title="JWT Analysis", border_style="cyan"
    ))

    for f in results.get("findings", []):
        if f.get("severity") in ("critical", "high"):
            console.print(f"  [bold red][{f.get('severity','?').upper()}][/bold red] {f.get('attack', '?')}")
            if f.get("crafted_token"):
                console.print(f"    Token: [dim]{f['crafted_token'][:80]}...[/dim]")


# ============================================================================
# OAuth Tester
# ============================================================================

@main.command()
@click.argument("target")
@click.option("--client-id", help="OAuth client_id")
@click.option("--redirect-uri", help="Registered redirect_uri")
@click.option("--auth-endpoint", help="Authorization endpoint URL")
@click.pass_context
def oauth(ctx, target, client_id, redirect_uri, auth_endpoint):
    """Run OAuth 2.0 / OIDC security assessment."""
    engine = get_engine(ctx)

    from wardenstrike.modules.scanner.oauth_tester import OAuthTester
    tester = OAuthTester(engine.config, engine.ai)

    console.print(f"[cyan]OAuth assessment: {target}[/cyan]")
    results = run_async(tester.test(
        target=target, client_id=client_id or "",
        redirect_uri=redirect_uri or "", auth_endpoint=auth_endpoint or ""
    ))

    console.print(Panel(
        f"[bold]OAuth Assessment Complete![/bold]\n\n"
        f"Discovery: {'Found' if results.get('discovery') else 'Not found'}\n"
        f"Critical: [bold red]{results.get('summary', {}).get('critical', 0)}[/bold red]\n"
        f"High: [red]{results.get('summary', {}).get('high', 0)}[/red]\n"
        f"Total: {results.get('summary', {}).get('total', 0)}",
        title="OAuth Results", border_style="cyan"
    ))

    for f in results.get("findings", []):
        console.print(f"  [{f.get('severity','info')}] {f.get('issue', '?')}")


# ============================================================================
# Web3 / Smart Contracts
# ============================================================================

@main.group()
def web3():
    """Web3 / Smart contract security audit."""
    pass


@web3.command("audit")
@click.argument("contract_path")
@click.option("--name", "-n", default="Contract", help="Contract name")
@click.option("--no-tools", is_flag=True, help="Skip Slither/Mythril")
@click.pass_context
def web3_audit(ctx, contract_path, name, no_tools):
    """Audit a Solidity smart contract."""
    engine = get_engine(ctx)
    from wardenstrike.modules.web3.contract_analyzer import ContractAnalyzer
    from pathlib import Path

    analyzer = ContractAnalyzer(engine.config, engine.ai)

    console.print(f"[cyan]Auditing contract: {contract_path}[/cyan]")
    source = Path(contract_path).read_text()
    results = run_async(analyzer.audit(
        source_code=source, contract_path=contract_path,
        contract_name=name, use_tools=not no_tools
    ))

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]Smart Contract Audit Complete![/bold]\n\n"
        f"Lines of code: {results.get('loc', 0)}\n"
        f"Critical: [bold red]{summary.get('critical', 0)}[/bold red]\n"
        f"High: [red]{summary.get('high', 0)}[/red]\n"
        f"Medium: [yellow]{summary.get('medium', 0)}[/yellow]\n"
        f"PoC templates: {len(results.get('poc_templates', {}))}",
        title="Web3 Audit Results", border_style="magenta"
    ))

    for f in results.get("findings", []):
        if f.get("severity") in ("critical", "high"):
            console.print(f"  [bold red][{f.get('severity','?').upper()}][/bold red] {f.get('bug_class','?')}: {f.get('description','?')[:80]}")
            if f.get("location"):
                console.print(f"    Location: [dim]{f['location']}[/dim]")


# ============================================================================
# Monitor
# ============================================================================

@main.group()
def monitor():
    """Continuous asset monitoring."""
    pass


@monitor.command("run")
@click.argument("targets", nargs=-1)
@click.option("--scope-file", type=click.Path(exists=True), help="File with targets (one per line)")
@click.pass_context
def monitor_run(ctx, targets, scope_file):
    """Run monitoring check on targets."""
    from wardenstrike.modules.monitor.continuous import ContinuousMonitor

    all_targets = list(targets)
    if scope_file:
        from pathlib import Path
        all_targets += [t.strip() for t in Path(scope_file).read_text().split("\n") if t.strip()]

    if not all_targets:
        console.print("[red]No targets specified. Use arguments or --scope-file[/red]")
        return

    engine = get_engine(ctx)
    monitor_engine = ContinuousMonitor(engine.config)

    console.print(f"[cyan]Monitoring {len(all_targets)} targets...[/cyan]")
    results = run_async(monitor_engine.run(all_targets))

    summary = results.get("summary", {})
    console.print(Panel(
        f"[bold]Monitor Run Complete![/bold]\n\n"
        f"Targets checked: {summary.get('targets_checked', 0)}\n"
        f"New alerts: [bold]{summary.get('new_alerts', 0)}[/bold]\n"
        f"High severity: [red]{summary.get('high_severity', 0)}[/red]",
        title="Monitor Results", border_style="yellow"
    ))

    for alert in results.get("new_alerts", []):
        sev_color = "red" if alert.get("severity") == "high" else "yellow"
        console.print(f"  [{sev_color}][{alert.get('alert_type','?').upper()}][/{sev_color}] {alert.get('change','?')}")


@monitor.command("alerts")
@click.option("--target", help="Filter by target")
@click.option("--severity", "-s", type=click.Choice(["high", "medium", "low"]))
@click.option("--limit", default=50, type=int)
@click.pass_context
def monitor_alerts(ctx, target, severity, limit):
    """Show alert history from monitor database."""
    from wardenstrike.modules.monitor.continuous import ContinuousMonitor
    engine = get_engine(ctx)
    monitor_engine = ContinuousMonitor(engine.config)

    alerts = monitor_engine.get_alerts_history(target, severity, limit)

    table = Table(title="Monitor Alerts", header_style="bold yellow")
    table.add_column("ID", width=4)
    table.add_column("Type", width=20)
    table.add_column("Target", width=30)
    table.add_column("Change", max_width=50)
    table.add_column("Severity", width=8)
    table.add_column("Time", width=20)

    for alert in alerts:
        sev_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(alert.get("severity",""), "white")
        table.add_row(
            str(alert.get("id", "")),
            alert.get("alert_type", ""),
            alert.get("target", "")[:30],
            alert.get("change", "")[:50],
            f"[{sev_color}]{alert.get('severity','?').upper()}[/{sev_color}]",
            (alert.get("timestamp", "") or "")[:19],
        )

    console.print(table)


# ============================================================================
# Code Review
# ============================================================================

@main.command("code-review")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--language", "-l", default="auto", help="Programming language")
@click.pass_context
def code_review(ctx, file_path, language):
    """AI-powered security code review."""
    engine = get_engine(ctx)

    from pathlib import Path
    code = Path(file_path).read_text()

    if not engine.ai:
        console.print("[red]AI engine not configured. Set ANTHROPIC_API_KEY[/red]")
        return

    console.print(f"[cyan]Reviewing: {file_path}[/cyan]")
    results = engine.ai.review_code(code, language, file_path)

    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return

    vulns = results.get("vulnerabilities", [])
    secrets = results.get("hardcoded_secrets", [])

    console.print(Panel(
        f"[bold]Code Review Complete![/bold]\n\n"
        f"Security score: {results.get('security_score', '?')}/10\n"
        f"Vulnerabilities: {len(vulns)}\n"
        f"Hardcoded secrets: [bold red]{len(secrets)}[/bold red]\n\n"
        f"{results.get('summary', '')}",
        title=f"Code Review: {file_path}", border_style="cyan"
    ))

    for v in vulns:
        sev_color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(v.get("severity",""), "white")
        console.print(f"\n  [{sev_color}][{v.get('severity','?').upper()}][/{sev_color}] Line {v.get('line','?')}: {v.get('type','?')} ({v.get('cwe','')})")
        console.print(f"    {v.get('description','')}")
        if v.get("fix"):
            console.print(f"    [dim]Fix: {v['fix'][:100]}[/dim]")

    for s in secrets:
        console.print(f"\n  [bold red][SECRET][/bold red] Line {s.get('line','?')}: {s.get('type','?')} — {s.get('value_preview','?')}")


# ============================================================================
# Nessus Integration
# ============================================================================

@main.group()
def nessus():
    """Nessus vulnerability scanner integration."""
    pass


@nessus.command("status")
@click.pass_context
def nessus_status(ctx):
    """Check Nessus connection."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.nessus import NessusClient
    client = NessusClient(engine.config)
    client.login()
    if client.is_connected():
        info = client.get_server_info()
        console.print(f"[green]Nessus connected![/green] Version: {info.get('nessus_ui_version', '?')}")
    else:
        console.print("[red]Cannot connect to Nessus[/red]")


@nessus.command("import")
@click.argument("scan_id", type=int)
@click.pass_context
def nessus_import(ctx, scan_id):
    """Import findings from a Nessus scan."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.integrations.nessus import NessusClient
    client = NessusClient(engine.config)
    client.login()

    findings = client.import_to_wardenstrike(scan_id, engine.db, eng.id)
    console.print(f"[green]Imported {len(findings)} findings from Nessus scan {scan_id}[/green]")


@nessus.command("scan")
@click.argument("targets", nargs=-1)
@click.option("--name", "-n", required=True, help="Scan name")
@click.option("--template", "-t", default="basic", help="Scan template")
@click.option("--wait", is_flag=True, help="Wait for scan to complete")
@click.pass_context
def nessus_scan(ctx, targets, name, template, wait):
    """Launch a Nessus scan."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.nessus import NessusClient
    client = NessusClient(engine.config)
    client.login()

    scan = client.create_scan(name, list(targets), template=template)
    if not scan:
        console.print("[red]Failed to create scan[/red]")
        return

    scan_id = scan.get("id")
    uuid = client.launch_scan(scan_id)
    console.print(f"[green]Scan launched: ID={scan_id}, UUID={uuid}[/green]")

    if wait:
        console.print("[cyan]Waiting for scan to complete...[/cyan]")
        result = client.wait_for_scan(scan_id)
        console.print(f"[green]Scan complete: {result.get('info', {}).get('status', '?')}[/green]")


# ============================================================================
# Metasploit Integration
# ============================================================================

@main.group()
def msf():
    """Metasploit Framework integration."""
    pass


@msf.command("status")
@click.pass_context
def msf_status(ctx):
    """Check Metasploit connection."""
    engine = get_engine(ctx)
    from wardenstrike.integrations.metasploit import MetasploitClient
    client = MetasploitClient(engine.config)
    if client.connect():
        console.print(f"[green]Metasploit connected![/green] Version: {client.get_version()}")
    else:
        console.print("[red]Cannot connect to Metasploit MSFRPC[/red]")
        console.print("[dim]Start MSFRPC: msfrpcd -P msfrpc_password -S -a 127.0.0.1[/dim]")


@msf.command("correlate")
@click.pass_context
def msf_correlate(ctx):
    """Correlate findings with Metasploit exploit availability."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    from wardenstrike.integrations.metasploit import MetasploitClient
    client = MetasploitClient(engine.config)
    if not client.connect():
        console.print("[red]Cannot connect to Metasploit[/red]")
        return

    findings = engine.db.get_findings(eng.id, severity="high")
    enriched = client.correlate_findings([vars(f) for f in findings] if hasattr(findings[0], '__dict__') else findings)

    exploitable = [f for f in enriched if f.get("exploitable")]
    console.print(f"[bold red]{len(exploitable)} findings have Metasploit modules![/bold red]")
    for f in exploitable:
        console.print(f"  [red]•[/red] {f.get('title','?')}: {f.get('exploit_count', 0)} modules")


# ============================================================================
# AI Commands
# ============================================================================

@main.group()
def ai():
    """AI-powered analysis commands."""
    pass


@ai.command("chain")
@click.pass_context
def ai_chain(ctx):
    """Build exploit chains from current engagement findings using AI."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    if not engine.ai:
        console.print("[red]AI not configured. Set ANTHROPIC_API_KEY[/red]")
        return

    findings_raw = engine.db.get_findings(eng.id)
    findings = [dict(f) if hasattr(f, '__dict__') else f for f in findings_raw]

    console.print(f"[cyan]Building exploit chains from {len(findings)} findings...[/cyan]")
    result = engine.ai.build_exploit_chain(findings)

    chains = result.get("chains", [])
    if not chains:
        console.print("[yellow]No exploit chains identified[/yellow]")
        return

    for chain in chains:
        console.print(Panel(
            f"[bold]{chain.get('name','?')}[/bold]\n\n"
            f"Objective: {chain.get('objective_achieved','?')}\n"
            f"Severity: {chain.get('combined_severity','?')}\n"
            f"Feasibility: {chain.get('feasibility','?')}\n"
            f"Est. Bounty: {chain.get('estimated_bounty','?')}\n\n"
            f"Steps:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(chain.get('steps', []))),
            border_style="red"
        ))

    if result.get("chain_diagram"):
        console.print(Panel(result["chain_diagram"], title="Chain Diagram"))


@ai.command("cloud-analyze")
@click.option("--provider", default="AWS", type=click.Choice(["AWS", "GCP", "Azure"]))
@click.pass_context
def ai_cloud_analyze(ctx, provider):
    """AI analysis of cloud findings."""
    engine = get_engine(ctx)
    eng = engine._require_engagement()

    findings_raw = engine.db.get_findings(eng.id, vuln_type=f"cloud_{provider.lower()}")
    findings = [dict(f) if hasattr(f, '__dict__') else f for f in findings_raw]

    if not findings:
        console.print(f"[yellow]No {provider} findings to analyze. Run 'wardenstrike cloud {provider.lower()}' first.[/yellow]")
        return

    result = engine.ai.analyze_cloud_findings(findings, provider)
    console.print(Panel(
        f"[bold]AI Cloud Analysis - {provider}[/bold]\n\n"
        f"Overall Risk: [bold red]{result.get('overall_risk', '?').upper()}[/bold red]\n\n"
        f"{result.get('executive_summary', '')}",
        border_style="red"
    ))

    for chain in result.get("critical_chains", []):
        console.print(f"\n[bold red]Critical Chain:[/bold red] {chain.get('chain','?')}")


if __name__ == "__main__":
    main()
