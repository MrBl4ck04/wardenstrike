"""
WardenStrike - Logging System
Rich-based colored logging with file output support.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text

WARDENSTRIKE_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "target": "bold magenta",
    "vuln.critical": "bold white on red",
    "vuln.high": "bold red",
    "vuln.medium": "bold yellow",
    "vuln.low": "bold blue",
    "vuln.info": "bold cyan",
    "header": "bold white",
    "dim": "dim",
    "highlight": "bold cyan",
})

console = Console(theme=WARDENSTRIKE_THEME, stderr=True)


class WardenStrikeLogger:
    """Custom logger with Rich formatting and file output."""

    def __init__(self, name: str = "wardenstrike", log_file: str | None = None, verbose: bool = False):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()

        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.addHandler(rich_handler)

        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            ))
            self.logger.addHandler(file_handler)

    def info(self, msg: str, **kwargs):
        self.logger.info(msg, **kwargs)

    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg, **kwargs)

    def error(self, msg: str, **kwargs):
        self.logger.error(msg, **kwargs)

    def critical(self, msg: str, **kwargs):
        self.logger.critical(msg, **kwargs)

    def success(self, msg: str):
        console.print(f"  [success]SUCCESS[/success] {msg}")

    def target(self, msg: str):
        console.print(f"  [target]TARGET[/target] {msg}")

    def vuln(self, severity: str, msg: str):
        style = f"vuln.{severity.lower()}"
        console.print(f"  [{style}]{severity.upper()}[/{style}] {msg}")

    def finding(self, title: str, severity: str, url: str = "", details: str = ""):
        sev_colors = {
            "critical": "bold white on red",
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold blue",
            "info": "bold cyan",
        }
        color = sev_colors.get(severity.lower(), "white")
        panel_content = Text()
        panel_content.append(f"Severity: ", style="bold")
        panel_content.append(f"{severity.upper()}\n", style=color)
        if url:
            panel_content.append(f"URL: ", style="bold")
            panel_content.append(f"{url}\n", style="underline cyan")
        if details:
            panel_content.append(f"\n{details}")
        console.print(Panel(panel_content, title=f"[bold]{title}[/bold]", border_style=color))

    def phase(self, phase_name: str, description: str = ""):
        console.print()
        console.print(f"  [header]{'='*60}[/header]")
        console.print(f"  [highlight]  {phase_name}[/highlight]")
        if description:
            console.print(f"  [dim]  {description}[/dim]")
        console.print(f"  [header]{'='*60}[/header]")
        console.print()

    def stats(self, data: dict):
        for key, value in data.items():
            console.print(f"  [dim]{key}:[/dim] [bold]{value}[/bold]")


def get_logger(name: str = "wardenstrike", **kwargs) -> WardenStrikeLogger:
    return WardenStrikeLogger(name, **kwargs)


def print_banner():
    banner = r"""
[bold red]
 __        ___    ____  ____  _____ _   _
 \ \      / / \  |  _ \|  _ \| ____| \ | |
  \ \ /\ / / _ \ | |_) | | | |  _| |  \| |
   \ V  V / ___ \|  _ <| |_| | |___| |\  |
    \_/\_/_/   \_\_| \_\____/|_____|_| \_|
[/bold red][bold cyan]
 ____ _____ ____  ___ _  _______
/ ___|_   _|  _ \|_ _| |/ / ____|
\___ \ | | | |_) || || ' /|  _|
 ___) || | |  _ < | || . \| |___
|____/ |_| |_| \_\___|_|\_\_____|
[/bold cyan]
[bold white]  AI-Powered Pentesting Framework[/bold white]   [dim]v1.0.0[/dim]
[dim]  by Warden Security | mrbl4ck[/dim]
"""
    console.print(banner)
