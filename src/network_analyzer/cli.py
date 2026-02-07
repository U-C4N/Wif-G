import sys
import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .app import NetworkAnalyzerEngine, AnalysisResults
from .history import ScanHistory

logger = logging.getLogger(__name__)

# Try to use rich; fall back to colorama if not available
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from colorama import init, Fore, Back, Style

init(autoreset=True)


class NetworkAnalyzerCLI:
    """UI layer - handles all terminal output and user interaction.

    Uses `rich` library for enhanced TUI when available,
    falls back to colorama-based output otherwise.
    """

    def __init__(self, engine: NetworkAnalyzerEngine):
        self._engine = engine
        if HAS_RICH:
            self._console = Console()
        else:
            self._console = None

    # ------------------------------------------------------------------ #
    #  Banner
    # ------------------------------------------------------------------ #
    def print_banner(self) -> None:
        if HAS_RICH:
            banner_text = Text()
            banner_text.append(
                "    _   _      _                      _\n"
                "   | \\ | | ___| |___      _____  _ __| | __\n"
                "   |  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ /\n"
                "   | |\\  |  __/ |_ \\ V  V / (_) | |  |   <\n"
                "   |_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\\n"
                "        / \\   _ __   __ _| |_   _ _______ _ __\n"
                "       / _ \\ | '_ \\ / _` | | | | |_  / _ \\ '__|\n"
                "      / ___ \\| | | | (_| | | |_| |/ /  __/ |\n"
                "     /_/   \\_\\_| |_|\\__,_|_|\\__, /___\\___|_|\n"
                "                            |___/\n",
                style="bold white"
            )
            banner_text.append(
                "   Network Security Analysis and Optimization Tool v2.0",
                style="bold yellow"
            )
            panel = Panel(
                Align.center(banner_text),
                border_style="cyan",
                padding=(1, 2),
            )
            self._console.print(panel)
        else:
            banner = f"""
{Fore.CYAN}{'=' * 62}
{Fore.WHITE}{Style.BRIGHT}
    _   _      _                      _
   | \\ | | ___| |___      _____  _ __| | __
   |  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ /
   | |\\  |  __/ |_ \\ V  V / (_) | |  |   <
   |_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\
        / \\   _ __   __ _| |_   _ _______ _ __
       / _ \\ | '_ \\ / _` | | | | |_  / _ \\ '__|
      / ___ \\| | | | (_| | | |_| |/ /  __/ |
     /_/   \\_\\_| |_|\\__,_|_|\\__, /___\\___|_|
                            |___/

{Fore.YELLOW}   Network Security Analysis and Optimization Tool v2.0
{Fore.CYAN}{'=' * 62}
"""
            print(banner)

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def print_section(self, title: str) -> None:
        if HAS_RICH:
            self._console.print()
            self._console.print(Rule(title, style="cyan"))
        else:
            print(f"\n{Fore.CYAN}{'=' * 60}")
            print(f"{Fore.WHITE}{Style.BRIGHT}  {title}")
            print(f"{Fore.CYAN}{'=' * 60}")

    def print_loading(self, message: str) -> None:
        if HAS_RICH:
            self._console.print(f"[yellow][*] {message}...[/yellow]", end="")
        else:
            print(f"{Fore.YELLOW}[*] {message}...", end='', flush=True)

    def print_done(self) -> None:
        if HAS_RICH:
            self._console.print(" [bold green][DONE][/bold green]")
        else:
            print(f" {Fore.GREEN}[DONE]")

    def print_info(self, key: str, value: str) -> None:
        if HAS_RICH:
            self._console.print(f"  [white]{key}:[/white] [green]{value}[/green]")
        else:
            print(f"  {Fore.WHITE}{key}: {Fore.GREEN}{value}")

    def print_warning(self, message: str) -> None:
        if HAS_RICH:
            self._console.print(f"  [yellow][!] {message}[/yellow]")
        else:
            print(f"  {Fore.YELLOW}[!] {message}")

    def print_danger(self, message: str) -> None:
        if HAS_RICH:
            self._console.print(f"  [bold red][!!!] {message}[/bold red]")
        else:
            print(f"  {Fore.RED}[!!!] {message}")

    def print_success(self, message: str) -> None:
        if HAS_RICH:
            self._console.print(f"  [green][+] {message}[/green]")
        else:
            print(f"  {Fore.GREEN}[+] {message}")

    def _format_bytes(self, bytes_val: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} PB"

    # ------------------------------------------------------------------ #
    #  Progress context manager for rich progress bars
    # ------------------------------------------------------------------ #
    def create_progress(self):
        """Return a rich Progress context manager, or None if rich is unavailable."""
        if HAS_RICH:
            return Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[bold green]{task.percentage:>3.0f}%"),
                console=self._console,
            )
        return None

    # ------------------------------------------------------------------ #
    #  Network display
    # ------------------------------------------------------------------ #
    def display_network(self, data: Dict) -> None:
        self.print_section("NETWORK INFORMATION")

        ssid = data.get('ssid') or "Unknown"

        if HAS_RICH:
            # Network info panel
            info_lines = []
            info_lines.append(f"[white]WiFi SSID:[/white] [green]{ssid}[/green]")

            signal = data.get('signal_strength')
            if signal:
                if signal > -50:
                    color, label = "green", "Excellent"
                elif signal > -70:
                    color, label = "yellow", "Good"
                else:
                    color, label = "red", "Weak"
                info_lines.append(
                    f"[white]Signal Strength:[/white] [{color}]{signal} dBm ({label})[/{color}]"
                )

            info_lines.append(f"[white]Local IP:[/white] [green]{data.get('local_ip') or 'Unknown'}[/green]")
            info_lines.append(f"[white]Gateway:[/white] [green]{data.get('gateway') or 'Unknown'}[/green]")

            self._console.print(Panel(
                "\n".join(info_lines),
                title="Connection",
                border_style="cyan",
                padding=(0, 2),
            ))

            # Interfaces table
            interfaces = data.get('interfaces', {})
            if interfaces:
                tbl = Table(title="Network Interfaces", box=box.ROUNDED, border_style="cyan")
                tbl.add_column("Interface", style="cyan")
                tbl.add_column("IP Address", style="white")
                tbl.add_column("Netmask", style="white")
                for iface, info in interfaces.items():
                    tbl.add_row(iface, info['ip'], info['netmask'])
                self._console.print(tbl)

            # Stats
            stats = data.get('stats', {})
            if stats:
                stats_tbl = Table(title="Network Statistics", box=box.ROUNDED, border_style="cyan")
                stats_tbl.add_column("Metric", style="white")
                stats_tbl.add_column("Value", style="green")
                stats_tbl.add_row("Sent", self._format_bytes(stats.get('bytes_sent', 0)))
                stats_tbl.add_row("Received", self._format_bytes(stats.get('bytes_recv', 0)))
                stats_tbl.add_row("Errors In", str(stats.get('errors_in', 0)))
                stats_tbl.add_row("Errors Out", str(stats.get('errors_out', 0)))
                self._console.print(stats_tbl)
        else:
            self.print_info("WiFi SSID", ssid)

            signal = data.get('signal_strength')
            if signal:
                if signal > -50:
                    signal_str = f"{signal} dBm (Excellent)"
                    color = Fore.GREEN
                elif signal > -70:
                    signal_str = f"{signal} dBm (Good)"
                    color = Fore.YELLOW
                else:
                    signal_str = f"{signal} dBm (Weak)"
                    color = Fore.RED
                print(f"  {Fore.WHITE}Signal Strength: {color}{signal_str}")

            self.print_info("Local IP", data.get('local_ip') or "Unknown")
            self.print_info("Gateway", data.get('gateway') or "Unknown")

            interfaces = data.get('interfaces', {})
            if interfaces:
                print(f"\n  {Fore.WHITE}Network Interfaces:")
                for iface, info in interfaces.items():
                    print(f"    {Fore.CYAN}{iface}: {Fore.WHITE}{info['ip']} ({info['netmask']})")

            stats = data.get('stats', {})
            if stats:
                print(f"\n  {Fore.WHITE}Network Statistics:")
                print(f"    {Fore.WHITE}Sent: {Fore.GREEN}{self._format_bytes(stats.get('bytes_sent', 0))}")
                print(f"    {Fore.WHITE}Received: {Fore.GREEN}{self._format_bytes(stats.get('bytes_recv', 0))}")
                print(f"    {Fore.WHITE}Errors: Incoming={stats.get('errors_in', 0)}, Outgoing={stats.get('errors_out', 0)}")

    # ------------------------------------------------------------------ #
    #  DNS display
    # ------------------------------------------------------------------ #
    def display_dns(self, data: Dict) -> None:
        self.print_section("DNS ANALYSIS")

        if HAS_RICH:
            tbl = Table(title="DNS Servers", box=box.ROUNDED, border_style="cyan")
            tbl.add_column("Server IP", style="cyan")
            tbl.add_column("Provider", style="white")
            tbl.add_column("Type", style="white")
            tbl.add_column("Response Time", style="white")

            for dns in data.get('servers', []):
                stype = "[green]PUBLIC DNS[/green]" if dns.get('is_public_resolver') else "[yellow]ISP/PRIVATE[/yellow]"
                response = f"{dns.get('response_time')}ms" if dns.get('response_time') else "N/A"
                tbl.add_row(dns['ip'], dns['provider'], stype, response)

            self._console.print(tbl)

            for warning in data.get('warnings', []):
                self.print_warning(warning)
        else:
            print(f"\n  {Fore.WHITE}Current DNS Servers:")
            for dns in data.get('servers', []):
                secure_status = f"{Fore.GREEN}[PUBLIC DNS]" if dns.get('is_public_resolver') else f"{Fore.YELLOW}[ISP/PRIVATE]"
                response = f"{dns.get('response_time')}ms" if dns.get('response_time') else "N/A"
                print(f"    {Fore.CYAN}{dns['ip']} {Fore.WHITE}({dns['provider']}) - {secure_status} - {response}")

            for warning in data.get('warnings', []):
                self.print_warning(warning)

    # ------------------------------------------------------------------ #
    #  Performance display
    # ------------------------------------------------------------------ #
    def display_performance(self, data: Dict) -> None:
        self.print_section("PERFORMANCE TESTS")

        if HAS_RICH:
            latency = data.get('latency', [])
            if latency:
                tbl = Table(title="Latency Results", box=box.ROUNDED, border_style="cyan")
                tbl.add_column("Target", style="cyan")
                tbl.add_column("Avg", style="white")
                tbl.add_column("Min", style="white")
                tbl.add_column("Max", style="white")

                for result in latency:
                    avg = result.get('avg_latency', -1)
                    if avg != -1:
                        avg_color = "green" if avg < 50 else ("yellow" if avg < 100 else "red")
                        tbl.add_row(
                            result['target'],
                            f"[{avg_color}]{avg}ms[/{avg_color}]",
                            f"{result.get('min_latency', 'N/A')}ms",
                            f"{result.get('max_latency', 'N/A')}ms",
                        )
                    else:
                        tbl.add_row(result['target'], "[red]Unreachable[/red]", "-", "-")

                self._console.print(tbl)

            # Jitter, packet loss, bandwidth as a summary panel
            summary_lines = []
            jitter = data.get('jitter', {})
            if jitter:
                j_val = jitter.get('jitter', -1)
                if j_val != -1:
                    j_color = "green" if j_val < 10 else ("yellow" if j_val < 30 else "red")
                    summary_lines.append(f"[white]Jitter:[/white] [{j_color}]{j_val}ms[/{j_color}] (samples: {jitter.get('samples', 0)})")
                else:
                    summary_lines.append("[white]Jitter:[/white] [red]Could not measure[/red]")

            pl = data.get('packet_loss', {})
            if pl:
                loss_pct = pl.get('loss_percentage', 0)
                loss_color = "green" if loss_pct == 0 else ("yellow" if loss_pct < 2 else "red")
                summary_lines.append(
                    f"[white]Packet Loss:[/white] [{loss_color}]{loss_pct}%[/{loss_color}] ({pl.get('received', 0)}/{pl.get('sent', 0)} received)"
                )

            bw = data.get('bandwidth', {})
            if bw:
                speed = bw.get('download_speed_mbps', 0)
                if speed > 0:
                    speed_color = "green" if speed > 10 else ("yellow" if speed > 1 else "red")
                    summary_lines.append(f"[white]Bandwidth:[/white] [{speed_color}]{speed:.2f} Mbps[/{speed_color}]")
                else:
                    summary_lines.append("[white]Bandwidth:[/white] [yellow]Could not determine[/yellow]")

            if summary_lines:
                self._console.print(Panel(
                    "\n".join(summary_lines),
                    title="Performance Summary",
                    border_style="cyan",
                    padding=(0, 2),
                ))
        else:
            latency = data.get('latency', [])
            if latency:
                print(f"\n  {Fore.WHITE}Latency Results:")
                print(f"  {'-' * 55}")
                print(f"  {Fore.WHITE}{'Target':<20} {'Avg':<12} {'Min':<12} {'Max':<12}")
                print(f"  {'-' * 55}")

                for result in latency:
                    avg = result.get('avg_latency', -1)
                    if avg != -1:
                        avg_color = Fore.GREEN if avg < 50 else (Fore.YELLOW if avg < 100 else Fore.RED)
                        print(f"  {Fore.CYAN}{result['target']:<20} {avg_color}{avg:<12}ms {Fore.WHITE}{result.get('min_latency', 'N/A'):<12}ms {result.get('max_latency', 'N/A'):<12}ms")
                    else:
                        print(f"  {Fore.CYAN}{result['target']:<20} {Fore.RED}{'Unreachable':<12}")

            jitter = data.get('jitter', {})
            if jitter:
                j_val = jitter.get('jitter', -1)
                if j_val != -1:
                    jitter_color = Fore.GREEN if j_val < 10 else (Fore.YELLOW if j_val < 30 else Fore.RED)
                    print(f"\n  {Fore.WHITE}Jitter: {jitter_color}{j_val}ms {Fore.WHITE}(samples: {jitter.get('samples', 0)})")
                else:
                    print(f"\n  {Fore.WHITE}Jitter: {Fore.RED}Could not measure")

            pl = data.get('packet_loss', {})
            if pl:
                loss_pct = pl.get('loss_percentage', 0)
                loss_color = Fore.GREEN if loss_pct == 0 else (Fore.YELLOW if loss_pct < 2 else Fore.RED)
                print(f"\n  {Fore.WHITE}Packet Loss: {loss_color}{loss_pct}% {Fore.WHITE}({pl.get('received', 0)}/{pl.get('sent', 0)} packets received)")

            bw = data.get('bandwidth', {})
            if bw:
                speed = bw.get('download_speed_mbps', 0)
                if speed > 0:
                    speed_color = Fore.GREEN if speed > 10 else (Fore.YELLOW if speed > 1 else Fore.RED)
                    print(f"\n  {Fore.WHITE}Bandwidth Estimate: {speed_color}{speed:.2f} Mbps")
                else:
                    print(f"\n  {Fore.WHITE}Bandwidth Estimate: {Fore.YELLOW}Could not determine")

    # ------------------------------------------------------------------ #
    #  Ports display
    # ------------------------------------------------------------------ #
    def display_ports(self, data: Dict) -> None:
        self.print_section("PORT SCAN")

        open_ports = data.get('open_ports', [])
        if not open_ports:
            self.print_success("No open ports found - appears secure")
            return

        if HAS_RICH:
            tbl = Table(
                title=f"Open Ports ({len(open_ports)} found)",
                box=box.ROUNDED,
                border_style="cyan",
            )
            tbl.add_column("Port", style="cyan")
            tbl.add_column("Service", style="white")
            tbl.add_column("Risk", style="white")
            tbl.add_column("Status", style="green")

            risk_styles = {
                'low': 'green',
                'medium': 'yellow',
                'high': 'red',
                'critical': 'bold red',
            }
            for port_info in open_ports:
                risk = port_info.get('risk_level', 'medium')
                style = risk_styles.get(risk, 'white')
                tbl.add_row(
                    str(port_info['port']),
                    port_info['service'],
                    f"[{style}]{risk.upper()}[/{style}]",
                    "OPEN",
                )

            self._console.print(tbl)

            dangerous = data.get('dangerous_ports', [])
            if dangerous:
                self._console.print()
                self._console.print(Panel(
                    "\n".join(
                        f"[bold red]Port {p['port']} ({p['service']}): {p['description']}[/bold red]"
                        for p in dangerous
                    ),
                    title="DANGEROUS PORTS DETECTED",
                    border_style="bold red",
                ))
        else:
            print(f"\n  {Fore.WHITE}Open Ports ({len(open_ports)} found):")
            print(f"  {'-' * 55}")
            print(f"  {Fore.WHITE}{'Port':<8} {'Service':<15} {'Risk':<12} {'Status':<10}")
            print(f"  {'-' * 55}")

            for port_info in open_ports:
                risk_color = {
                    'low': Fore.GREEN,
                    'medium': Fore.YELLOW,
                    'high': Fore.RED,
                    'critical': Fore.RED + Style.BRIGHT
                }.get(port_info.get('risk_level', 'medium'), Fore.WHITE)

                risk_display = port_info.get('risk_level', 'unknown').upper()
                print(f"  {Fore.CYAN}{port_info['port']:<8} {Fore.WHITE}{port_info['service']:<15} {risk_color}{risk_display:<12} {Fore.GREEN}OPEN")

            dangerous = data.get('dangerous_ports', [])
            if dangerous:
                print(f"\n  {Fore.RED}{Style.BRIGHT}DANGEROUS PORTS DETECTED!")
                for port_info in dangerous:
                    self.print_danger(f"Port {port_info['port']} ({port_info['service']}): {port_info['description']}")

    # ------------------------------------------------------------------ #
    #  Security display
    # ------------------------------------------------------------------ #
    def display_security(self, data: Dict) -> None:
        self.print_section("SECURITY ANALYSIS")

        summary = data.get('summary', {})
        score = summary.get('security_score', 0)

        if score >= 80:
            score_label = "GOOD"
        elif score >= 60:
            score_label = "MODERATE"
        elif score >= 40:
            score_label = "LOW"
        else:
            score_label = "CRITICAL"

        if HAS_RICH:
            # Score gauge
            if score >= 80:
                score_color = "green"
            elif score >= 60:
                score_color = "yellow"
            elif score >= 40:
                score_color = "red"
            else:
                score_color = "bold red"

            filled = int(score / 100 * 30)
            bar = "[" + "#" * filled + "-" * (30 - filled) + "]"

            score_text = Text()
            score_text.append(f"\n  {score}/100 ", style=score_color)
            score_text.append(f"({score_label})\n", style=score_color)
            score_text.append(f"  {bar}\n\n", style=score_color)
            score_text.append(f"  Total Issues: ", style="white")
            score_text.append(f"{summary.get('total_issues', 0)}\n", style="yellow")
            score_text.append(f"  Critical Issues: ", style="white")
            score_text.append(f"{summary.get('critical_issues', 0)}\n", style="red")
            score_text.append(f"  High Risk: ", style="white")
            score_text.append(f"{summary.get('high_risk_issues', 0)}", style="red")

            self._console.print(Panel(score_text, title="Security Score", border_style=score_color))

            # Issues table
            issues = data.get('issues', [])
            if issues:
                for issue in issues:
                    risk = issue.get('risk_level', 'MEDIUM')
                    risk_style = {
                        'LOW': 'green',
                        'MEDIUM': 'yellow',
                        'HIGH': 'red',
                        'CRITICAL': 'bold red',
                    }.get(risk, 'white')

                    issue_text = (
                        f"[{risk_style}][{risk}][/{risk_style}] [white]{issue.get('title', '')}[/white]\n"
                        f"  [cyan]Category: {issue.get('category', '')}[/cyan]\n"
                        f"  [white]{issue.get('description', '')}[/white]\n"
                        f"  [green]Recommendation: {issue.get('recommendation', '')}[/green]"
                    )
                    self._console.print(issue_text)
                    self._console.print()
        else:
            if score >= 80:
                score_color = Fore.GREEN
            elif score >= 60:
                score_color = Fore.YELLOW
            elif score >= 40:
                score_color = Fore.RED
            else:
                score_color = Fore.RED + Style.BRIGHT

            print(f"\n  {Fore.WHITE}Security Score: {score_color}{score}/100 ({score_label})")
            print(f"  {Fore.WHITE}Total Issues: {Fore.YELLOW}{summary.get('total_issues', 0)}")
            print(f"  {Fore.WHITE}Critical Issues: {Fore.RED}{summary.get('critical_issues', 0)}")
            print(f"  {Fore.WHITE}High Risk: {Fore.RED}{summary.get('high_risk_issues', 0)}")

            issues = data.get('issues', [])
            if issues:
                print(f"\n  {Fore.WHITE}Detected Issues:")
                print(f"  {'-' * 55}")

                for issue in issues:
                    risk = issue.get('risk_level', 'MEDIUM')
                    risk_color = {
                        'LOW': Fore.GREEN,
                        'MEDIUM': Fore.YELLOW,
                        'HIGH': Fore.RED,
                        'CRITICAL': Fore.RED + Style.BRIGHT
                    }.get(risk, Fore.WHITE)

                    print(f"\n  {risk_color}[{risk}] {Fore.WHITE}{issue.get('title', '')}")
                    print(f"    {Fore.CYAN}Category: {issue.get('category', '')}")
                    print(f"    {Fore.WHITE}{issue.get('description', '')}")
                    print(f"    {Fore.GREEN}Recommendation: {issue.get('recommendation', '')}")

    # ------------------------------------------------------------------ #
    #  Optimization plan display
    # ------------------------------------------------------------------ #
    def display_optimization_plan(self, data: Dict) -> bool:
        self.print_section("OPTIMIZATION PLAN")

        plan = data.get('plan', [])
        if not plan:
            self.print_success("Your system appears to be optimized!")
            return False

        if HAS_RICH:
            tbl = Table(title="Available Optimizations", box=box.ROUNDED, border_style="cyan")
            tbl.add_column("#", style="cyan", width=4)
            tbl.add_column("Optimization", style="white")
            tbl.add_column("Type", style="white")
            tbl.add_column("Impact", style="green")
            tbl.add_column("Risk", style="yellow")

            for i, item in enumerate(plan, 1):
                badge = "[green]AUTO[/green]" if item.get('auto_applicable') else "[yellow]MANUAL[/yellow]"
                tbl.add_row(
                    str(i),
                    item['title'],
                    badge,
                    item['impact'],
                    item['risk'],
                )

            self._console.print(tbl)

            manual_recs = data.get('manual_recommendations', [])
            if manual_recs:
                self._console.print()
                self._console.print("[white]Issues Requiring Manual Steps:[/white]")
                for rec in manual_recs:
                    self._console.print(f"\n  [yellow]{rec['issue']}[/yellow]")
                    for step in rec['steps']:
                        self._console.print(f"    [white]- {step}[/white]")
        else:
            print(f"\n  {Fore.WHITE}Available Optimizations:")
            print(f"  {'-' * 55}")

            for i, item in enumerate(plan, 1):
                auto_badge = f"{Fore.GREEN}[AUTOMATIC]" if item.get('auto_applicable') else f"{Fore.YELLOW}[MANUAL]"
                print(f"\n  {Fore.CYAN}{i}. {Fore.WHITE}{item['title']} {auto_badge}")
                print(f"     {Fore.WHITE}{item['description']}")
                print(f"     {Fore.GREEN}Impact: {item['impact']}")
                print(f"     {Fore.YELLOW}Risk: {item['risk']}")

            manual_recs = data.get('manual_recommendations', [])
            if manual_recs:
                print(f"\n  {Fore.WHITE}Issues Requiring Manual Steps:")
                for rec in manual_recs:
                    print(f"\n  {Fore.YELLOW}{rec['issue']}")
                    for step in rec['steps']:
                        print(f"    {Fore.WHITE}- {step}")

        return True

    # ------------------------------------------------------------------ #
    #  Applied optimizations display
    # ------------------------------------------------------------------ #
    def display_optimizations_applied(self, results: List[Dict]) -> None:
        self.print_section("APPLYING OPTIMIZATIONS")

        success_count = 0
        fail_count = 0
        skip_count = 0

        for result in results:
            action = result.get('action', 'Unknown')
            message = result.get('message', '')
            success = result.get('success', False)

            if success:
                success_count += 1
                self.print_success(f"{action}: {message}")
            elif action.startswith('fix_'):
                skip_count += 1
                if HAS_RICH:
                    self._console.print(f"  [dim yellow][SKIP] {action}: {message}[/dim yellow]")
                else:
                    print(f"  {Fore.YELLOW}[SKIP] {action}: {message}")
            else:
                fail_count += 1
                self.print_warning(f"{action}: {message}")

        # Summary
        if HAS_RICH:
            self._console.print()
            summary_lines = []
            summary_lines.append(f"[green]Successful: {success_count}[/green]")
            if fail_count > 0:
                summary_lines.append(f"[red]Failed: {fail_count} (may require Administrator)[/red]")
            if skip_count > 0:
                summary_lines.append(f"[yellow]Skipped: {skip_count}[/yellow]")
            self._console.print(Panel(
                "\n".join(summary_lines),
                title="Optimization Summary",
                border_style="green" if fail_count == 0 else "yellow",
                padding=(0, 2),
            ))
        else:
            print(f"\n  {Fore.WHITE}--- Optimization Summary ---")
            print(f"  {Fore.GREEN}Successful: {success_count}")
            if fail_count > 0:
                print(f"  {Fore.RED}Failed: {fail_count} (may require Administrator)")
            if skip_count > 0:
                print(f"  {Fore.YELLOW}Skipped: {skip_count}")
            print()

        # Write log file
        self._write_optimization_log(results, success_count, fail_count, skip_count)

    # ------------------------------------------------------------------ #
    #  Optimization log writer
    # ------------------------------------------------------------------ #
    def _write_optimization_log(self, results: List[Dict],
                                success_count: int, fail_count: int,
                                skip_count: int) -> None:
        """Write optimization results to a timestamped log file."""
        try:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))), 'logs')
            os.makedirs(log_dir, exist_ok=True)

            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            log_path = os.path.join(log_dir, f'optimization_{timestamp}.log')

            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"Wif-G v2.0 - Optimization Log\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'=' * 60}\n\n")

                f.write(f"SUMMARY\n")
                f.write(f"{'-' * 40}\n")
                f.write(f"  Total operations: {len(results)}\n")
                f.write(f"  Successful:       {success_count}\n")
                f.write(f"  Failed:           {fail_count}\n")
                f.write(f"  Skipped:          {skip_count}\n\n")

                f.write(f"DETAILED RESULTS\n")
                f.write(f"{'=' * 60}\n\n")

                for i, result in enumerate(results, 1):
                    action = result.get('action', 'Unknown')
                    success = result.get('success', False)
                    message = result.get('message', '')
                    requires_restart = result.get('requires_restart', False)

                    if success:
                        status = 'SUCCESS'
                    elif action.startswith('fix_'):
                        status = 'SKIPPED'
                    else:
                        status = 'FAILED'

                    f.write(f"[{i}] {action}\n")
                    f.write(f"    Status:  {status}\n")
                    f.write(f"    Message: {message}\n")
                    if requires_restart:
                        f.write(f"    Note:    Requires system restart\n")
                    f.write(f"\n")

                if fail_count > 0:
                    f.write(f"TROUBLESHOOTING\n")
                    f.write(f"{'=' * 60}\n")
                    f.write(f"  Some optimizations failed. To fix:\n")
                    f.write(f"  1. Run the program as Administrator\n")
                    f.write(f"     Right-click CMD/Terminal -> Run as Administrator\n")
                    f.write(f"  2. Re-run: python main.py\n")
                    f.write(f"  3. For TCP/MTU changes, admin rights are required\n\n")

            if HAS_RICH:
                self._console.print(f"  [dim]Log saved: {log_path}[/dim]")
            else:
                print(f"  {Fore.WHITE}Log saved: {log_path}")

        except (OSError, PermissionError) as e:
            logger.debug("Could not write optimization log: %s", e)

    # ------------------------------------------------------------------ #
    #  Comparison display
    # ------------------------------------------------------------------ #
    def display_comparison(self, comparison: Dict) -> None:
        if not comparison or not comparison.get('has_previous'):
            return

        delta = comparison.get('delta', {})
        self.print_section("COMPARISON WITH PREVIOUS SCAN")

        score_change = delta.get('score_change', 0)
        direction = delta.get('score_direction', 'unchanged')

        if HAS_RICH:
            lines = []
            if direction == 'improved':
                lines.append(f"[green]Score: +{score_change} points (IMPROVED)[/green]")
            elif direction == 'declined':
                lines.append(f"[red]Score: {score_change} points (DECLINED)[/red]")
            else:
                lines.append("[white]Score: Unchanged[/white]")

            issues_change = delta.get('issues_change', 0)
            if issues_change > 0:
                lines.append(f"[red]New issues: +{issues_change}[/red]")
            elif issues_change < 0:
                lines.append(f"[green]Resolved issues: {abs(issues_change)}[/green]")

            new_ports = delta.get('new_open_ports', [])
            if new_ports:
                lines.append(f"[red]New open ports: {new_ports}[/red]")

            closed_ports = delta.get('newly_closed_ports', [])
            if closed_ports:
                lines.append(f"[green]Newly closed ports: {closed_ports}[/green]")

            lines.append(f"[white]Previous scan: {delta.get('previous_timestamp', 'N/A')}[/white]")

            self._console.print(Panel("\n".join(lines), border_style="cyan"))
        else:
            if direction == 'improved':
                print(f"  {Fore.GREEN}Score: +{score_change} points (IMPROVED)")
            elif direction == 'declined':
                print(f"  {Fore.RED}Score: {score_change} points (DECLINED)")
            else:
                print(f"  {Fore.WHITE}Score: Unchanged")

            issues_change = delta.get('issues_change', 0)
            if issues_change > 0:
                print(f"  {Fore.RED}New issues: +{issues_change}")
            elif issues_change < 0:
                print(f"  {Fore.GREEN}Resolved issues: {abs(issues_change)}")

            new_ports = delta.get('new_open_ports', [])
            if new_ports:
                print(f"  {Fore.RED}New open ports: {new_ports}")

            closed_ports = delta.get('newly_closed_ports', [])
            if closed_ports:
                print(f"  {Fore.GREEN}Newly closed ports: {closed_ports}")

            print(f"  {Fore.WHITE}Previous scan: {delta.get('previous_timestamp', 'N/A')}")

    # ------------------------------------------------------------------ #
    #  History display
    # ------------------------------------------------------------------ #
    def display_history(self, scans: List[Dict]) -> None:
        self.print_section("SCAN HISTORY")

        if not scans:
            self.print_info("No scans", "No previous scans found")
            return

        if HAS_RICH:
            tbl = Table(title="Scan History", box=box.ROUNDED, border_style="cyan")
            tbl.add_column("ID", style="cyan")
            tbl.add_column("Timestamp", style="white")
            tbl.add_column("Score", style="white")
            tbl.add_column("Issues", style="yellow")

            for scan in scans:
                score = scan.get('security_score', 'N/A')
                if isinstance(score, int) and score >= 80:
                    score_str = f"[green]{score}[/green]"
                elif isinstance(score, int) and score >= 60:
                    score_str = f"[yellow]{score}[/yellow]"
                else:
                    score_str = f"[red]{score}[/red]"

                tbl.add_row(
                    str(scan['id']),
                    scan['timestamp'],
                    score_str,
                    str(scan.get('total_issues', 'N/A')),
                )

            self._console.print(tbl)
        else:
            print(f"\n  {Fore.WHITE}{'ID':<6} {'Timestamp':<25} {'Score':<8} {'Issues':<8}")
            print(f"  {'-' * 50}")

            for scan in scans:
                score = scan.get('security_score', 'N/A')
                score_color = Fore.GREEN if isinstance(score, int) and score >= 80 else (
                    Fore.YELLOW if isinstance(score, int) and score >= 60 else Fore.RED
                )
                print(f"  {Fore.CYAN}{scan['id']:<6} {Fore.WHITE}{scan['timestamp']:<25} {score_color}{score:<8} {Fore.YELLOW}{scan.get('total_issues', 'N/A')}")
