import sys
import logging
from typing import Any, Dict, List, Optional

from colorama import init, Fore, Back, Style

from .app import NetworkAnalyzerEngine, AnalysisResults
from .history import ScanHistory

init(autoreset=True)

logger = logging.getLogger(__name__)


class NetworkAnalyzerCLI:
    """UI layer - handles all terminal output and user interaction."""

    def __init__(self, engine: NetworkAnalyzerEngine):
        self._engine = engine

    def print_banner(self) -> None:
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

{Fore.YELLOW}   Network Security Analysis and Optimization Tool v1.0
{Fore.CYAN}{'=' * 62}
"""
        print(banner)

    def print_section(self, title: str) -> None:
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.WHITE}{Style.BRIGHT}  {title}")
        print(f"{Fore.CYAN}{'=' * 60}")

    def print_loading(self, message: str) -> None:
        print(f"{Fore.YELLOW}[*] {message}...", end='', flush=True)

    def print_done(self) -> None:
        print(f" {Fore.GREEN}[DONE]")

    def print_info(self, key: str, value: str) -> None:
        print(f"  {Fore.WHITE}{key}: {Fore.GREEN}{value}")

    def print_warning(self, message: str) -> None:
        print(f"  {Fore.YELLOW}[!] {message}")

    def print_danger(self, message: str) -> None:
        print(f"  {Fore.RED}[!!!] {message}")

    def print_success(self, message: str) -> None:
        print(f"  {Fore.GREEN}[+] {message}")

    def _format_bytes(self, bytes_val: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} PB"

    def display_network(self, data: Dict) -> None:
        self.print_section("NETWORK INFORMATION")

        ssid = data.get('ssid') or "Unknown"
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

    def display_dns(self, data: Dict) -> None:
        self.print_section("DNS ANALYSIS")

        print(f"\n  {Fore.WHITE}Current DNS Servers:")
        for dns in data.get('servers', []):
            secure_status = f"{Fore.GREEN}[PUBLIC DNS]" if dns.get('is_public_resolver') else f"{Fore.YELLOW}[ISP/PRIVATE]"
            response = f"{dns.get('response_time')}ms" if dns.get('response_time') else "N/A"
            print(f"    {Fore.CYAN}{dns['ip']} {Fore.WHITE}({dns['provider']}) - {secure_status} - {response}")

        for warning in data.get('warnings', []):
            self.print_warning(warning)

    def display_performance(self, data: Dict) -> None:
        self.print_section("PERFORMANCE TESTS")

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

    def display_ports(self, data: Dict) -> None:
        self.print_section("PORT SCAN")

        open_ports = data.get('open_ports', [])
        if not open_ports:
            self.print_success("No open ports found - appears secure")
            return

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

    def display_security(self, data: Dict) -> None:
        self.print_section("SECURITY ANALYSIS")

        summary = data.get('summary', {})
        score = summary.get('security_score', 0)

        if score >= 80:
            score_color = Fore.GREEN
            score_label = "GOOD"
        elif score >= 60:
            score_color = Fore.YELLOW
            score_label = "MODERATE"
        elif score >= 40:
            score_color = Fore.RED
            score_label = "LOW"
        else:
            score_color = Fore.RED + Style.BRIGHT
            score_label = "CRITICAL"

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

    def display_optimization_plan(self, data: Dict) -> bool:
        self.print_section("OPTIMIZATION PLAN")

        plan = data.get('plan', [])
        if not plan:
            self.print_success("Your system appears to be optimized!")
            return False

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

    def display_optimizations_applied(self, results: List[Dict]) -> None:
        self.print_section("APPLYING OPTIMIZATIONS")

        for result in results:
            if result.get('success'):
                self.print_success(f"{result['action']}: {result['message']}")
            else:
                self.print_warning(f"{result['action']}: {result['message']}")

        print(f"\n  {Fore.GREEN}Optimization complete!")

    def display_comparison(self, comparison: Dict) -> None:
        if not comparison or not comparison.get('has_previous'):
            return

        delta = comparison.get('delta', {})
        self.print_section("COMPARISON WITH PREVIOUS SCAN")

        score_change = delta.get('score_change', 0)
        direction = delta.get('score_direction', 'unchanged')

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

    def display_history(self, scans: List[Dict]) -> None:
        self.print_section("SCAN HISTORY")

        if not scans:
            self.print_info("No scans", "No previous scans found")
            return

        print(f"\n  {Fore.WHITE}{'ID':<6} {'Timestamp':<25} {'Score':<8} {'Issues':<8}")
        print(f"  {'-' * 50}")

        for scan in scans:
            score = scan.get('security_score', 'N/A')
            score_color = Fore.GREEN if isinstance(score, int) and score >= 80 else (
                Fore.YELLOW if isinstance(score, int) and score >= 60 else Fore.RED
            )
            print(f"  {Fore.CYAN}{scan['id']:<6} {Fore.WHITE}{scan['timestamp']:<25} {score_color}{score:<8} {Fore.YELLOW}{scan.get('total_issues', 'N/A')}")
