#!/usr/bin/env python3
import sys
import time
import asyncio
from colorama import init, Fore, Back, Style

from src.network_analyzer import (
    NetworkScanner,
    PortScanner,
    DNSAnalyzer,
    SecurityAnalyzer,
    NetworkOptimizer,
    PerformanceTests
)

init(autoreset=True)


class NetworkAnalyzerApp:
    def __init__(self):
        self._network_scanner = NetworkScanner()
        self._port_scanner = PortScanner()
        self._dns_analyzer = DNSAnalyzer()
        self._performance_tester = None
        self._performance_results = None
        self._security_analyzer = None
        self._optimizer = None
        
    def print_banner(self) -> None:
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                ║
║   {Fore.WHITE}  _   _      _                      _                     {Fore.CYAN}║
║   {Fore.WHITE} | \\ | | ___| |___      _____  _ __| | __                 {Fore.CYAN}║
║   {Fore.WHITE} |  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ /                 {Fore.CYAN}║
║   {Fore.WHITE} | |\\  |  __/ |_ \\ V  V / (_) | |  |   <                  {Fore.CYAN}║
║   {Fore.WHITE} |_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\                 {Fore.CYAN}║
║   {Fore.WHITE}     / \\   _ __   __ _| |_   _ _______ _ __               {Fore.CYAN}║
║   {Fore.WHITE}    / _ \\ | '_ \\ / _` | | | | |_  / _ \\ '__|              {Fore.CYAN}║
║   {Fore.WHITE}   / ___ \\| | | | (_| | | |_| |/ /  __/ |                 {Fore.CYAN}║
║   {Fore.WHITE}  /_/   \\_\\_| |_|\\__,_|_|\\__, /___\\___|_|                 {Fore.CYAN}║
║   {Fore.WHITE}                         |___/                            {Fore.CYAN}║
║                                                                ║
║   {Fore.YELLOW}Network Security Analysis and Optimization Tool v1.0{Fore.CYAN}       ║
║                                                                ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
        
    def print_section(self, title: str) -> None:
        print(f"\n{Fore.CYAN}{'═' * 60}")
        print(f"{Fore.WHITE}{Style.BRIGHT}  {title}")
        print(f"{Fore.CYAN}{'═' * 60}")
        
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
        
    def scan_network(self) -> None:
        self.print_section("NETWORK INFORMATION")
        
        self.print_loading("Scanning network")
        self._network_scanner.scan()
        self.print_done()
        
        ssid = self._network_scanner.ssid or "Unknown"
        self.print_info("WiFi SSID", ssid)
        
        signal = self._network_scanner.signal_strength
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
        
        self.print_info("Local IP", self._network_scanner.local_ip or "Unknown")
        self.print_info("Gateway", self._network_scanner.gateway or "Unknown")
        
        print(f"\n  {Fore.WHITE}Network Interfaces:")
        for iface, info in self._network_scanner.interfaces.items():
            print(f"    {Fore.CYAN}{iface}: {Fore.WHITE}{info['ip']} ({info['netmask']})")
            
        stats = self._network_scanner.get_network_stats()
        print(f"\n  {Fore.WHITE}Network Statistics:")
        print(f"    {Fore.WHITE}Sent: {Fore.GREEN}{self._format_bytes(stats['bytes_sent'])}")
        print(f"    {Fore.WHITE}Received: {Fore.GREEN}{self._format_bytes(stats['bytes_recv'])}")
        print(f"    {Fore.WHITE}Errors: Incoming={stats['errors_in']}, Outgoing={stats['errors_out']}")
        
    def scan_dns(self) -> None:
        self.print_section("DNS ANALYSIS")
        
        self.print_loading("Analyzing DNS servers")
        self._dns_analyzer.analyze()
        self.print_done()
        
        print(f"\n  {Fore.WHITE}Current DNS Servers:")
        for dns in self._dns_analyzer.current_dns:
            secure_status = f"{Fore.GREEN}[PUBLIC DNS]" if dns.is_public_resolver else f"{Fore.YELLOW}[ISP/PRIVATE]"
            response = f"{dns.response_time}ms" if dns.response_time else "N/A"
            print(f"    {Fore.CYAN}{dns.ip} {Fore.WHITE}({dns.provider}) - {secure_status} - {response}")
            
        for warning in self._dns_analyzer.dns_warnings:
            self.print_warning(warning)
    
    def run_performance_tests(self) -> None:
        self.print_section("PERFORMANCE TESTS")
        
        gateway = self._network_scanner.gateway
        self._performance_tester = PerformanceTests(gateway=gateway)
        
        self.print_loading("Running latency tests")
        latency_results = asyncio.run(self._performance_tester.latency_test())
        self.print_done()
        
        print(f"\n  {Fore.WHITE}Latency Results:")
        print(f"  {'─' * 55}")
        print(f"  {Fore.WHITE}{'Target':<20} {'Avg':<12} {'Min':<12} {'Max':<12}")
        print(f"  {'─' * 55}")
        
        for result in latency_results:
            if result.avg_latency != -1:
                avg_color = Fore.GREEN if result.avg_latency < 50 else (Fore.YELLOW if result.avg_latency < 100 else Fore.RED)
                print(f"  {Fore.CYAN}{result.target:<20} {avg_color}{result.avg_latency:<12}ms {Fore.WHITE}{result.min_latency:<12}ms {result.max_latency:<12}ms")
            else:
                print(f"  {Fore.CYAN}{result.target:<20} {Fore.RED}{'Unreachable':<12}")
        
        self.print_loading("Testing network jitter")
        jitter_result = asyncio.run(self._performance_tester.jitter_test())
        self.print_done()
        
        if jitter_result.jitter != -1:
            jitter_color = Fore.GREEN if jitter_result.jitter < 10 else (Fore.YELLOW if jitter_result.jitter < 30 else Fore.RED)
            print(f"\n  {Fore.WHITE}Jitter: {jitter_color}{jitter_result.jitter}ms {Fore.WHITE}(samples: {jitter_result.samples})")
            if jitter_result.jitter < 10:
                self.print_success("Excellent jitter - suitable for real-time applications")
            elif jitter_result.jitter < 30:
                self.print_warning("Moderate jitter - may affect VoIP/video calls")
            else:
                self.print_danger("High jitter - poor for real-time applications")
        else:
            print(f"\n  {Fore.WHITE}Jitter: {Fore.RED}Could not measure")
        
        self.print_loading("Testing packet loss")
        packet_loss_result = asyncio.run(self._performance_tester.packet_loss_test())
        self.print_done()
        
        loss_pct = packet_loss_result.loss_percentage
        loss_color = Fore.GREEN if loss_pct == 0 else (Fore.YELLOW if loss_pct < 2 else Fore.RED)
        print(f"\n  {Fore.WHITE}Packet Loss: {loss_color}{loss_pct}% {Fore.WHITE}({packet_loss_result.received}/{packet_loss_result.sent} packets received)")
        
        if loss_pct == 0:
            self.print_success("No packet loss detected")
        elif loss_pct < 2:
            self.print_warning("Minor packet loss - generally acceptable")
        else:
            self.print_danger("Significant packet loss - network issues detected")
        
        self.print_loading("Estimating bandwidth")
        bandwidth_result = asyncio.run(self._performance_tester.bandwidth_estimate(test_duration=3.0))
        self.print_done()
        
        if bandwidth_result.download_speed_mbps > 0:
            speed = bandwidth_result.download_speed_mbps
            speed_color = Fore.GREEN if speed > 10 else (Fore.YELLOW if speed > 1 else Fore.RED)
            print(f"\n  {Fore.WHITE}Bandwidth Estimate: {speed_color}{speed:.2f} Mbps")
            print(f"  {Fore.WHITE}  Test duration: {bandwidth_result.test_duration}s, Data: {self._format_bytes(bandwidth_result.bytes_received)}")
        else:
            print(f"\n  {Fore.WHITE}Bandwidth Estimate: {Fore.YELLOW}Could not determine")
        
        self._performance_results = {
            'latency': latency_results,
            'jitter': jitter_result,
            'packet_loss': packet_loss_result,
            'bandwidth': bandwidth_result
        }
            
    def scan_ports(self) -> None:
        self.print_section("PORT SCAN")
        
        target = self._network_scanner.gateway or 'localhost'
        self._port_scanner.target = target
        
        self.print_loading(f"Scanning ports ({target})")
        self._port_scanner.scan_common_ports()
        self.print_done()
        
        open_ports = self._port_scanner.open_ports
        
        if not open_ports:
            self.print_success("No open ports found - appears secure")
            return
            
        print(f"\n  {Fore.WHITE}Open Ports ({len(open_ports)} found):")
        print(f"  {'─' * 55}")
        print(f"  {Fore.WHITE}{'Port':<8} {'Service':<15} {'Risk':<12} {'Status':<10}")
        print(f"  {'─' * 55}")
        
        for port_info in open_ports:
            risk_color = {
                'low': Fore.GREEN,
                'medium': Fore.YELLOW,
                'high': Fore.RED,
                'critical': Fore.RED + Style.BRIGHT
            }.get(port_info.risk_level, Fore.WHITE)
            
            risk_display = port_info.risk_level.upper()
            print(f"  {Fore.CYAN}{port_info.port:<8} {Fore.WHITE}{port_info.service:<15} {risk_color}{risk_display:<12} {Fore.GREEN}OPEN")
            
        dangerous = self._port_scanner.get_dangerous_ports()
        if dangerous:
            print(f"\n  {Fore.RED}{Style.BRIGHT}DANGEROUS PORTS DETECTED!")
            for port_info in dangerous:
                self.print_danger(f"Port {port_info.port} ({port_info.service}): {port_info.description}")
                
    def analyze_security(self) -> None:
        self.print_section("SECURITY ANALYSIS")
        
        self._security_analyzer = SecurityAnalyzer(
            self._network_scanner,
            self._port_scanner,
            self._dns_analyzer,
            self._performance_tester
        )
        
        if self._performance_results:
            self._security_analyzer.set_performance_results(self._performance_results)
        
        self.print_loading("Performing security analysis")
        self._security_analyzer.analyze()
        self.print_done()
        
        summary = self._security_analyzer.get_summary()
        
        score = summary['security_score']
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
        print(f"  {Fore.WHITE}Total Issues: {Fore.YELLOW}{summary['total_issues']}")
        print(f"  {Fore.WHITE}Critical Issues: {Fore.RED}{summary['critical_issues']}")
        print(f"  {Fore.WHITE}High Risk: {Fore.RED}{summary['high_risk_issues']}")
        
        if self._security_analyzer.issues:
            print(f"\n  {Fore.WHITE}Detected Issues:")
            print(f"  {'─' * 55}")
            
            for issue in self._security_analyzer.issues:
                risk_color = {
                    'LOW': Fore.GREEN,
                    'MEDIUM': Fore.YELLOW,
                    'HIGH': Fore.RED,
                    'CRITICAL': Fore.RED + Style.BRIGHT
                }.get(issue.risk_level.name, Fore.WHITE)
                
                print(f"\n  {risk_color}[{issue.risk_level.name}] {Fore.WHITE}{issue.title}")
                print(f"    {Fore.CYAN}Category: {issue.category}")
                print(f"    {Fore.WHITE}{issue.description}")
                print(f"    {Fore.GREEN}Recommendation: {issue.recommendation}")
                
    def show_optimization_plan(self) -> bool:
        self.print_section("OPTIMIZATION PLAN")
        
        if self._security_analyzer is None:
            self.print_warning("Security analysis not yet performed")
            return False
            
        self._optimizer = NetworkOptimizer(
            self._security_analyzer,
            self._dns_analyzer
        )
        
        plan = self._optimizer.get_optimization_plan()
        
        if not plan:
            self.print_success("Your system appears to be optimized!")
            return False
            
        print(f"\n  {Fore.WHITE}Available Optimizations:")
        print(f"  {'─' * 55}")
        
        for i, item in enumerate(plan, 1):
            auto_badge = f"{Fore.GREEN}[AUTOMATIC]" if item['auto_applicable'] else f"{Fore.YELLOW}[MANUAL]"
            print(f"\n  {Fore.CYAN}{i}. {Fore.WHITE}{item['title']} {auto_badge}")
            print(f"     {Fore.WHITE}{item['description']}")
            print(f"     {Fore.GREEN}Impact: {item['impact']}")
            print(f"     {Fore.YELLOW}Risk: {item['risk']}")
            
        manual_recs = self._optimizer.get_manual_recommendations()
        if manual_recs:
            print(f"\n  {Fore.WHITE}Issues Requiring Manual Steps:")
            for rec in manual_recs:
                print(f"\n  {Fore.YELLOW}{rec['issue']}")
                for step in rec['steps']:
                    print(f"    {Fore.WHITE}- {step}")
                    
        return True
        
    def apply_optimizations(self) -> None:
        self.print_section("APPLYING OPTIMIZATIONS")
        
        if self._optimizer is None:
            self.print_warning("Optimizer not yet ready")
            return
            
        results = self._optimizer.apply_all_optimizations()
        
        for result in results:
            if result.success:
                self.print_success(f"{result.action}: {result.message}")
            else:
                self.print_warning(f"{result.action}: {result.message}")
                
        print(f"\n  {Fore.GREEN}Optimization complete!")
        
    def _format_bytes(self, bytes_val: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} PB"
        
    def run(self) -> None:
        self.print_banner()
        
        try:
            self.scan_network()
            self.scan_dns()
            self.run_performance_tests()
            self.scan_ports()
            self.analyze_security()
            
            has_optimizations = self.show_optimization_plan()
            
            if has_optimizations:
                print(f"\n{Fore.YELLOW}Would you like to apply optimizations? (yes/no): ", end='')
                response = input().strip().lower()
                
                if response in ('yes', 'y'):
                    self.apply_optimizations()
                else:
                    print(f"\n{Fore.CYAN}Optimizations skipped. You can apply them manually.")
                    
            print(f"\n{Fore.GREEN}Analysis complete!")
            print(f"{Fore.CYAN}{'═' * 60}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Program interrupted by user.")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}Error occurred: {str(e)}")
            sys.exit(1)


def main():
    app = NetworkAnalyzerApp()
    app.run()


if __name__ == '__main__':
    main()
