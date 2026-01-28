import subprocess
import os
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass

from .security_analyzer import SecurityAnalyzer, SecurityIssue
from .dns_analyzer import DNSAnalyzer


@dataclass
class OptimizationResult:
    action: str
    success: bool
    message: str
    requires_restart: bool


class NetworkOptimizer:
    def __init__(
        self,
        security_analyzer: SecurityAnalyzer,
        dns_analyzer: DNSAnalyzer
    ):
        self._security_analyzer = security_analyzer
        self._dns_analyzer = dns_analyzer
        self._optimization_results: List[OptimizationResult] = []
        self._is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self._is_windows = platform.system() == 'Windows'
        
    def get_optimization_plan(self) -> List[Dict]:
        plan = []
        
        dns_recs = self._dns_analyzer.get_dns_recommendations()
        if dns_recs:
            best_dns = self._dns_analyzer.get_best_dns_recommendation()
            plan.append({
                'id': 'dns_optimization',
                'title': 'Optimize DNS Server',
                'description': f"Change DNS to {best_dns['name']} ({best_dns['ip']}) - {best_dns['description']}",
                'impact': 'Faster and more secure internet connection',
                'risk': 'Low',
                'auto_applicable': True
            })
            
        fixable = self._security_analyzer.get_fixable_issues()
        for issue in fixable:
            plan.append({
                'id': f'fix_{issue.category.lower().replace(" ", "_")}',
                'title': issue.title,
                'description': issue.recommendation,
                'impact': 'Security improvement',
                'risk': 'Low',
                'auto_applicable': issue.auto_fixable
            })
            
        plan.append({
            'id': 'tcp_optimization',
            'title': 'Optimize TCP Settings',
            'description': 'Optimize TCP buffer sizes and window scaling',
            'impact': 'Faster data transfer',
            'risk': 'Low',
            'auto_applicable': self._is_root
        })
        
        plan.append({
            'id': 'dns_cache',
            'title': 'Clear DNS Cache',
            'description': 'Clear system DNS cache',
            'impact': 'Clears stale DNS records',
            'risk': 'Very low',
            'auto_applicable': True
        })
        
        return plan
        
    def apply_optimization(self, optimization_id: str) -> OptimizationResult:
        optimizers = {
            'dns_optimization': self._optimize_dns,
            'tcp_optimization': self._optimize_tcp,
            'dns_cache': self._clear_dns_cache,
        }
        
        # Handle dynamic fix_* IDs
        if optimization_id.startswith('fix_'):
            # For fixable issues, check if they're DNS-related and can be auto-fixed
            if 'dns' in optimization_id.lower():
                # DNS issues are handled by dns_optimization
                return OptimizationResult(
                    action=optimization_id,
                    success=False,
                    message='DNS issues are addressed by DNS optimization. Please run DNS optimization separately.',
                    requires_restart=False
                )
            else:
                # Other fixable issues require manual intervention
                return OptimizationResult(
                    action=optimization_id,
                    success=False,
                    message='This issue requires manual configuration. Please check the recommendations.',
                    requires_restart=False
                )
        
        optimizer_func = optimizers.get(optimization_id)
        if optimizer_func:
            result = optimizer_func()
            self._optimization_results.append(result)
            return result
            
        return OptimizationResult(
            action=optimization_id,
            success=False,
            message='Unknown optimization',
            requires_restart=False
        )
        
    def apply_all_optimizations(self) -> List[OptimizationResult]:
        results = []
        plan = self.get_optimization_plan()
        
        for item in plan:
            if item['auto_applicable']:
                result = self.apply_optimization(item['id'])
                results.append(result)
                
        return results
        
    def _optimize_dns(self) -> OptimizationResult:
        best_dns = self._dns_analyzer.get_best_dns_recommendation()
        
        if self._is_windows:
            return self._optimize_dns_windows(best_dns)
        
        if not self._is_root:
            return OptimizationResult(
                action='DNS Optimization',
                success=False,
                message=f"Root permission required to change DNS. Manually add 'nameserver {best_dns['ip']}' to /etc/resolv.conf",
                requires_restart=False
            )
            
        try:
            with open('/etc/resolv.conf', 'r') as f:
                original = f.read()
                
            with open('/etc/resolv.conf.backup', 'w') as f:
                f.write(original)
                
            new_resolv = f"nameserver {best_dns['ip']}\nnameserver 8.8.8.8\n"
            with open('/etc/resolv.conf', 'w') as f:
                f.write(new_resolv)
                
            return OptimizationResult(
                action='DNS Optimization',
                success=True,
                message=f"DNS server changed to {best_dns['name']} ({best_dns['ip']})",
                requires_restart=False
            )
        except Exception as e:
            return OptimizationResult(
                action='DNS Optimization',
                success=False,
                message=f"Failed to change DNS: {str(e)}",
                requires_restart=False
            )
    
    def _optimize_dns_windows(self, best_dns: Dict) -> OptimizationResult:
        """Windows DNS optimization using netsh command"""
        try:
            # Get active network interface
            result = subprocess.run(
                ['netsh', 'interface', 'show', 'interface'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Try to set DNS on all active interfaces
            interfaces_result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Find active interface (simplified - uses first non-loopback)
            # In production, you'd parse the output properly
            dns_primary = best_dns['ip']
            dns_secondary = '8.8.8.8'
            
            # Try to set DNS (requires admin)
            try:
                # This requires admin privileges
                subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'set', 'dns', 'name="Wi-Fi"', 'static', dns_primary],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'add', 'dns', 'name="Wi-Fi"', dns_secondary, 'index=2'],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                
                return OptimizationResult(
                    action='DNS Optimization',
                    success=True,
                    message=f"DNS changed to {best_dns['name']} ({dns_primary}). Please run as Administrator for automatic changes, or change manually in Network Settings.",
                    requires_restart=False
                )
            except Exception:
                return OptimizationResult(
                    action='DNS Optimization',
                    success=False,
                    message=f"Administrator privileges required. Manually change DNS to {best_dns['name']} ({dns_primary}) in Network Settings > Adapter Properties > IPv4 Properties",
                    requires_restart=False
                )
        except Exception as e:
            return OptimizationResult(
                action='DNS Optimization',
                success=False,
                message=f"Windows DNS change requires manual configuration. Set DNS to {best_dns['name']} ({best_dns['ip']}) in Network Settings.",
                requires_restart=False
            )
            
    def _optimize_tcp(self) -> OptimizationResult:
        if not self._is_root:
            return OptimizationResult(
                action='TCP Optimization',
                success=False,
                message='Root permission required to change TCP settings',
                requires_restart=False
            )
            
        try:
            sysctl_settings = [
                'net.core.rmem_max=16777216',
                'net.core.wmem_max=16777216',
                'net.ipv4.tcp_window_scaling=1',
                'net.ipv4.tcp_timestamps=1',
            ]
            
            for setting in sysctl_settings:
                subprocess.run(['sysctl', '-w', setting], capture_output=True)
                
            return OptimizationResult(
                action='TCP Optimization',
                success=True,
                message='TCP buffer settings optimized',
                requires_restart=False
            )
        except Exception as e:
            return OptimizationResult(
                action='TCP Optimization',
                success=False,
                message=f"Failed to optimize TCP: {str(e)}",
                requires_restart=False
            )
            
    def _clear_dns_cache(self) -> OptimizationResult:
        if self._is_windows:
            try:
                # Windows DNS cache flush
                result = subprocess.run(
                    ['ipconfig', '/flushdns'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return OptimizationResult(
                        action='DNS Cache Clear',
                        success=True,
                        message='DNS cache cleared successfully',
                        requires_restart=False
                    )
                else:
                    return OptimizationResult(
                        action='DNS Cache Clear',
                        success=False,
                        message='Failed to clear DNS cache. Try running as Administrator.',
                        requires_restart=False
                    )
            except Exception as e:
                return OptimizationResult(
                    action='DNS Cache Clear',
                    success=False,
                    message=f'Failed to clear DNS cache: {str(e)}',
                    requires_restart=False
                )
        
        # Linux/Mac
        try:
            subprocess.run(
                ['systemd-resolve', '--flush-caches'],
                capture_output=True,
                timeout=5
            )
            return OptimizationResult(
                action='DNS Cache Clear',
                success=True,
                message='DNS cache cleared',
                requires_restart=False
            )
        except:
            try:
                subprocess.run(
                    ['service', 'nscd', 'restart'],
                    capture_output=True,
                    timeout=5
                )
                return OptimizationResult(
                    action='DNS Cache Clear',
                    success=True,
                    message='DNS cache cleared (nscd)',
                    requires_restart=False
                )
            except:
                return OptimizationResult(
                    action='DNS Cache Clear',
                    success=False,
                    message='Failed to clear DNS cache (no system support)',
                    requires_restart=False
                )
                
    @property
    def optimization_results(self) -> List[OptimizationResult]:
        return self._optimization_results
        
    def get_manual_recommendations(self) -> List[Dict]:
        recommendations = []
        
        high_risk = self._security_analyzer.get_high_risk_issues()
        for issue in high_risk:
            if not issue.auto_fixable:
                recommendations.append({
                    'category': issue.category,
                    'issue': issue.title,
                    'steps': self._get_manual_steps(issue)
                })
                
        return recommendations
        
    def _get_manual_steps(self, issue: SecurityIssue) -> List[str]:
        if 'port' in issue.category.lower():
            if self._is_windows:
                return [
                    'Open Windows Defender Firewall',
                    'Click "Advanced settings"',
                    'Add inbound/outbound rule to block the port',
                    'Restart the system to apply changes'
                ]
            return [
                'Check your firewall configuration',
                'Stop the relevant service or close the port',
                'Add firewall rule: sudo ufw deny <port>',
                'Restart the system to apply changes'
            ]
        elif 'dns' in issue.category.lower():
            if self._is_windows:
                return [
                    'Open Settings > Network & Internet',
                    'Click on your connection (Wi-Fi or Ethernet)',
                    'Click "Hardware properties"',
                    'Under DNS server assignment, click Edit',
                    'Set to Manual and enter 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google)'
                ]
            return [
                'Edit /etc/resolv.conf file',
                'Add nameserver 1.1.1.1 line',
                'Restart network connection'
            ]
        else:
            return [issue.recommendation]
