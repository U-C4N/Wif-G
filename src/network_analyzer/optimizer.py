import subprocess
import os
import re
import logging
import platform
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .security_analyzer import SecurityAnalyzer, SecurityIssue
from .dns_analyzer import DNSAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class OptimizationResult:
    action: str
    success: bool
    message: str
    requires_restart: bool


@dataclass
class TcpSettings:
    auto_tuning_level: Optional[str] = None
    ecn_capability: Optional[str] = None
    timestamps: Optional[str] = None
    rss: Optional[str] = None
    chimney_offload: Optional[str] = None


@dataclass
class MtuResult:
    interface_name: str
    current_mtu: int
    optimal_mtu: int
    changed: bool
    message: str


def _sanitize_interface_name(name: str) -> str:
    """Sanitize interface name to prevent injection."""
    return re.sub(r'[^a-zA-Z0-9_ \-()]', '', name)


def _detect_wifi_interface() -> Optional[str]:
    """Detect the active WiFi interface name on Windows."""
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            timeout=5
        )
        match = re.search(r'Name\s*:\s*(.+)', result.stdout)
        if match:
            return match.group(1).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        logger.debug("Could not detect WiFi interface: %s", e)
    return None


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
            'description': 'Optimize TCP/IP stack: auto-tuning, ECN, timestamps, RSS, Nagle algorithm',
            'impact': 'Faster data transfer',
            'risk': 'Low',
            'auto_applicable': self._is_root or self._is_windows
        })

        if self._is_windows:
            plan.append({
                'id': 'mtu_optimization',
                'title': 'Optimize MTU',
                'description': 'Discover and set optimal MTU to prevent fragmentation',
                'impact': 'Reduced fragmentation, better throughput',
                'risk': 'Low',
                'auto_applicable': True
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
            'mtu_optimization': self._optimize_mtu,
            'dns_cache': self._clear_dns_cache,
        }

        if optimization_id.startswith('fix_'):
            if 'dns' in optimization_id.lower():
                return OptimizationResult(
                    action=optimization_id,
                    success=False,
                    message='DNS issues are addressed by DNS optimization. Please run DNS optimization separately.',
                    requires_restart=False
                )
            else:
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
        except (OSError, PermissionError) as e:
            return OptimizationResult(
                action='DNS Optimization',
                success=False,
                message=f"Failed to change DNS: {str(e)}",
                requires_restart=False
            )

    def _optimize_dns_windows(self, best_dns: Dict) -> OptimizationResult:
        try:
            interface_name = _detect_wifi_interface()
            if not interface_name:
                interface_name = 'Wi-Fi'
            interface_name = _sanitize_interface_name(interface_name)

            dns_primary = best_dns['ip']
            dns_secondary = '8.8.8.8'

            try:
                subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'set', 'dns',
                     f'name={interface_name}', 'static', dns_primary],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'add', 'dns',
                     f'name={interface_name}', dns_secondary, 'index=2'],
                    capture_output=True,
                    timeout=5,
                    check=False
                )

                return OptimizationResult(
                    action='DNS Optimization',
                    success=True,
                    message=f"DNS changed to {best_dns['name']} ({dns_primary}). Run as Administrator for automatic changes, or change manually in Network Settings.",
                    requires_restart=False
                )
            except (subprocess.SubprocessError, OSError) as e:
                logger.debug("Windows DNS optimization failed: %s", e)
                return OptimizationResult(
                    action='DNS Optimization',
                    success=False,
                    message=f"Administrator privileges required. Manually change DNS to {best_dns['name']} ({dns_primary}) in Network Settings > Adapter Properties > IPv4 Properties",
                    requires_restart=False
                )
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug("Windows DNS optimization error: %s", e)
            return OptimizationResult(
                action='DNS Optimization',
                success=False,
                message=f"Windows DNS change requires manual configuration. Set DNS to {best_dns['name']} ({best_dns['ip']}) in Network Settings.",
                requires_restart=False
            )

    def _optimize_tcp(self) -> OptimizationResult:
        if self._is_windows:
            return self._optimize_tcp_windows()

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
                subprocess.run(['sysctl', '-w', setting], capture_output=True, check=True)

            return OptimizationResult(
                action='TCP Optimization',
                success=True,
                message='TCP buffer settings optimized',
                requires_restart=False
            )
        except (subprocess.SubprocessError, OSError) as e:
            return OptimizationResult(
                action='TCP Optimization',
                success=False,
                message=f"Failed to optimize TCP: {str(e)}",
                requires_restart=False
            )

    def _read_tcp_settings_windows(self) -> TcpSettings:
        """Read current Windows TCP global settings via netsh."""
        settings = TcpSettings()
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'tcp', 'show', 'global'],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout

            match = re.search(r'Receive Window Auto-Tuning Level\s*:\s*(\S+)', output)
            if match:
                settings.auto_tuning_level = match.group(1).strip()

            match = re.search(r'ECN Capability\s*:\s*(\S+)', output)
            if match:
                settings.ecn_capability = match.group(1).strip()

            match = re.search(r'Timestamps\s*:\s*(\S+)', output)
            if match:
                settings.timestamps = match.group(1).strip()

            match = re.search(r'Receive-Side Scaling State\s*:\s*(\S+)', output)
            if match:
                settings.rss = match.group(1).strip()

            match = re.search(r'Chimney Offload State\s*:\s*(\S+)', output)
            if match:
                settings.chimney_offload = match.group(1).strip()

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Failed to read TCP settings: %s", e)

        return settings

    def _optimize_tcp_windows(self) -> OptimizationResult:
        """Optimize TCP/IP stack settings on Windows using netsh."""
        before = self._read_tcp_settings_windows()
        changes: List[str] = []
        errors: List[str] = []

        optimizations = [
            (['netsh', 'interface', 'tcp', 'set', 'global',
              'autotuninglevel=normal'], 'Auto-Tuning Level -> normal'),
            (['netsh', 'interface', 'tcp', 'set', 'global',
              'ecncapability=enabled'], 'ECN Capability -> enabled'),
            (['netsh', 'interface', 'tcp', 'set', 'global',
              'timestamps=enabled'], 'Timestamps -> enabled'),
            (['netsh', 'interface', 'tcp', 'set', 'global',
              'rss=enabled'], 'RSS -> enabled'),
        ]

        for cmd, description in optimizations:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    changes.append(description)
                else:
                    errors.append(f"{description}: {result.stderr.strip()}")
            except (subprocess.SubprocessError, OSError) as e:
                errors.append(f"{description}: {str(e)}")

        # Nagle algorithm optimization via registry
        nagle_result = self._optimize_nagle_windows()
        if nagle_result:
            changes.append(nagle_result)

        after = self._read_tcp_settings_windows()

        if changes:
            before_str = (f"Before: AutoTuning={before.auto_tuning_level}, "
                          f"ECN={before.ecn_capability}, "
                          f"Timestamps={before.timestamps}, "
                          f"RSS={before.rss}")
            after_str = (f"After: AutoTuning={after.auto_tuning_level}, "
                         f"ECN={after.ecn_capability}, "
                         f"Timestamps={after.timestamps}, "
                         f"RSS={after.rss}")
            msg = (f"TCP optimized: {', '.join(changes)}. "
                   f"{before_str}. {after_str}")
            if errors:
                msg += f". Warnings: {'; '.join(errors)}"
            return OptimizationResult(
                action='TCP Optimization',
                success=True,
                message=msg,
                requires_restart=False
            )

        return OptimizationResult(
            action='TCP Optimization',
            success=False,
            message=f"TCP optimization failed. Run as Administrator. Errors: {'; '.join(errors)}" if errors
                    else "TCP optimization failed. Run as Administrator.",
            requires_restart=False
        )

    def _optimize_nagle_windows(self) -> Optional[str]:
        """Disable Nagle algorithm on active network interfaces via registry."""
        if not self._is_windows:
            return None

        try:
            import winreg
        except ImportError:
            logger.debug("winreg not available")
            return None

        modified = 0
        base_path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as base_key:
                index = 0
                while True:
                    try:
                        guid = winreg.EnumKey(base_key, index)
                        iface_path = f'{base_path}\\{guid}'
                        try:
                            with winreg.OpenKey(
                                winreg.HKEY_LOCAL_MACHINE, iface_path,
                                0, winreg.KEY_READ | winreg.KEY_WRITE
                            ) as iface_key:
                                # Check if this interface has an IP (is active)
                                try:
                                    ip, _ = winreg.QueryValueEx(iface_key, 'DhcpIPAddress')
                                    if not ip or ip == '0.0.0.0':
                                        index += 1
                                        continue
                                except FileNotFoundError:
                                    try:
                                        ip, _ = winreg.QueryValueEx(iface_key, 'IPAddress')
                                        if not ip:
                                            index += 1
                                            continue
                                    except FileNotFoundError:
                                        index += 1
                                        continue

                                winreg.SetValueEx(
                                    iface_key, 'TcpNoDelay', 0,
                                    winreg.REG_DWORD, 1
                                )
                                winreg.SetValueEx(
                                    iface_key, 'TcpAckFrequency', 0,
                                    winreg.REG_DWORD, 1
                                )
                                modified += 1
                        except PermissionError:
                            logger.debug("No permission to modify registry for %s", guid)
                        except OSError as e:
                            logger.debug("Registry error for %s: %s", guid, e)
                        index += 1
                    except OSError:
                        break
        except (PermissionError, OSError) as e:
            logger.debug("Cannot access TCP interface registry: %s", e)
            return None

        if modified > 0:
            return f"Nagle disabled on {modified} interface(s) (TcpNoDelay=1, TcpAckFrequency=1)"
        return None

    def _clear_dns_cache(self) -> OptimizationResult:
        if self._is_windows:
            try:
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
            except (subprocess.SubprocessError, OSError) as e:
                return OptimizationResult(
                    action='DNS Cache Clear',
                    success=False,
                    message=f'Failed to clear DNS cache: {str(e)}',
                    requires_restart=False
                )

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
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
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
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                return OptimizationResult(
                    action='DNS Cache Clear',
                    success=False,
                    message='Failed to clear DNS cache (no system support)',
                    requires_restart=False
                )

    def _optimize_mtu(self, target: str = '8.8.8.8') -> OptimizationResult:
        """Discover and set optimal MTU on Windows."""
        if not self._is_windows:
            return OptimizationResult(
                action='MTU Optimization',
                success=False,
                message='MTU optimization is only supported on Windows',
                requires_restart=False
            )

        interface_name = _detect_wifi_interface() or 'Wi-Fi'
        interface_name = _sanitize_interface_name(interface_name)

        current_mtu = self._read_current_mtu(interface_name)
        optimal_mtu = self._discover_optimal_mtu(target)

        if optimal_mtu is None:
            return OptimizationResult(
                action='MTU Optimization',
                success=False,
                message=f"Could not discover optimal MTU. Current MTU: {current_mtu or 'unknown'}",
                requires_restart=False
            )

        if current_mtu and current_mtu == optimal_mtu:
            return OptimizationResult(
                action='MTU Optimization',
                success=True,
                message=f"MTU is already optimal at {current_mtu}",
                requires_restart=False
            )

        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'set', 'subinterface',
                 interface_name, f'mtu={optimal_mtu}', 'store=persistent'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return OptimizationResult(
                    action='MTU Optimization',
                    success=True,
                    message=f"MTU changed from {current_mtu or 'unknown'} to {optimal_mtu}",
                    requires_restart=False
                )
            else:
                return OptimizationResult(
                    action='MTU Optimization',
                    success=False,
                    message=f"Failed to set MTU. Run as Administrator. "
                            f"Optimal MTU: {optimal_mtu}, Current: {current_mtu or 'unknown'}. "
                            f"Error: {result.stderr.strip()}",
                    requires_restart=False
                )
        except (subprocess.SubprocessError, OSError) as e:
            return OptimizationResult(
                action='MTU Optimization',
                success=False,
                message=f"Failed to set MTU: {str(e)}. Optimal MTU: {optimal_mtu}",
                requires_restart=False
            )

    def _read_current_mtu(self, interface_name: str) -> Optional[int]:
        """Read current MTU for the given interface."""
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'show', 'subinterfaces'],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.splitlines():
                if interface_name.lower() in line.lower():
                    match = re.search(r'(\d+)\s+\d+\s+\d+', line)
                    if match:
                        return int(match.group(1))
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug("Failed to read MTU: %s", e)
        return None

    def _discover_optimal_mtu(
        self,
        target: str,
        low: int = 1200,
        high: int = 1500
    ) -> Optional[int]:
        """Binary search for optimal MTU using ping with Don't Fragment flag."""
        best_mtu = None

        while low <= high:
            mid = (low + high) // 2
            # Subtract 28 bytes for IP (20) + ICMP (8) headers
            payload_size = mid - 28

            if self._ping_with_df(target, payload_size):
                best_mtu = mid
                low = mid + 1
            else:
                high = mid - 1

        return best_mtu

    def _ping_with_df(self, target: str, payload_size: int) -> bool:
        """Ping with Don't Fragment flag. Returns True if no fragmentation needed."""
        try:
            result = subprocess.run(
                ['ping', '-f', '-l', str(payload_size), '-n', '1', '-w', '1000', target],
                capture_output=True,
                text=True,
                timeout=5
            )
            # If ping succeeds without fragmentation
            return result.returncode == 0 and 'fragment' not in result.stdout.lower()
        except (subprocess.SubprocessError, OSError):
            return False

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
