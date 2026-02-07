import socket
import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass
import psutil
import netifaces

logger = logging.getLogger(__name__)


@dataclass
class ProcessConnection:
    pid: Optional[int]
    process_name: str
    exe_path: Optional[str]
    local_address: Optional[str]
    local_port: Optional[int]
    remote_address: Optional[str]
    remote_port: Optional[int]
    status: str
    is_external: bool
    suspicious: bool
    reason: Optional[str]


class NetworkScanner:
    def __init__(self):
        self._interfaces: Dict = {}
        self._gateway: Optional[str] = None
        self._local_ip: Optional[str] = None
        self._ssid: Optional[str] = None
        self._signal_strength: Optional[int] = None
        self._is_windows = platform.system() == 'Windows'

    def scan(self) -> None:
        self._scan_interfaces()
        self._scan_gateway()
        self._scan_wifi_info()

    def _scan_interfaces(self) -> None:
        self._interfaces = {}
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ipv4_info = addrs[netifaces.AF_INET][0]
                self._interfaces[interface] = {
                    'ip': ipv4_info.get('addr'),
                    'netmask': ipv4_info.get('netmask'),
                    'broadcast': ipv4_info.get('broadcast')
                }
                if ipv4_info.get('addr') and not ipv4_info['addr'].startswith('127.'):
                    self._local_ip = ipv4_info['addr']

    def _scan_gateway(self) -> None:
        gateways = netifaces.gateways()
        default_gw = gateways.get('default', {})
        if netifaces.AF_INET in default_gw:
            self._gateway = default_gw[netifaces.AF_INET][0]

    def _scan_wifi_info(self) -> None:
        if self._is_windows:
            self._scan_wifi_info_windows()
            return

        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout + result.stderr

            ssid_match = re.search(r'ESSID:"([^"]*)"', output)
            if ssid_match:
                self._ssid = ssid_match.group(1)

            signal_match = re.search(r'Signal level[=:](-?\d+)', output)
            if signal_match:
                self._signal_strength = int(signal_match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                result = subprocess.run(
                    ['nmcli', '-t', '-f', 'active,ssid,signal', 'dev', 'wifi'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if line.startswith('yes:'):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            self._ssid = parts[1]
                            self._signal_strength = int(parts[2]) if parts[2].isdigit() else None
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("Could not detect WiFi info via iwconfig or nmcli")

    def _scan_wifi_info_windows(self) -> None:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout

            ssid_match = re.search(r'SSID\s*:\s*(.+)', output)
            if ssid_match:
                self._ssid = ssid_match.group(1).strip()

            signal_match = re.search(r'Signal\s*:\s*(\d+)%', output)
            if signal_match:
                pct = int(signal_match.group(1))
                # Convert percentage to approximate dBm
                self._signal_strength = int((pct / 2) - 100)
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not detect WiFi info on Windows: %s", e)

    @property
    def interfaces(self) -> Dict:
        return self._interfaces

    @property
    def gateway(self) -> Optional[str]:
        return self._gateway

    @property
    def local_ip(self) -> Optional[str]:
        return self._local_ip

    @property
    def ssid(self) -> Optional[str]:
        return self._ssid

    @property
    def signal_strength(self) -> Optional[int]:
        return self._signal_strength

    def get_network_stats(self) -> Dict:
        stats = psutil.net_io_counters()
        return {
            'bytes_sent': stats.bytes_sent,
            'bytes_recv': stats.bytes_recv,
            'packets_sent': stats.packets_sent,
            'packets_recv': stats.packets_recv,
            'errors_in': stats.errin,
            'errors_out': stats.errout,
            'drop_in': stats.dropin,
            'drop_out': stats.dropout
        }

    def get_active_connections(self) -> List[Dict]:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        return connections

    KNOWN_SYSTEM_PROCESSES = {
        'svchost.exe', 'system', 'services.exe', 'lsass.exe',
        'csrss.exe', 'wininit.exe', 'winlogon.exe', 'explorer.exe',
        'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
        'searchindexer.exe', 'spoolsv.exe', 'dwm.exe',
        'runtimebroker.exe', 'applicationframehost.exe',
    }

    KNOWN_SAFE_PROCESSES = {
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe',
        'brave.exe', 'iexplore.exe', 'code.exe', 'python.exe',
        'pythonw.exe', 'node.exe', 'git.exe', 'ssh.exe',
        'outlook.exe', 'teams.exe', 'slack.exe', 'discord.exe',
        'spotify.exe', 'onedrive.exe', 'dropbox.exe',
        'windowsterminal.exe', 'powershell.exe', 'cmd.exe',
    }

    def get_process_connections(self) -> List[ProcessConnection]:
        results: List[ProcessConnection] = []

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, OSError) as e:
            logger.debug("Cannot access network connections: %s", e)
            return results

        for conn in connections:
            if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'CLOSE_WAIT'):
                continue

            pid = conn.pid
            process_name = 'unknown'
            exe_path = None

            if pid is not None:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name() or 'unknown'
                    try:
                        exe_path = proc.exe()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            local_ip = conn.laddr.ip if conn.laddr else None
            local_port = conn.laddr.port if conn.laddr else None
            remote_ip = conn.raddr.ip if conn.raddr else None
            remote_port = conn.raddr.port if conn.raddr else None

            is_external = self._is_external_ip(remote_ip) if remote_ip else False

            suspicious, reason = self._check_suspicious(
                process_name, exe_path, remote_ip, remote_port, is_external
            )

            results.append(ProcessConnection(
                pid=pid,
                process_name=process_name,
                exe_path=exe_path,
                local_address=local_ip,
                local_port=local_port,
                remote_address=remote_ip,
                remote_port=remote_port,
                status=conn.status,
                is_external=is_external,
                suspicious=suspicious,
                reason=reason
            ))

        results.sort(key=lambda x: (not x.suspicious, x.process_name))
        return results

    @staticmethod
    def _is_external_ip(ip: Optional[str]) -> bool:
        if not ip:
            return False
        if ip.startswith('127.') or ip == '::1':
            return False
        if ip.startswith('10.'):
            return False
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                return False
        if ip.startswith('192.168.'):
            return False
        if ip.startswith('169.254.'):
            return False
        return True

    def _check_suspicious(
        self,
        process_name: str,
        exe_path: Optional[str],
        remote_ip: Optional[str],
        remote_port: Optional[int],
        is_external: bool
    ) -> tuple:
        name_lower = process_name.lower()

        if not is_external:
            return False, None

        if name_lower == 'unknown':
            return True, 'Unknown process connecting to external IP'

        if (name_lower in self.KNOWN_SYSTEM_PROCESSES
                and name_lower != 'svchost.exe'):
            return True, (
                f'System process {process_name} connecting to external IP'
            )

        if exe_path and self._is_windows:
            system_root = (
                platform.os.environ.get('SystemRoot', r'C:\Windows') # type: ignore[attr-defined]
            )
            program_files = platform.os.environ.get( # type: ignore[attr-defined]
                'ProgramFiles', r'C:\Program Files'
            )
            program_files_x86 = platform.os.environ.get( # type: ignore[attr-defined]
                'ProgramFiles(x86)', r'C:\Program Files (x86)'
            )

            exe_lower = exe_path.lower()
            trusted_paths = [
                system_root.lower(),
                program_files.lower(),
                program_files_x86.lower(),
            ]
            in_trusted = any(exe_lower.startswith(p) for p in trusted_paths)
            if not in_trusted and name_lower not in self.KNOWN_SAFE_PROCESSES:
                return True, (
                    f'Process {process_name} running from untrusted path: '
                    f'{exe_path}'
                )

        return False, None
