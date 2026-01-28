import socket
import subprocess
import re
from typing import Dict, List, Optional
import psutil
import netifaces


class NetworkScanner:
    def __init__(self):
        self._interfaces: Dict = {}
        self._gateway: Optional[str] = None
        self._local_ip: Optional[str] = None
        self._ssid: Optional[str] = None
        self._signal_strength: Optional[int] = None
        
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
                pass
                
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
