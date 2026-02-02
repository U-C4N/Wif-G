import socket
import re
import logging
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    port: int
    state: str
    service: str
    risk_level: str
    description: str


def validate_target(target: str) -> bool:
    """Validate that target is a valid IP address or hostname."""
    # Allow localhost
    if target in ('localhost', '127.0.0.1'):
        return True
    # Check valid IPv4
    ip_pattern = re.compile(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    )
    match = ip_pattern.match(target)
    if match:
        return all(0 <= int(g) <= 255 for g in match.groups())
    # Allow valid hostnames
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(hostname_pattern.match(target))


def validate_port(port: int) -> bool:
    """Validate port number is in valid range."""
    return isinstance(port, int) and 1 <= port <= 65535


class PortScanner:
    MAX_WORKERS = 50

    CRITICAL_PORTS = [22, 23, 80, 443, 445, 3389]

    COMMON_PORTS = {
        20: ('FTP Data', 'medium', 'File Transfer Protocol data'),
        21: ('FTP', 'high', 'File Transfer Protocol - often attacked'),
        22: ('SSH', 'low', 'Secure Shell - generally safe if updated'),
        23: ('Telnet', 'critical', 'Unencrypted remote access - very dangerous'),
        25: ('SMTP', 'medium', 'Mail server - can be abused for spam'),
        53: ('DNS', 'low', 'Domain Name System'),
        80: ('HTTP', 'medium', 'Web server - unencrypted'),
        110: ('POP3', 'medium', 'Email retrieval - often unencrypted'),
        135: ('RPC', 'high', 'Windows RPC - frequently targeted'),
        139: ('NetBIOS', 'high', 'Windows file sharing - security risk'),
        143: ('IMAP', 'medium', 'Email access protocol'),
        443: ('HTTPS', 'low', 'Secure web server'),
        445: ('SMB', 'critical', 'Windows file sharing - major attack vector'),
        993: ('IMAPS', 'low', 'Secure IMAP'),
        995: ('POP3S', 'low', 'Secure POP3'),
        1433: ('MSSQL', 'high', 'Microsoft SQL Server'),
        1434: ('MSSQL Browser', 'high', 'SQL Server Browser'),
        3306: ('MySQL', 'high', 'MySQL Database - should not be exposed'),
        3389: ('RDP', 'critical', 'Remote Desktop - major security risk'),
        5432: ('PostgreSQL', 'high', 'PostgreSQL Database'),
        5900: ('VNC', 'high', 'Virtual Network Computing'),
        6379: ('Redis', 'high', 'Redis Database - often unsecured'),
        8080: ('HTTP-Alt', 'medium', 'Alternative HTTP port'),
        8443: ('HTTPS-Alt', 'low', 'Alternative HTTPS port'),
        27017: ('MongoDB', 'high', 'MongoDB - often misconfigured'),
    }

    DANGEROUS_PORTS = [23, 135, 139, 445, 3389, 1433, 3306, 5432, 27017, 6379]

    def __init__(self, target: str = 'localhost', timeout: float = 1.0):
        if not validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        self._target = target
        self._timeout = timeout
        self._open_ports: List[PortInfo] = []
        self._scan_completed = False

    @property
    def target(self) -> str:
        return self._target

    @target.setter
    def target(self, value: str) -> None:
        if not validate_target(value):
            raise ValueError(f"Invalid target: {value}")
        self._target = value
        self._scan_completed = False

    @property
    def open_ports(self) -> List[PortInfo]:
        return self._open_ports

    def _check_port(self, port: int) -> Optional[PortInfo]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self._timeout)
            result = sock.connect_ex((self._target, port))
            sock.close()

            if result == 0:
                service, risk, desc = self.COMMON_PORTS.get(
                    port,
                    ('Unknown', 'medium', 'Unknown service')
                )
                return PortInfo(
                    port=port,
                    state='open',
                    service=service,
                    risk_level=risk,
                    description=desc
                )
        except socket.error as e:
            logger.debug("Error checking port %d: %s", port, e)
        return None

    def scan_common_ports(self) -> List[PortInfo]:
        self._open_ports = []
        ports_to_scan = list(self.COMMON_PORTS.keys())

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self._open_ports.append(result)

        self._open_ports.sort(key=lambda x: x.port)
        self._scan_completed = True
        return self._open_ports

    def quick_scan(self) -> List[PortInfo]:
        self._open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {executor.submit(self._check_port, port): port for port in self.CRITICAL_PORTS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self._open_ports.append(result)

        self._open_ports.sort(key=lambda x: x.port)
        self._scan_completed = True
        return self._open_ports

    def scan_port_range(self, start: int = 1, end: int = 1024) -> List[PortInfo]:
        if not (validate_port(start) and validate_port(end)):
            raise ValueError(f"Invalid port range: {start}-{end}")
        if start > end:
            raise ValueError(f"Start port {start} must be <= end port {end}")

        self._open_ports = []
        ports_to_scan = range(start, end + 1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self._open_ports.append(result)

        self._open_ports.sort(key=lambda x: x.port)
        self._scan_completed = True
        return self._open_ports

    def get_dangerous_ports(self) -> List[PortInfo]:
        return [p for p in self._open_ports if p.risk_level in ('high', 'critical')]

    def get_critical_ports(self) -> List[PortInfo]:
        return [p for p in self._open_ports if p.risk_level == 'critical']

    def get_port_recommendations(self) -> List[Dict]:
        recommendations = []
        for port_info in self.get_dangerous_ports():
            rec = {
                'port': port_info.port,
                'service': port_info.service,
                'risk_level': port_info.risk_level,
                'recommendation': self.get_recommendation(port_info)
            }
            recommendations.append(rec)
        return recommendations

    def get_recommendation(self, port_info: PortInfo) -> str:
        recommendations = {
            23: 'Stop using Telnet, use SSH instead',
            135: 'Disable RPC service or block it with firewall',
            139: 'Disable NetBIOS service',
            445: 'Close SMB port to external access',
            3389: 'Use VPN instead of RDP or change the port number',
            1433: 'Close SQL Server to external access',
            3306: 'Bind MySQL to localhost only',
            5432: 'Open PostgreSQL only to trusted IPs',
            6379: 'Protect Redis with password and close external access',
            27017: 'Enable MongoDB authentication',
        }
        return recommendations.get(
            port_info.port,
            f'Review {port_info.service} service and close it if not needed'
        )
