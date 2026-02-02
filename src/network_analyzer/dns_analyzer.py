import subprocess
import socket
import re
import struct
import random
import time
import logging
import platform
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


logger = logging.getLogger(__name__)


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = pattern.match(ip)
    if not match:
        return False
    return all(0 <= int(g) <= 255 for g in match.groups())


@dataclass
class DNSServer:
    ip: str
    name: Optional[str]
    response_time: Optional[float]
    is_public_resolver: bool
    provider: str


class DNSAnalyzer:
    KNOWN_DNS_PROVIDERS = {
        '8.8.8.8': ('Google DNS', True),
        '8.8.4.4': ('Google DNS', True),
        '1.1.1.1': ('Cloudflare DNS', True),
        '1.0.0.1': ('Cloudflare DNS', True),
        '9.9.9.9': ('Quad9 DNS', True),
        '149.112.112.112': ('Quad9 DNS', True),
        '208.67.222.222': ('OpenDNS', True),
        '208.67.220.220': ('OpenDNS', True),
        '94.140.14.14': ('AdGuard DNS', True),
        '94.140.15.15': ('AdGuard DNS', True),
    }

    RECOMMENDED_DNS = [
        {'ip': '1.1.1.1', 'name': 'Cloudflare', 'description': 'Fastest and privacy-focused'},
        {'ip': '8.8.8.8', 'name': 'Google', 'description': 'Reliable and widely used'},
        {'ip': '9.9.9.9', 'name': 'Quad9', 'description': 'Security-focused, blocks malicious sites'},
    ]

    def __init__(self):
        self._current_dns: List[DNSServer] = []
        self._dns_leaks: List[str] = []
        self._dns_cache: Dict[str, Optional[float]] = {}
        self._is_windows = platform.system() == 'Windows'

    def analyze(self) -> None:
        self._scan_current_dns()
        self._check_dns_security()

    def _scan_current_dns(self) -> None:
        self._current_dns = []
        dns_servers = self._get_dns_from_resolv()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dns = {executor.submit(self._measure_dns_response_cached, dns_ip): dns_ip for dns_ip in dns_servers}

            for future in concurrent.futures.as_completed(future_to_dns):
                dns_ip = future_to_dns[future]
                provider, is_public = self.KNOWN_DNS_PROVIDERS.get(
                    dns_ip,
                    ('ISP/Unknown', False)
                )
                response_time = future.result()

                self._current_dns.append(DNSServer(
                    ip=dns_ip,
                    name=None,
                    response_time=response_time,
                    is_public_resolver=is_public,
                    provider=provider
                ))

    def _get_dns_from_resolv(self) -> List[str]:
        dns_servers = []

        if self._is_windows:
            return self._get_dns_windows()

        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('nameserver'):
                        parts = line.split()
                        if len(parts) >= 2 and validate_ip(parts[1]):
                            dns_servers.append(parts[1])
        except FileNotFoundError:
            pass

        if not dns_servers:
            try:
                result = subprocess.run(
                    ['nmcli', 'dev', 'show'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'DNS' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match and validate_ip(match.group(1)):
                            dns_servers.append(match.group(1))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("Could not detect DNS servers via nmcli")

        return dns_servers

    def _get_dns_windows(self) -> List[str]:
        """Get DNS servers on Windows using nslookup and netsh."""
        dns_servers = []
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'show', 'dnsservers'],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match and validate_ip(match.group(1)):
                    ip = match.group(1)
                    if ip not in dns_servers:
                        dns_servers.append(ip)
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not get DNS via netsh: %s", e)

        if not dns_servers:
            try:
                result = subprocess.run(
                    ['nslookup', 'localhost'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                match = re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match and validate_ip(match.group(1)):
                    dns_servers.append(match.group(1))
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.debug("Could not get DNS via nslookup: %s", e)

        return dns_servers

    def _measure_dns_response_cached(self, dns_ip: str) -> Optional[float]:
        if dns_ip in self._dns_cache:
            return self._dns_cache[dns_ip]
        result = self._measure_dns_response(dns_ip)
        self._dns_cache[dns_ip] = result
        return result

    def _measure_dns_response(self, dns_ip: str) -> Optional[float]:
        if not validate_ip(dns_ip):
            logger.warning("Invalid DNS IP: %s", dns_ip)
            return None

        sock = None
        try:
            query = self._build_dns_query('google.com')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            start = time.time()
            sock.sendto(query, (dns_ip, 53))
            sock.recvfrom(512)
            end = time.time()

            return round((end - start) * 1000, 2)
        except (socket.error, OSError) as e:
            logger.debug("DNS response measurement failed for %s: %s", dns_ip, e)
            return None
        finally:
            if sock is not None:
                sock.close()

    def clear_cache(self) -> None:
        self._dns_cache.clear()

    def _build_dns_query(self, domain: str) -> bytes:
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1
        header = struct.pack('>HHHHHH', transaction_id, flags, questions, 0, 0, 0)

        query_name = b''
        for part in domain.split('.'):
            query_name += bytes([len(part)]) + part.encode()
        query_name += b'\x00'

        query_type = 1
        query_class = 1
        question = query_name + struct.pack('>HH', query_type, query_class)

        return header + question

    def _check_dns_security(self) -> None:
        self._dns_leaks = []
        for dns in self._current_dns:
            if not dns.is_public_resolver:
                self._dns_leaks.append(
                    f"DNS server {dns.ip} ({dns.provider}) is not a known public DNS - privacy policy unknown"
                )

    @property
    def current_dns(self) -> List[DNSServer]:
        return self._current_dns

    @property
    def dns_warnings(self) -> List[str]:
        return self._dns_leaks

    def get_dns_recommendations(self) -> List[Dict]:
        recommendations = []

        has_public_dns = any(dns.is_public_resolver for dns in self._current_dns)

        if not has_public_dns:
            recommendations.append({
                'type': 'warning',
                'message': 'You are not using a known public DNS server',
                'suggestion': 'Consider using Cloudflare (1.1.1.1) or Google (8.8.8.8) DNS'
            })

        slow_dns = [dns for dns in self._current_dns if dns.response_time and dns.response_time > 100]
        if slow_dns:
            recommendations.append({
                'type': 'performance',
                'message': 'Your DNS response time is slow',
                'suggestion': 'Consider switching to faster DNS servers'
            })

        return recommendations

    def get_best_dns_recommendation(self) -> Dict:
        return self.RECOMMENDED_DNS[0]
