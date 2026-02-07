import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str
    entry_type: str


@dataclass
class ArpSpoofingAlert:
    alert_type: str
    description: str
    risk_level: str
    affected_ips: List[str]
    suspicious_mac: str


class ArpAnalyzer:
    def __init__(self, gateway: Optional[str] = None):
        self._gateway = gateway
        self._arp_table: List[ArpEntry] = []
        self._alerts: List[ArpSpoofingAlert] = []
        self._gateway_mac: Optional[str] = None
        self._previous_gateway_mac: Optional[str] = None
        self._is_windows = platform.system() == 'Windows'

    @property
    def arp_table(self) -> List[ArpEntry]:
        return self._arp_table

    @property
    def alerts(self) -> List[ArpSpoofingAlert]:
        return self._alerts

    @property
    def gateway_mac(self) -> Optional[str]:
        return self._gateway_mac

    def set_previous_gateway_mac(self, mac: str) -> None:
        self._previous_gateway_mac = mac

    def get_arp_table(self) -> List[ArpEntry]:
        self._arp_table = []
        if self._is_windows:
            self._parse_arp_windows()
        else:
            self._parse_arp_linux()
        return self._arp_table

    def _parse_arp_windows(self) -> None:
        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                timeout=10
            )
            current_interface = 'unknown'
            for line in result.stdout.split('\n'):
                iface_match = re.search(
                    r'Interface:\s*(\d+\.\d+\.\d+\.\d+)', line
                )
                if iface_match:
                    current_interface = iface_match.group(1)
                    continue

                entry_match = re.match(
                    r'\s*(\d+\.\d+\.\d+\.\d+)\s+'
                    r'([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+'
                    r'(\S+)',
                    line
                )
                if entry_match:
                    ip = entry_match.group(1)
                    mac = entry_match.group(2).lower().replace('-', ':')
                    entry_type = entry_match.group(3).strip()
                    self._arp_table.append(ArpEntry(
                        ip=ip,
                        mac=mac,
                        interface=current_interface,
                        entry_type=entry_type
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Failed to read ARP table: %s", e)

    def _parse_arp_linux(self) -> None:
        try:
            result = subprocess.run(
                ['arp', '-n'],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    mac = parts[2].lower()
                    interface = parts[4]
                    if mac != '(incomplete)':
                        self._arp_table.append(ArpEntry(
                            ip=ip,
                            mac=mac,
                            interface=interface,
                            entry_type='dynamic'
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Failed to read ARP table: %s", e)

    def detect_spoofing(self) -> List[ArpSpoofingAlert]:
        self._alerts = []

        if not self._arp_table:
            self.get_arp_table()

        self._check_duplicate_macs()
        self._check_gateway_mac()

        return self._alerts

    def _check_duplicate_macs(self) -> None:
        mac_to_ips: Dict[str, List[str]] = {}
        for entry in self._arp_table:
            if entry.mac == 'ff:ff:ff:ff:ff:ff':
                continue
            if entry.mac.startswith('01:00:5e'):
                continue
            mac_to_ips.setdefault(entry.mac, []).append(entry.ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                self._alerts.append(ArpSpoofingAlert(
                    alert_type='duplicate_mac',
                    description=(
                        f"MAC address {mac} is associated with multiple IPs: "
                        f"{', '.join(ips)}. This may indicate ARP spoofing."
                    ),
                    risk_level='critical',
                    affected_ips=ips,
                    suspicious_mac=mac
                ))

    def check_gateway_mac(self) -> Optional[ArpSpoofingAlert]:
        if not self._gateway:
            return None

        for entry in self._arp_table:
            if entry.ip == self._gateway:
                self._gateway_mac = entry.mac
                break

        if not self._gateway_mac:
            return None

        if (self._previous_gateway_mac
                and self._gateway_mac != self._previous_gateway_mac):
            alert = ArpSpoofingAlert(
                alert_type='gateway_mac_changed',
                description=(
                    f"Gateway ({self._gateway}) MAC address changed from "
                    f"{self._previous_gateway_mac} to {self._gateway_mac}. "
                    f"This may indicate ARP spoofing or gateway replacement."
                ),
                risk_level='critical',
                affected_ips=[self._gateway],
                suspicious_mac=self._gateway_mac
            )
            self._alerts.append(alert)
            return alert

        return None

    def _check_gateway_mac(self) -> None:
        self.check_gateway_mac()

    def get_summary(self) -> Dict:
        return {
            'total_entries': len(self._arp_table),
            'alerts': len(self._alerts),
            'gateway_mac': self._gateway_mac,
            'spoofing_detected': any(
                a.alert_type == 'duplicate_mac' for a in self._alerts
            ),
            'gateway_mac_changed': any(
                a.alert_type == 'gateway_mac_changed' for a in self._alerts
            ),
        }
