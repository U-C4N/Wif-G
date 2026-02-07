import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    signal: Optional[int]
    channel: Optional[int]
    authentication: Optional[str]
    encryption: Optional[str]


@dataclass
class EvilTwinAlert:
    alert_type: str
    ssid: str
    description: str
    risk_level: str
    suspicious_aps: List[AccessPoint]


class EvilTwinDetector:
    def __init__(self, current_ssid: Optional[str] = None):
        self._current_ssid = current_ssid
        self._access_points: List[AccessPoint] = []
        self._alerts: List[EvilTwinAlert] = []
        self._is_windows = platform.system() == 'Windows'

    @property
    def access_points(self) -> List[AccessPoint]:
        return self._access_points

    @property
    def alerts(self) -> List[EvilTwinAlert]:
        return self._alerts

    def scan_access_points(self) -> List[AccessPoint]:
        self._access_points = []
        if self._is_windows:
            self._scan_windows()
        else:
            self._scan_linux()
        return self._access_points

    def _scan_windows(self) -> None:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                timeout=15
            )
            self._parse_netsh_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Failed to scan WiFi networks: %s", e)

    def _scan_linux(self) -> None:
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f',
                 'SSID,BSSID,SIGNAL,CHAN,SECURITY', 'dev', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=15
            )
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split(':')
                if len(parts) >= 5:
                    ssid = parts[0].strip()
                    bssid = ':'.join(parts[1:7]).strip().lower()
                    signal_str = parts[7].strip() if len(parts) > 7 else ''
                    channel_str = parts[8].strip() if len(parts) > 8 else ''
                    security = parts[9].strip() if len(parts) > 9 else ''

                    signal = int(signal_str) if signal_str.isdigit() else None
                    channel = (int(channel_str)
                               if channel_str.isdigit() else None)

                    self._access_points.append(AccessPoint(
                        ssid=ssid,
                        bssid=bssid,
                        signal=signal,
                        channel=channel,
                        authentication=security,
                        encryption=None
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Failed to scan WiFi on Linux: %s", e)

    def _parse_netsh_output(self, output: str) -> None:
        current_ssid = None
        current_bssid = None
        current_signal = None
        current_channel = None
        current_auth = None
        current_enc = None

        for line in output.split('\n'):
            line = line.strip()

            ssid_match = re.match(r'^SSID\s+\d+\s*:\s*(.+)', line)
            if ssid_match:
                if current_ssid is not None and current_bssid is not None:
                    self._access_points.append(AccessPoint(
                        ssid=current_ssid,
                        bssid=current_bssid,
                        signal=current_signal,
                        channel=current_channel,
                        authentication=current_auth,
                        encryption=current_enc
                    ))
                current_ssid = ssid_match.group(1).strip()
                current_bssid = None
                current_signal = None
                current_channel = None
                current_auth = None
                current_enc = None
                continue

            bssid_match = re.match(
                r'^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line
            )
            if bssid_match:
                if (current_ssid is not None
                        and current_bssid is not None):
                    self._access_points.append(AccessPoint(
                        ssid=current_ssid,
                        bssid=current_bssid,
                        signal=current_signal,
                        channel=current_channel,
                        authentication=current_auth,
                        encryption=current_enc
                    ))
                current_bssid = bssid_match.group(1).lower()
                current_signal = None
                current_channel = None
                continue

            signal_match = re.match(r'^Signal\s*:\s*(\d+)%', line)
            if signal_match:
                current_signal = int(signal_match.group(1))
                continue

            channel_match = re.match(r'^Channel\s*:\s*(\d+)', line)
            if channel_match:
                current_channel = int(channel_match.group(1))
                continue

            auth_match = re.match(r'^Authentication\s*:\s*(.+)', line)
            if auth_match:
                current_auth = auth_match.group(1).strip()
                continue

            enc_match = re.match(r'^Encryption\s*:\s*(.+)', line)
            if enc_match:
                current_enc = enc_match.group(1).strip()
                continue

        if current_ssid is not None and current_bssid is not None:
            self._access_points.append(AccessPoint(
                ssid=current_ssid,
                bssid=current_bssid,
                signal=current_signal,
                channel=current_channel,
                authentication=current_auth,
                encryption=current_enc
            ))

    def detect_evil_twins(self) -> List[EvilTwinAlert]:
        self._alerts = []

        if not self._access_points:
            self.scan_access_points()

        self._check_duplicate_ssids()
        self._check_signal_anomalies()
        self._check_security_downgrade()

        return self._alerts

    def _check_duplicate_ssids(self) -> None:
        ssid_to_aps: Dict[str, List[AccessPoint]] = {}
        for ap in self._access_points:
            if ap.ssid:
                ssid_to_aps.setdefault(ap.ssid, []).append(ap)

        for ssid, aps in ssid_to_aps.items():
            if len(aps) > 1:
                bssids = {ap.bssid for ap in aps}
                if len(bssids) > 1:
                    risk = 'critical' if ssid == self._current_ssid else 'high'
                    self._alerts.append(EvilTwinAlert(
                        alert_type='duplicate_ssid',
                        ssid=ssid,
                        description=(
                            f"Multiple access points found with SSID "
                            f"'{ssid}' ({len(bssids)} unique BSSIDs). "
                            f"This could indicate an Evil Twin attack."
                        ),
                        risk_level=risk,
                        suspicious_aps=aps
                    ))

    def _check_signal_anomalies(self) -> None:
        if not self._current_ssid:
            return

        current_aps = [
            ap for ap in self._access_points
            if ap.ssid == self._current_ssid and ap.signal is not None
        ]

        for ap in current_aps:
            if ap.signal is not None and ap.signal > 90:
                self._alerts.append(EvilTwinAlert(
                    alert_type='signal_anomaly',
                    ssid=ap.ssid,
                    description=(
                        f"Unusually strong signal ({ap.signal}%) from "
                        f"BSSID {ap.bssid}. A nearby rogue AP may be "
                        f"broadcasting a strong signal to attract clients."
                    ),
                    risk_level='medium',
                    suspicious_aps=[ap]
                ))

    def _check_security_downgrade(self) -> None:
        if not self._current_ssid:
            return

        current_aps = [
            ap for ap in self._access_points
            if ap.ssid == self._current_ssid
        ]

        auth_types = set()
        for ap in current_aps:
            if ap.authentication:
                auth_types.add(ap.authentication)

        if len(auth_types) > 1:
            has_open = any(
                a.lower() in ('open', 'none', '') for a in auth_types
            )
            if has_open:
                self._alerts.append(EvilTwinAlert(
                    alert_type='security_downgrade',
                    ssid=self._current_ssid,
                    description=(
                        f"SSID '{self._current_ssid}' has both secured and "
                        f"open access points. An attacker may be running an "
                        f"open AP to capture credentials."
                    ),
                    risk_level='critical',
                    suspicious_aps=[
                        ap for ap in current_aps
                        if ap.authentication
                        and ap.authentication.lower() in ('open', 'none', '')
                    ]
                ))

    def get_risk_assessment(self) -> Dict:
        has_evil_twin = any(
            a.alert_type == 'duplicate_ssid' for a in self._alerts
        )
        has_signal_anomaly = any(
            a.alert_type == 'signal_anomaly' for a in self._alerts
        )
        has_downgrade = any(
            a.alert_type == 'security_downgrade' for a in self._alerts
        )

        if has_downgrade or (has_evil_twin and has_signal_anomaly):
            overall_risk = 'critical'
        elif has_evil_twin:
            overall_risk = 'high'
        elif has_signal_anomaly:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'

        return {
            'overall_risk': overall_risk,
            'total_aps': len(self._access_points),
            'total_alerts': len(self._alerts),
            'evil_twin_detected': has_evil_twin,
            'signal_anomaly_detected': has_signal_anomaly,
            'security_downgrade_detected': has_downgrade,
        }
