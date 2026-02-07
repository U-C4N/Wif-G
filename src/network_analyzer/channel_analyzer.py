import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Non-overlapping channels for 2.4 GHz
NON_OVERLAPPING_2GHZ = [1, 6, 11]

# Common 5 GHz channels
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    signal: int
    channel: int
    band: str
    authentication: str
    encryption: str


@dataclass
class ChannelInfo:
    channel: int
    band: str
    ap_count: int
    avg_signal: float
    interference_score: float
    access_points: List[str] = field(default_factory=list)


@dataclass
class ChannelRecommendation:
    band: str
    recommended_channel: int
    reason: str
    current_channel: Optional[int]
    interference_score: float


class WiFiChannelAnalyzer:
    def __init__(self):
        self._access_points: List[AccessPoint] = []
        self._channel_analysis: Dict[str, List[ChannelInfo]] = {
            '2.4GHz': [],
            '5GHz': [],
        }
        self._is_windows = platform.system() == 'Windows'

    def scan_networks(self) -> List[AccessPoint]:
        """Scan for visible WiFi networks and their channel/signal info."""
        if not self._is_windows:
            logger.warning("WiFi channel analysis is only supported on Windows")
            return []

        self._access_points = []

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode != 0:
                logger.debug("netsh wlan show networks failed: %s", result.stderr)
                return []

            self._parse_network_output(result.stdout)

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not scan WiFi networks: %s", e)

        return self._access_points

    def _parse_network_output(self, output: str) -> None:
        """Parse netsh wlan show networks mode=bssid output."""
        # Split into blocks per SSID line (not BSSID)
        blocks = re.split(r'(?m)(?=^[ \t]*SSID \d+\s*:)', output)

        for block in blocks:
            if not block.strip():
                continue

            # Match SSID line but not BSSID line
            ssid_match = re.search(r'(?<![B])SSID \d+\s*:\s*(.*)', block)
            ssid = ssid_match.group(1).strip() if ssid_match else ''

            auth_match = re.search(r'Authentication\s*:\s*(.+)', block)
            if not auth_match:
                auth_match = re.search(r'Kimlik do.rulama\s*:\s*(.+)', block)
            authentication = auth_match.group(1).strip() if auth_match else 'Unknown'

            enc_match = re.search(r'Encryption\s*:\s*(.+)', block)
            if not enc_match:
                enc_match = re.search(r'ifreleme\s*:\s*(.+)', block)
            encryption = enc_match.group(1).strip() if enc_match else 'Unknown'

            # Each SSID block can have multiple BSSIDs
            bssid_blocks = re.split(r'(?=BSSID \d+\s*:)', block)
            for bssid_block in bssid_blocks:
                bssid_match = re.search(r'BSSID \d+\s*:\s*([0-9a-fA-F:]+)', bssid_block)
                if not bssid_match:
                    continue
                bssid = bssid_match.group(1).strip()

                signal_match = re.search(r'Signal\s*:\s*(\d+)%', bssid_block)
                if not signal_match:
                    signal_match = re.search(r'Sinyal\s*:\s*(\d+)%', bssid_block)
                signal = int(signal_match.group(1)) if signal_match else 0

                channel_match = re.search(r'Channel\s*:\s*(\d+)', bssid_block)
                if not channel_match:
                    channel_match = re.search(r'Kanal\s*:\s*(\d+)', bssid_block)
                channel = int(channel_match.group(1)) if channel_match else 0

                if channel == 0:
                    continue

                band = '5GHz' if channel >= 36 else '2.4GHz'

                self._access_points.append(AccessPoint(
                    ssid=ssid,
                    bssid=bssid,
                    signal=signal,
                    channel=channel,
                    band=band,
                    authentication=authentication,
                    encryption=encryption,
                ))

    def analyze_channels(self) -> Dict[str, List[ChannelInfo]]:
        """Analyze channel congestion and interference for both bands."""
        if not self._access_points:
            self.scan_networks()

        self._channel_analysis = {'2.4GHz': [], '5GHz': []}

        # Group APs by channel
        channel_aps: Dict[int, List[AccessPoint]] = {}
        for ap in self._access_points:
            channel_aps.setdefault(ap.channel, []).append(ap)

        for channel, aps in sorted(channel_aps.items()):
            band = '5GHz' if channel >= 36 else '2.4GHz'
            avg_signal = sum(ap.signal for ap in aps) / len(aps) if aps else 0
            interference = self._calculate_interference(channel, band)

            info = ChannelInfo(
                channel=channel,
                band=band,
                ap_count=len(aps),
                avg_signal=round(avg_signal, 1),
                interference_score=round(interference, 1),
                access_points=[ap.ssid or '(Hidden)' for ap in aps],
            )
            self._channel_analysis[band].append(info)

        # Sort by channel number
        for band in self._channel_analysis:
            self._channel_analysis[band].sort(key=lambda c: c.channel)

        return self._channel_analysis

    def _calculate_interference(self, channel: int, band: str) -> float:
        """Calculate interference score for a channel (0-100, lower is better).

        For 2.4GHz, overlapping channels within +/-4 channels contribute
        interference weighted by proximity and signal strength.
        For 5GHz, only same-channel APs contribute (no overlap between channels).
        """
        score = 0.0

        for ap in self._access_points:
            if ap.band != band:
                continue

            if band == '2.4GHz':
                distance = abs(ap.channel - channel)
                if distance == 0:
                    weight = 1.0
                elif distance <= 4:
                    weight = (5 - distance) / 5.0
                else:
                    continue
            else:
                # 5GHz channels don't overlap
                if ap.channel != channel:
                    continue
                weight = 1.0

            # Higher signal from other APs means more interference
            signal_factor = ap.signal / 100.0
            score += weight * signal_factor * 20

        return min(score, 100.0)

    def get_recommendation(self) -> List[ChannelRecommendation]:
        """Recommend the best channel for each band."""
        if not self._channel_analysis['2.4GHz'] and not self._channel_analysis['5GHz']:
            self.analyze_channels()

        recommendations = []
        current_channel = self._get_current_channel()

        # 2.4GHz recommendation - only consider non-overlapping channels
        rec_2g = self._recommend_2ghz(current_channel)
        if rec_2g:
            recommendations.append(rec_2g)

        # 5GHz recommendation
        rec_5g = self._recommend_5ghz(current_channel)
        if rec_5g:
            recommendations.append(rec_5g)

        return recommendations

    def _recommend_2ghz(self, current_channel: Optional[int]) -> Optional[ChannelRecommendation]:
        """Find the best non-overlapping 2.4GHz channel."""
        # Calculate interference for each non-overlapping channel
        channel_scores: Dict[int, float] = {}
        for ch in NON_OVERLAPPING_2GHZ:
            channel_scores[ch] = self._calculate_interference(ch, '2.4GHz')

        if not channel_scores:
            return None

        best_channel = min(channel_scores, key=channel_scores.get)
        best_score = channel_scores[best_channel]

        # Count APs on best channel
        ap_count = sum(1 for ap in self._access_points
                       if ap.channel == best_channel and ap.band == '2.4GHz')

        current_2g = current_channel if current_channel and current_channel < 36 else None

        if current_2g and current_2g == best_channel:
            reason = f'Kanal {best_channel} zaten en uygun kanal (girismim skoru: {best_score:.0f})'
        else:
            reason = (f'Kanal {best_channel} en az yogun kanal '
                      f'({ap_count} AG, girisim skoru: {best_score:.0f})')

        return ChannelRecommendation(
            band='2.4GHz',
            recommended_channel=best_channel,
            reason=reason,
            current_channel=current_2g,
            interference_score=best_score,
        )

    def _recommend_5ghz(self, current_channel: Optional[int]) -> Optional[ChannelRecommendation]:
        """Find the best 5GHz channel."""
        has_5ghz_aps = any(ap.band == '5GHz' for ap in self._access_points)

        if not has_5ghz_aps:
            return None

        channel_scores: Dict[int, float] = {}
        for ap in self._access_points:
            if ap.band == '5GHz' and ap.channel not in channel_scores:
                channel_scores[ap.channel] = self._calculate_interference(ap.channel, '5GHz')

        # Also consider channels with 0 APs that are in range
        for ch in CHANNELS_5GHZ:
            if ch not in channel_scores:
                channel_scores[ch] = 0.0

        if not channel_scores:
            return None

        best_channel = min(channel_scores, key=channel_scores.get)
        best_score = channel_scores[best_channel]

        ap_count = sum(1 for ap in self._access_points
                       if ap.channel == best_channel and ap.band == '5GHz')

        current_5g = current_channel if current_channel and current_channel >= 36 else None

        if current_5g and current_5g == best_channel:
            reason = f'Kanal {best_channel} zaten en uygun 5GHz kanali (girisim skoru: {best_score:.0f})'
        else:
            reason = (f'Kanal {best_channel} en az yogun 5GHz kanali '
                      f'({ap_count} AG, girisim skoru: {best_score:.0f})')

        return ChannelRecommendation(
            band='5GHz',
            recommended_channel=best_channel,
            reason=reason,
            current_channel=current_5g,
            interference_score=best_score,
        )

    def _get_current_channel(self) -> Optional[int]:
        """Get the channel of the currently connected WiFi network."""
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                timeout=5
            )
            match = re.search(r'Channel\s*:\s*(\d+)', result.stdout)
            if not match:
                match = re.search(r'Kanal\s*:\s*(\d+)', result.stdout)
            if match:
                return int(match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not detect current WiFi channel: %s", e)
        return None

    @property
    def access_points(self) -> List[AccessPoint]:
        return self._access_points

    @property
    def channel_analysis(self) -> Dict[str, List[ChannelInfo]]:
        return self._channel_analysis

    def get_summary(self) -> Dict:
        """Return a summary of channel analysis."""
        if not self._access_points:
            self.scan_networks()
        if not self._channel_analysis['2.4GHz'] and not self._channel_analysis['5GHz']:
            self.analyze_channels()

        total_aps = len(self._access_points)
        aps_2g = sum(1 for ap in self._access_points if ap.band == '2.4GHz')
        aps_5g = sum(1 for ap in self._access_points if ap.band == '5GHz')
        channels_2g = len(self._channel_analysis.get('2.4GHz', []))
        channels_5g = len(self._channel_analysis.get('5GHz', []))

        most_congested = None
        max_aps = 0
        for info_list in self._channel_analysis.values():
            for info in info_list:
                if info.ap_count > max_aps:
                    max_aps = info.ap_count
                    most_congested = info.channel

        return {
            'total_access_points': total_aps,
            'access_points_2ghz': aps_2g,
            'access_points_5ghz': aps_5g,
            'active_channels_2ghz': channels_2g,
            'active_channels_5ghz': channels_5g,
            'most_congested_channel': most_congested,
            'most_congested_ap_count': max_aps,
            'current_channel': self._get_current_channel(),
        }
