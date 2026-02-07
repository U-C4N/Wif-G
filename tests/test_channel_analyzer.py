from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.channel_analyzer import (
    WiFiChannelAnalyzer, AccessPoint, ChannelInfo, ChannelRecommendation,
)


NETSH_NETWORKS_OUTPUT = """
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 85%
         Radio type         : 802.11n
         Channel            : 6

    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 60%
         Radio type         : 802.11ac
         Channel            : 36

SSID 2 : NeighborWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : ff:ee:dd:cc:bb:01
         Signal             : 45%
         Radio type         : 802.11n
         Channel            : 6

SSID 3 : FarAwayNet
    Network type            : Infrastructure
    Authentication          : WPA-Personal
    Encryption              : TKIP
    BSSID 1                 : 11:22:33:44:55:01
         Signal             : 30%
         Radio type         : 802.11n
         Channel            : 1

SSID 4 : Office5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ff:01
         Signal             : 70%
         Radio type         : 802.11ac
         Channel            : 36
"""


@pytest.fixture
def analyzer():
    a = WiFiChannelAnalyzer()
    a._is_windows = True
    return a


class TestWiFiChannelAnalyzer:
    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_networks(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(
            stdout=NETSH_NETWORKS_OUTPUT,
            returncode=0
        )

        aps = analyzer.scan_networks()

        # 5 BSSIDs total: HomeNetwork has 2 (ch6 + ch36), NeighborWiFi (ch6),
        # FarAwayNet (ch1), Office5G (ch36)
        assert len(aps) == 5
        # Channel 6 has 2 APs (HomeNetwork BSSID1 + NeighborWiFi)
        ch6_aps = [ap for ap in aps if ap.channel == 6]
        assert len(ch6_aps) == 2
        # Channel 36 has 2 APs (HomeNetwork BSSID2 + Office5G)
        ch36_aps = [ap for ap in aps if ap.channel == 36]
        assert len(ch36_aps) == 2
        # Channel 1 has 1 AP (FarAwayNet)
        ch1_aps = [ap for ap in aps if ap.channel == 1]
        assert len(ch1_aps) == 1

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_networks_parses_ssid(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(
            stdout=NETSH_NETWORKS_OUTPUT,
            returncode=0
        )

        aps = analyzer.scan_networks()

        ssids = [ap.ssid for ap in aps]
        assert 'HomeNetwork' in ssids
        assert 'NeighborWiFi' in ssids
        assert 'FarAwayNet' in ssids

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_networks_parses_signal(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(
            stdout=NETSH_NETWORKS_OUTPUT,
            returncode=0
        )

        aps = analyzer.scan_networks()

        home_ap = next(ap for ap in aps if ap.ssid == 'HomeNetwork' and ap.channel == 6)
        assert home_ap.signal == 85

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_networks_parses_band(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(
            stdout=NETSH_NETWORKS_OUTPUT,
            returncode=0
        )

        aps = analyzer.scan_networks()

        ch1 = next(ap for ap in aps if ap.channel == 1)
        assert ch1.band == '2.4GHz'

        ch36 = next(ap for ap in aps if ap.channel == 36)
        assert ch36.band == '5GHz'

    def test_analyze_channels(self, analyzer):
        analyzer._access_points = [
            AccessPoint('Net1', 'aa:bb:cc:dd:ee:01', 80, 1, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('Net2', 'aa:bb:cc:dd:ee:02', 60, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('Net3', 'aa:bb:cc:dd:ee:03', 50, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('Net4', 'aa:bb:cc:dd:ee:04', 70, 11, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('Net5', 'aa:bb:cc:dd:ee:05', 90, 36, '5GHz', 'WPA2', 'CCMP'),
        ]

        result = analyzer.analyze_channels()

        assert '2.4GHz' in result
        assert '5GHz' in result

        channels_2g = {ci.channel: ci for ci in result['2.4GHz']}
        assert 1 in channels_2g
        assert 6 in channels_2g
        assert 11 in channels_2g

        # Channel 6 has 2 APs
        assert channels_2g[6].ap_count == 2
        # Channel 1 has 1 AP
        assert channels_2g[1].ap_count == 1

    def test_analyze_channels_interference_score(self, analyzer):
        # Put many strong APs on channel 6
        analyzer._access_points = [
            AccessPoint('A', 'aa:bb:cc:dd:ee:01', 90, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('B', 'aa:bb:cc:dd:ee:02', 85, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('C', 'aa:bb:cc:dd:ee:03', 80, 6, '2.4GHz', 'WPA2', 'CCMP'),
        ]

        result = analyzer.analyze_channels()

        ch6_info = next(ci for ci in result['2.4GHz'] if ci.channel == 6)
        # Interference should be high for channel 6
        assert ch6_info.interference_score > 0

    def test_interference_from_overlapping_channels(self, analyzer):
        # APs on channel 5 and 7 should cause interference on channel 6
        analyzer._access_points = [
            AccessPoint('A', 'aa:bb:cc:dd:ee:01', 80, 5, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('B', 'aa:bb:cc:dd:ee:02', 80, 7, '2.4GHz', 'WPA2', 'CCMP'),
        ]

        interference_ch6 = analyzer._calculate_interference(6, '2.4GHz')
        interference_ch1 = analyzer._calculate_interference(1, '2.4GHz')

        # Channel 6 should have more interference due to nearby APs
        assert interference_ch6 > interference_ch1

    def test_5ghz_no_overlap(self, analyzer):
        analyzer._access_points = [
            AccessPoint('A', 'aa:bb:cc:dd:ee:01', 80, 36, '5GHz', 'WPA2', 'CCMP'),
        ]

        # Channel 40 should have 0 interference from channel 36 AP
        interference = analyzer._calculate_interference(40, '5GHz')
        assert interference == 0.0

        # Channel 36 should have non-zero interference
        interference_36 = analyzer._calculate_interference(36, '5GHz')
        assert interference_36 > 0

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_get_recommendation_prefers_least_congested(self, mock_run, analyzer):
        # Mock _get_current_channel
        mock_run.return_value = MagicMock(
            stdout='    Channel            : 6\n',
            returncode=0
        )

        # Heavy congestion on channel 6, light on 1 and 11
        analyzer._access_points = [
            AccessPoint('A', 'aa:01', 90, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('B', 'aa:02', 85, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('C', 'aa:03', 80, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('D', 'aa:04', 75, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('E', 'aa:05', 30, 1, '2.4GHz', 'WPA2', 'CCMP'),
        ]
        analyzer.analyze_channels()

        recs = analyzer.get_recommendation()

        rec_2g = next((r for r in recs if r.band == '2.4GHz'), None)
        assert rec_2g is not None
        # Should recommend channel 11 (no APs) or channel 1 (1 weak AP)
        assert rec_2g.recommended_channel in (1, 11)

    def test_get_summary(self, analyzer):
        analyzer._access_points = [
            AccessPoint('A', 'aa:01', 80, 1, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('B', 'aa:02', 60, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('C', 'aa:03', 50, 6, '2.4GHz', 'WPA2', 'CCMP'),
            AccessPoint('D', 'aa:04', 70, 36, '5GHz', 'WPA2', 'CCMP'),
        ]
        analyzer.analyze_channels()

        summary = analyzer.get_summary()

        assert summary['total_access_points'] == 4
        assert summary['access_points_2ghz'] == 3
        assert summary['access_points_5ghz'] == 1
        assert summary['most_congested_channel'] == 6
        assert summary['most_congested_ap_count'] == 2

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_networks_failure(self, mock_run, analyzer):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='netsh', timeout=15)

        aps = analyzer.scan_networks()

        assert aps == []

    def test_not_windows(self):
        a = WiFiChannelAnalyzer()
        a._is_windows = False

        assert a.scan_networks() == []

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_scan_empty_output(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(stdout='', returncode=0)

        aps = analyzer.scan_networks()

        assert aps == []

    @patch('src.network_analyzer.channel_analyzer.subprocess.run')
    def test_get_current_channel(self, mock_run, analyzer):
        mock_run.return_value = MagicMock(
            stdout='    Channel            : 11\n',
            returncode=0
        )

        channel = analyzer._get_current_channel()

        assert channel == 11


# Need subprocess import for TimeoutExpired
import subprocess
