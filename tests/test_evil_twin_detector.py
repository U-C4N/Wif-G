from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.evil_twin_detector import (
    EvilTwinDetector, AccessPoint, EvilTwinAlert
)


SAMPLE_NETSH_OUTPUT = """
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 75%
         Channel            : 6
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 40%
         Channel            : 6

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:01
         Signal             : 50%
         Channel            : 11
"""

SAMPLE_NETSH_EVIL_TWIN = """
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 60%
         Channel            : 6

SSID 2 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : ff:ee:dd:cc:bb:aa
         Signal             : 95%
         Channel            : 1
"""


class TestEvilTwinDetector:
    @patch('src.network_analyzer.evil_twin_detector.platform')
    def test_init(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        detector = EvilTwinDetector(current_ssid='HomeNetwork')
        assert detector.access_points == []
        assert detector.alerts == []

    @patch('src.network_analyzer.evil_twin_detector.platform')
    @patch('src.network_analyzer.evil_twin_detector.subprocess.run')
    def test_scan_access_points(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_NETSH_OUTPUT, returncode=0
        )

        detector = EvilTwinDetector()
        aps = detector.scan_access_points()

        assert len(aps) == 3
        ssids = [ap.ssid for ap in aps]
        assert ssids.count('HomeNetwork') == 2
        assert ssids.count('CoffeeShop') == 1

    @patch('src.network_analyzer.evil_twin_detector.platform')
    @patch('src.network_analyzer.evil_twin_detector.subprocess.run')
    def test_no_evil_twin_same_network(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_NETSH_OUTPUT, returncode=0
        )

        detector = EvilTwinDetector(current_ssid='HomeNetwork')
        detector.scan_access_points()
        alerts = detector.detect_evil_twins()

        dup_alerts = [a for a in alerts if a.alert_type == 'duplicate_ssid']
        assert len(dup_alerts) == 1
        assert dup_alerts[0].ssid == 'HomeNetwork'
        assert dup_alerts[0].risk_level == 'critical'

    @patch('src.network_analyzer.evil_twin_detector.platform')
    @patch('src.network_analyzer.evil_twin_detector.subprocess.run')
    def test_evil_twin_with_security_downgrade(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_NETSH_EVIL_TWIN, returncode=0
        )

        detector = EvilTwinDetector(current_ssid='HomeNetwork')
        detector.scan_access_points()
        alerts = detector.detect_evil_twins()

        downgrade_alerts = [
            a for a in alerts if a.alert_type == 'security_downgrade'
        ]
        assert len(downgrade_alerts) == 1
        assert downgrade_alerts[0].risk_level == 'critical'

    @patch('src.network_analyzer.evil_twin_detector.platform')
    def test_signal_anomaly_detection(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        detector = EvilTwinDetector(current_ssid='TestNetwork')
        detector._access_points = [
            AccessPoint(
                ssid='TestNetwork', bssid='aa:bb:cc:dd:ee:01',
                signal=95, channel=6,
                authentication='WPA2', encryption='CCMP'
            ),
        ]

        alerts = detector.detect_evil_twins()

        signal_alerts = [
            a for a in alerts if a.alert_type == 'signal_anomaly'
        ]
        assert len(signal_alerts) == 1
        assert signal_alerts[0].risk_level == 'medium'

    @patch('src.network_analyzer.evil_twin_detector.platform')
    def test_risk_assessment_low(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        detector = EvilTwinDetector(current_ssid='SafeNetwork')
        detector._access_points = [
            AccessPoint(
                ssid='SafeNetwork', bssid='aa:bb:cc:dd:ee:01',
                signal=60, channel=6,
                authentication='WPA2', encryption='CCMP'
            ),
        ]

        detector.detect_evil_twins()
        assessment = detector.get_risk_assessment()

        assert assessment['overall_risk'] == 'low'
        assert assessment['evil_twin_detected'] is False

    @patch('src.network_analyzer.evil_twin_detector.platform')
    def test_risk_assessment_critical(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        detector = EvilTwinDetector(current_ssid='HomeNetwork')
        detector._access_points = [
            AccessPoint(
                ssid='HomeNetwork', bssid='aa:bb:cc:dd:ee:01',
                signal=60, channel=6,
                authentication='WPA2-Personal', encryption='CCMP'
            ),
            AccessPoint(
                ssid='HomeNetwork', bssid='ff:ee:dd:cc:bb:aa',
                signal=95, channel=1,
                authentication='Open', encryption='None'
            ),
        ]

        detector.detect_evil_twins()
        assessment = detector.get_risk_assessment()

        assert assessment['overall_risk'] == 'critical'
        assert assessment['evil_twin_detected'] is True
        assert assessment['security_downgrade_detected'] is True

    @patch('src.network_analyzer.evil_twin_detector.platform')
    @patch('src.network_analyzer.evil_twin_detector.subprocess.run')
    def test_subprocess_failure(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.side_effect = FileNotFoundError("netsh not found")

        detector = EvilTwinDetector()
        aps = detector.scan_access_points()

        assert aps == []

    @patch('src.network_analyzer.evil_twin_detector.platform')
    def test_no_current_ssid_skips_signal_check(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        detector = EvilTwinDetector(current_ssid=None)
        detector._access_points = [
            AccessPoint(
                ssid='Network', bssid='aa:bb:cc:dd:ee:01',
                signal=95, channel=6,
                authentication='WPA2', encryption='CCMP'
            ),
        ]

        alerts = detector.detect_evil_twins()

        signal_alerts = [
            a for a in alerts if a.alert_type == 'signal_anomaly'
        ]
        assert len(signal_alerts) == 0
