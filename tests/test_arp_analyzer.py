from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.arp_analyzer import ArpAnalyzer, ArpEntry, ArpSpoofingAlert


SAMPLE_ARP_WINDOWS = """
Interface: 192.168.1.100 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.50          aa-bb-cc-dd-ee-02     dynamic
  192.168.1.51          aa-bb-cc-dd-ee-03     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""

SAMPLE_ARP_SPOOFED = """
Interface: 192.168.1.100 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.50          aa-bb-cc-dd-ee-01     dynamic
  192.168.1.51          aa-bb-cc-dd-ee-03     dynamic
"""


class TestArpAnalyzer:
    @patch('src.network_analyzer.arp_analyzer.platform')
    def test_init(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        assert analyzer.arp_table == []
        assert analyzer.alerts == []
        assert analyzer.gateway_mac is None

    @patch('src.network_analyzer.arp_analyzer.platform')
    @patch('src.network_analyzer.arp_analyzer.subprocess.run')
    def test_get_arp_table_windows(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_ARP_WINDOWS, returncode=0
        )

        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        table = analyzer.get_arp_table()

        assert len(table) >= 3
        assert any(e.ip == '192.168.1.1' for e in table)
        assert any(e.ip == '192.168.1.50' for e in table)

    @patch('src.network_analyzer.arp_analyzer.platform')
    @patch('src.network_analyzer.arp_analyzer.subprocess.run')
    def test_detect_spoofing_clean(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_ARP_WINDOWS, returncode=0
        )

        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        alerts = analyzer.detect_spoofing()

        spoofing_alerts = [
            a for a in alerts if a.alert_type == 'duplicate_mac'
        ]
        assert len(spoofing_alerts) == 0

    @patch('src.network_analyzer.arp_analyzer.platform')
    @patch('src.network_analyzer.arp_analyzer.subprocess.run')
    def test_detect_spoofing_duplicate_mac(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(
            stdout=SAMPLE_ARP_SPOOFED, returncode=0
        )

        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        alerts = analyzer.detect_spoofing()

        spoofing_alerts = [
            a for a in alerts if a.alert_type == 'duplicate_mac'
        ]
        assert len(spoofing_alerts) == 1
        assert spoofing_alerts[0].risk_level == 'critical'
        assert '192.168.1.1' in spoofing_alerts[0].affected_ips
        assert '192.168.1.50' in spoofing_alerts[0].affected_ips

    @patch('src.network_analyzer.arp_analyzer.platform')
    def test_check_gateway_mac_changed(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        analyzer._arp_table = [
            ArpEntry(ip='192.168.1.1', mac='aa:bb:cc:dd:ee:99',
                     interface='192.168.1.100', entry_type='dynamic'),
        ]
        analyzer.set_previous_gateway_mac('aa:bb:cc:dd:ee:01')

        alert = analyzer.check_gateway_mac()

        assert alert is not None
        assert alert.alert_type == 'gateway_mac_changed'
        assert alert.risk_level == 'critical'

    @patch('src.network_analyzer.arp_analyzer.platform')
    def test_check_gateway_mac_unchanged(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        analyzer._arp_table = [
            ArpEntry(ip='192.168.1.1', mac='aa:bb:cc:dd:ee:01',
                     interface='192.168.1.100', entry_type='dynamic'),
        ]
        analyzer.set_previous_gateway_mac('aa:bb:cc:dd:ee:01')

        alert = analyzer.check_gateway_mac()
        assert alert is None

    @patch('src.network_analyzer.arp_analyzer.platform')
    def test_get_summary(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        analyzer = ArpAnalyzer(gateway='192.168.1.1')
        analyzer._arp_table = [
            ArpEntry(ip='192.168.1.1', mac='aa:bb:cc:dd:ee:01',
                     interface='192.168.1.100', entry_type='dynamic'),
        ]

        summary = analyzer.get_summary()

        assert 'total_entries' in summary
        assert 'alerts' in summary
        assert 'spoofing_detected' in summary
        assert 'gateway_mac_changed' in summary

    @patch('src.network_analyzer.arp_analyzer.platform')
    @patch('src.network_analyzer.arp_analyzer.subprocess.run')
    def test_subprocess_failure_handled(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.side_effect = FileNotFoundError("arp not found")

        analyzer = ArpAnalyzer()
        table = analyzer.get_arp_table()

        assert table == []

    @patch('src.network_analyzer.arp_analyzer.platform')
    def test_broadcast_and_multicast_filtered(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        analyzer = ArpAnalyzer()
        analyzer._arp_table = [
            ArpEntry(ip='192.168.1.1', mac='ff:ff:ff:ff:ff:ff',
                     interface='eth0', entry_type='static'),
            ArpEntry(ip='224.0.0.1', mac='01:00:5e:00:00:01',
                     interface='eth0', entry_type='static'),
            ArpEntry(ip='192.168.1.2', mac='aa:bb:cc:dd:ee:01',
                     interface='eth0', entry_type='dynamic'),
            ArpEntry(ip='192.168.1.3', mac='aa:bb:cc:dd:ee:01',
                     interface='eth0', entry_type='dynamic'),
        ]

        alerts = analyzer.detect_spoofing()

        dup_alerts = [a for a in alerts if a.alert_type == 'duplicate_mac']
        assert len(dup_alerts) == 1
        assert 'aa:bb:cc:dd:ee:01' == dup_alerts[0].suspicious_mac
