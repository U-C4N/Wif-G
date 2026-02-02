import subprocess
from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.network_scanner import NetworkScanner


@pytest.fixture
def scanner():
    return NetworkScanner()


class TestNetworkScanner:
    @patch('src.network_analyzer.network_scanner.netifaces')
    def test_scan_interfaces(self, mock_netifaces, scanner):
        mock_netifaces.AF_INET = 2
        mock_netifaces.interfaces.return_value = ['eth0', 'lo']
        mock_netifaces.ifaddresses.side_effect = [
            {2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}]},
            {2: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}]},
        ]

        scanner._scan_interfaces()

        assert 'eth0' in scanner.interfaces
        assert scanner.interfaces['eth0']['ip'] == '192.168.1.100'
        assert scanner.local_ip == '192.168.1.100'

    @patch('src.network_analyzer.network_scanner.netifaces')
    def test_scan_gateway(self, mock_netifaces, scanner):
        mock_netifaces.AF_INET = 2
        mock_netifaces.gateways.return_value = {
            'default': {2: ('192.168.1.1', 'eth0')}
        }

        scanner._scan_gateway()

        assert scanner.gateway == '192.168.1.1'

    @patch('src.network_analyzer.network_scanner.netifaces')
    def test_scan_gateway_no_default(self, mock_netifaces, scanner):
        mock_netifaces.AF_INET = 2
        mock_netifaces.gateways.return_value = {'default': {}}

        scanner._scan_gateway()

        assert scanner.gateway is None

    @patch('src.network_analyzer.network_scanner.platform')
    @patch('src.network_analyzer.network_scanner.subprocess.run')
    def test_scan_wifi_info_windows(self, mock_run, mock_platform, scanner):
        scanner._is_windows = True
        mock_run.return_value = MagicMock(
            stdout='    SSID            : MyWiFi\n    Signal          : 85%\n',
            returncode=0
        )

        scanner._scan_wifi_info()

        assert scanner.ssid == 'MyWiFi'
        assert scanner.signal_strength is not None

    @patch('src.network_analyzer.network_scanner.subprocess.run')
    def test_scan_wifi_info_linux_iwconfig(self, mock_run, scanner):
        scanner._is_windows = False
        mock_run.return_value = MagicMock(
            stdout='wlan0     IEEE 802.11  ESSID:"TestNetwork"  Signal level=-45 dBm',
            stderr='',
            returncode=0
        )

        scanner._scan_wifi_info()

        assert scanner.ssid == 'TestNetwork'
        assert scanner.signal_strength == -45

    @patch('src.network_analyzer.network_scanner.subprocess.run')
    def test_scan_wifi_info_fallback_nmcli(self, mock_run, scanner):
        scanner._is_windows = False
        mock_run.side_effect = [
            FileNotFoundError(),  # iwconfig fails
            MagicMock(stdout='yes:HomeWiFi:72\n', returncode=0),  # nmcli succeeds
        ]

        scanner._scan_wifi_info()

        assert scanner.ssid == 'HomeWiFi'
        assert scanner.signal_strength == 72

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_network_stats(self, mock_psutil, scanner):
        mock_stats = MagicMock()
        mock_stats.bytes_sent = 1000
        mock_stats.bytes_recv = 2000
        mock_stats.packets_sent = 10
        mock_stats.packets_recv = 20
        mock_stats.errin = 0
        mock_stats.errout = 0
        mock_stats.dropin = 0
        mock_stats.dropout = 0
        mock_psutil.net_io_counters.return_value = mock_stats

        stats = scanner.get_network_stats()

        assert stats['bytes_sent'] == 1000
        assert stats['bytes_recv'] == 2000
        assert stats['errors_in'] == 0

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_active_connections(self, mock_psutil, scanner):
        mock_conn = MagicMock()
        mock_conn.status = 'ESTABLISHED'
        mock_conn.laddr = MagicMock(ip='192.168.1.100', port=54321)
        mock_conn.raddr = MagicMock(ip='8.8.8.8', port=443)
        mock_conn.pid = 1234
        mock_psutil.net_connections.return_value = [mock_conn]

        connections = scanner.get_active_connections()

        assert len(connections) == 1
        assert connections[0]['remote_address'] == '8.8.8.8:443'
