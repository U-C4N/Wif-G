import socket
from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.port_scanner import PortScanner, PortInfo, validate_target, validate_port


class TestValidation:
    def test_validate_target_localhost(self):
        assert validate_target('localhost') is True

    def test_validate_target_valid_ip(self):
        assert validate_target('192.168.1.1') is True
        assert validate_target('8.8.8.8') is True

    def test_validate_target_invalid_ip(self):
        assert validate_target('999.999.999.999') is False
        assert validate_target('not_an_ip') is False

    def test_validate_target_valid_hostname(self):
        assert validate_target('google.com') is True
        assert validate_target('my-server.example.com') is True

    def test_validate_target_invalid_hostname(self):
        assert validate_target('') is False
        assert validate_target('-invalid.com') is False

    def test_validate_port_valid(self):
        assert validate_port(1) is True
        assert validate_port(80) is True
        assert validate_port(65535) is True

    def test_validate_port_invalid(self):
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False


class TestPortScanner:
    def test_init_valid_target(self):
        scanner = PortScanner('192.168.1.1')
        assert scanner.target == '192.168.1.1'

    def test_init_invalid_target(self):
        with pytest.raises(ValueError):
            PortScanner('; rm -rf /')

    def test_set_target_valid(self):
        scanner = PortScanner()
        scanner.target = '10.0.0.1'
        assert scanner.target == '10.0.0.1'

    def test_set_target_invalid(self):
        scanner = PortScanner()
        with pytest.raises(ValueError):
            scanner.target = 'invalid; command'

    @patch('src.network_analyzer.port_scanner.socket.socket')
    def test_check_port_open(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        scanner = PortScanner('192.168.1.1')
        result = scanner._check_port(80)

        assert result is not None
        assert result.port == 80
        assert result.state == 'open'
        assert result.service == 'HTTP'

    @patch('src.network_analyzer.port_scanner.socket.socket')
    def test_check_port_closed(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_sock

        scanner = PortScanner('192.168.1.1')
        result = scanner._check_port(80)

        assert result is None

    @patch('src.network_analyzer.port_scanner.socket.socket')
    def test_check_port_error(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.error("Connection error")
        mock_socket_class.return_value = mock_sock

        scanner = PortScanner('192.168.1.1')
        result = scanner._check_port(80)

        assert result is None

    @patch.object(PortScanner, '_check_port')
    def test_scan_common_ports(self, mock_check):
        mock_check.side_effect = lambda port: PortInfo(
            port=port, state='open', service='Test', risk_level='low', description='Test'
        ) if port in [80, 443] else None

        scanner = PortScanner('192.168.1.1')
        results = scanner.scan_common_ports()

        assert len(results) == 2
        assert results[0].port == 80
        assert results[1].port == 443

    @patch.object(PortScanner, '_check_port')
    def test_quick_scan(self, mock_check):
        mock_check.return_value = None

        scanner = PortScanner()
        results = scanner.quick_scan()

        assert results == []
        assert scanner._scan_completed is True

    def test_scan_port_range_invalid(self):
        scanner = PortScanner()
        with pytest.raises(ValueError):
            scanner.scan_port_range(100, 50)

    def test_get_dangerous_ports(self):
        scanner = PortScanner()
        scanner._open_ports = [
            PortInfo(port=80, state='open', service='HTTP', risk_level='medium', description='Web server'),
            PortInfo(port=23, state='open', service='Telnet', risk_level='critical', description='Telnet'),
            PortInfo(port=445, state='open', service='SMB', risk_level='critical', description='SMB'),
        ]

        dangerous = scanner.get_dangerous_ports()
        assert len(dangerous) == 2

    def test_get_recommendation(self):
        scanner = PortScanner()
        telnet = PortInfo(port=23, state='open', service='Telnet', risk_level='critical', description='Telnet')
        rec = scanner.get_recommendation(telnet)
        assert 'SSH' in rec

    def test_max_workers_reduced(self):
        assert PortScanner.MAX_WORKERS == 50
