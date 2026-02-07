from unittest.mock import patch, MagicMock, PropertyMock
import pytest

from src.network_analyzer.network_scanner import (
    NetworkScanner, ProcessConnection
)


class TestProcessConnections:
    def test_process_connection_dataclass(self):
        pc = ProcessConnection(
            pid=1234,
            process_name='chrome.exe',
            exe_path=r'C:\Program Files\Google\Chrome\chrome.exe',
            local_address='192.168.1.100',
            local_port=52345,
            remote_address='142.250.80.46',
            remote_port=443,
            status='ESTABLISHED',
            is_external=True,
            suspicious=False,
            reason=None
        )
        assert pc.pid == 1234
        assert pc.process_name == 'chrome.exe'
        assert pc.is_external is True
        assert pc.suspicious is False

    def test_is_external_ip_private(self):
        assert NetworkScanner._is_external_ip('192.168.1.1') is False
        assert NetworkScanner._is_external_ip('10.0.0.1') is False
        assert NetworkScanner._is_external_ip('172.16.0.1') is False
        assert NetworkScanner._is_external_ip('172.31.255.255') is False
        assert NetworkScanner._is_external_ip('127.0.0.1') is False
        assert NetworkScanner._is_external_ip('169.254.1.1') is False

    def test_is_external_ip_public(self):
        assert NetworkScanner._is_external_ip('8.8.8.8') is True
        assert NetworkScanner._is_external_ip('142.250.80.46') is True
        assert NetworkScanner._is_external_ip('1.1.1.1') is True

    def test_is_external_ip_edge_cases(self):
        assert NetworkScanner._is_external_ip(None) is False
        assert NetworkScanner._is_external_ip('::1') is False
        assert NetworkScanner._is_external_ip('172.15.0.1') is True
        assert NetworkScanner._is_external_ip('172.32.0.1') is True

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_process_connections_basic(self, mock_psutil):
        mock_conn = MagicMock()
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 1234
        mock_conn.laddr.ip = '192.168.1.100'
        mock_conn.laddr.port = 52345
        mock_conn.raddr.ip = '142.250.80.46'
        mock_conn.raddr.port = 443

        mock_psutil.net_connections.return_value = [mock_conn]

        mock_proc = MagicMock()
        mock_proc.name.return_value = 'chrome.exe'
        mock_proc.exe.return_value = r'C:\Program Files\Google\Chrome\chrome.exe'
        mock_psutil.Process.return_value = mock_proc

        scanner = NetworkScanner()
        results = scanner.get_process_connections()

        assert len(results) == 1
        assert results[0].process_name == 'chrome.exe'
        assert results[0].is_external is True
        assert results[0].suspicious is False

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_process_connections_unknown_process(self, mock_psutil):
        mock_conn = MagicMock()
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 9999
        mock_conn.laddr.ip = '192.168.1.100'
        mock_conn.laddr.port = 52345
        mock_conn.raddr.ip = '8.8.8.8'
        mock_conn.raddr.port = 443

        mock_psutil.net_connections.return_value = [mock_conn]
        mock_psutil.Process.side_effect = mock_psutil.NoSuchProcess(9999)
        mock_psutil.NoSuchProcess = type('NoSuchProcess', (Exception,), {})
        mock_psutil.AccessDenied = type('AccessDenied', (Exception,), {})
        mock_psutil.ZombieProcess = type('ZombieProcess', (Exception,), {})

        mock_psutil.Process.side_effect = mock_psutil.NoSuchProcess(9999)

        scanner = NetworkScanner()
        results = scanner.get_process_connections()

        assert len(results) == 1
        assert results[0].process_name == 'unknown'
        assert results[0].suspicious is True

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_process_connections_filters_listen(self, mock_psutil):
        mock_conn = MagicMock()
        mock_conn.status = 'LISTEN'
        mock_conn.pid = 1234
        mock_conn.laddr.ip = '0.0.0.0'
        mock_conn.laddr.port = 80
        mock_conn.raddr = None

        mock_psutil.net_connections.return_value = [mock_conn]

        scanner = NetworkScanner()
        results = scanner.get_process_connections()

        assert len(results) == 0

    @patch('src.network_analyzer.network_scanner.psutil')
    def test_get_process_connections_access_denied(self, mock_psutil):
        mock_psutil.AccessDenied = type('AccessDenied', (Exception,), {})
        mock_psutil.net_connections.side_effect = mock_psutil.AccessDenied()

        scanner = NetworkScanner()
        results = scanner.get_process_connections()

        assert results == []

    def test_check_suspicious_local_connection(self):
        scanner = NetworkScanner()
        suspicious, reason = scanner._check_suspicious(
            'chrome.exe', r'C:\Program Files\Google\Chrome\chrome.exe',
            '192.168.1.1', 80, False
        )
        assert suspicious is False

    @patch('src.network_analyzer.network_scanner.platform')
    def test_check_suspicious_system_process_external(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        scanner = NetworkScanner()
        suspicious, reason = scanner._check_suspicious(
            'lsass.exe', r'C:\Windows\System32\lsass.exe',
            '8.8.8.8', 443, True
        )
        assert suspicious is True
        assert 'System process' in reason

    def test_known_system_processes_list(self):
        assert 'svchost.exe' in NetworkScanner.KNOWN_SYSTEM_PROCESSES
        assert 'lsass.exe' in NetworkScanner.KNOWN_SYSTEM_PROCESSES

    def test_known_safe_processes_list(self):
        assert 'chrome.exe' in NetworkScanner.KNOWN_SAFE_PROCESSES
        assert 'firefox.exe' in NetworkScanner.KNOWN_SAFE_PROCESSES
        assert 'python.exe' in NetworkScanner.KNOWN_SAFE_PROCESSES
