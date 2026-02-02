import socket
from unittest.mock import patch, MagicMock, mock_open
import pytest

from src.network_analyzer.dns_analyzer import DNSAnalyzer, DNSServer, validate_ip


class TestValidateIP:
    def test_valid_ips(self):
        assert validate_ip('8.8.8.8') is True
        assert validate_ip('192.168.1.1') is True
        assert validate_ip('0.0.0.0') is True
        assert validate_ip('255.255.255.255') is True

    def test_invalid_ips(self):
        assert validate_ip('999.999.999.999') is False
        assert validate_ip('not_an_ip') is False
        assert validate_ip('') is False
        assert validate_ip('1.2.3') is False
        assert validate_ip('256.1.1.1') is False


class TestDNSAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return DNSAnalyzer()

    def test_known_dns_providers(self, analyzer):
        provider, is_public = analyzer.KNOWN_DNS_PROVIDERS.get('8.8.8.8', (None, False))
        assert provider == 'Google DNS'
        assert is_public is True

    def test_unknown_dns_provider(self, analyzer):
        provider, is_public = analyzer.KNOWN_DNS_PROVIDERS.get('10.0.0.1', ('ISP/Unknown', False))
        assert provider == 'ISP/Unknown'
        assert is_public is False

    @patch('builtins.open', mock_open(read_data='nameserver 8.8.8.8\nnameserver 1.1.1.1\n'))
    def test_get_dns_from_resolv_linux(self, analyzer):
        analyzer._is_windows = False
        servers = analyzer._get_dns_from_resolv()
        assert '8.8.8.8' in servers
        assert '1.1.1.1' in servers

    @patch('src.network_analyzer.dns_analyzer.subprocess.run')
    def test_get_dns_windows(self, mock_run, analyzer):
        analyzer._is_windows = True
        mock_run.return_value = MagicMock(
            stdout='DNS Servers: 8.8.8.8\n  1.1.1.1\n',
            returncode=0
        )
        servers = analyzer._get_dns_windows()
        assert '8.8.8.8' in servers

    @patch('src.network_analyzer.dns_analyzer.socket.socket')
    def test_measure_dns_response_success(self, mock_socket_class, analyzer):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b'\x00' * 64, ('8.8.8.8', 53))
        mock_socket_class.return_value = mock_sock

        result = analyzer._measure_dns_response('8.8.8.8')
        assert result is not None
        assert isinstance(result, float)
        mock_sock.close.assert_called_once()

    @patch('src.network_analyzer.dns_analyzer.socket.socket')
    def test_measure_dns_response_timeout(self, mock_socket_class, analyzer):
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = socket.error("timeout")
        mock_socket_class.return_value = mock_sock

        result = analyzer._measure_dns_response('8.8.8.8')
        assert result is None
        mock_sock.close.assert_called_once()

    def test_measure_dns_response_invalid_ip(self, analyzer):
        result = analyzer._measure_dns_response('not_valid')
        assert result is None

    def test_measure_dns_response_cached(self, analyzer):
        analyzer._dns_cache['8.8.8.8'] = 5.0
        result = analyzer._measure_dns_response_cached('8.8.8.8')
        assert result == 5.0

    def test_clear_cache(self, analyzer):
        analyzer._dns_cache['8.8.8.8'] = 5.0
        analyzer.clear_cache()
        assert len(analyzer._dns_cache) == 0

    def test_build_dns_query(self, analyzer):
        query = analyzer._build_dns_query('google.com')
        assert isinstance(query, bytes)
        assert len(query) > 12  # At least header size

    def test_check_dns_security_public(self, analyzer):
        analyzer._current_dns = [
            DNSServer(ip='8.8.8.8', name=None, response_time=5.0, is_public_resolver=True, provider='Google DNS')
        ]
        analyzer._check_dns_security()
        assert len(analyzer.dns_warnings) == 0

    def test_check_dns_security_private(self, analyzer):
        analyzer._current_dns = [
            DNSServer(ip='10.0.0.1', name=None, response_time=5.0, is_public_resolver=False, provider='ISP/Unknown')
        ]
        analyzer._check_dns_security()
        assert len(analyzer.dns_warnings) == 1

    def test_get_dns_recommendations_no_public(self, analyzer):
        analyzer._current_dns = [
            DNSServer(ip='10.0.0.1', name=None, response_time=5.0, is_public_resolver=False, provider='ISP')
        ]
        recs = analyzer.get_dns_recommendations()
        assert any(r['type'] == 'warning' for r in recs)

    def test_get_dns_recommendations_slow(self, analyzer):
        analyzer._current_dns = [
            DNSServer(ip='8.8.8.8', name=None, response_time=150.0, is_public_resolver=True, provider='Google')
        ]
        recs = analyzer.get_dns_recommendations()
        assert any(r['type'] == 'performance' for r in recs)

    def test_get_best_dns_recommendation(self, analyzer):
        rec = analyzer.get_best_dns_recommendation()
        assert rec['ip'] == '1.1.1.1'
        assert rec['name'] == 'Cloudflare'
