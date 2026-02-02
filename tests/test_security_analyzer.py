from unittest.mock import MagicMock, patch
import pytest

from src.network_analyzer.security_analyzer import SecurityAnalyzer, SecurityIssue, RiskLevel
from src.network_analyzer.port_scanner import PortInfo


@pytest.fixture
def mock_deps():
    network_scanner = MagicMock()
    network_scanner.get_network_stats.return_value = {
        'bytes_sent': 1000, 'bytes_recv': 2000,
        'packets_sent': 10, 'packets_recv': 20,
        'errors_in': 0, 'errors_out': 0,
        'drop_in': 0, 'drop_out': 0
    }
    network_scanner.signal_strength = -55

    port_scanner = MagicMock()
    port_scanner.get_dangerous_ports.return_value = []

    dns_analyzer = MagicMock()
    dns_analyzer.dns_warnings = []
    dns_analyzer.get_dns_recommendations.return_value = []

    return network_scanner, port_scanner, dns_analyzer


@pytest.fixture
def analyzer(mock_deps):
    ns, ps, dns = mock_deps
    return SecurityAnalyzer(ns, ps, dns)


class TestSecurityAnalyzer:
    def test_initial_score(self, analyzer):
        analyzer.analyze()
        assert analyzer.security_score == 100

    def test_dangerous_port_reduces_score(self, mock_deps):
        ns, ps, dns = mock_deps
        ps.get_dangerous_ports.return_value = [
            PortInfo(port=23, state='open', service='Telnet', risk_level='critical', description='Telnet')
        ]
        ps.get_recommendation.return_value = 'Use SSH'

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        assert sa.security_score < 100
        assert len(sa.issues) >= 1
        assert sa.issues[0].risk_level == RiskLevel.CRITICAL

    def test_dns_warning_adds_issue(self, mock_deps):
        ns, ps, dns = mock_deps
        dns.dns_warnings = ['DNS server 10.0.0.1 is not public']
        dns.get_dns_recommendations.return_value = []

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        assert any(i.category == 'DNS Security' for i in sa.issues)

    def test_high_error_rate(self, mock_deps):
        ns, ps, dns = mock_deps
        ns.get_network_stats.return_value = {
            'bytes_sent': 1000, 'bytes_recv': 2000,
            'packets_sent': 10, 'packets_recv': 20,
            'errors_in': 200, 'errors_out': 0,
            'drop_in': 0, 'drop_out': 0
        }

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        assert any(i.title == 'High network error rate' for i in sa.issues)

    def test_weak_wifi_signal(self, mock_deps):
        ns, ps, dns = mock_deps
        ns.signal_strength = -80

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        assert any(i.title == 'Weak WiFi signal' for i in sa.issues)

    def test_performance_high_latency(self, mock_deps):
        ns, ps, dns = mock_deps
        sa = SecurityAnalyzer(ns, ps, dns)

        latency_result = MagicMock()
        latency_result.avg_latency = 250.0
        latency_result.target = '8.8.8.8'

        sa.set_performance_results({
            'latency': [latency_result],
            'jitter': None,
            'packet_loss': None
        })
        sa.analyze()

        assert any('High latency' in i.title for i in sa.issues)

    def test_performance_high_jitter(self, mock_deps):
        ns, ps, dns = mock_deps
        sa = SecurityAnalyzer(ns, ps, dns)

        jitter_result = MagicMock()
        jitter_result.jitter = 50.0

        sa.set_performance_results({
            'latency': [],
            'jitter': jitter_result,
            'packet_loss': None
        })
        sa.analyze()

        assert any('jitter' in i.title.lower() for i in sa.issues)

    def test_performance_high_packet_loss(self, mock_deps):
        ns, ps, dns = mock_deps
        sa = SecurityAnalyzer(ns, ps, dns)

        packet_loss = MagicMock()
        packet_loss.loss_percentage = 10.0
        packet_loss.sent = 50
        packet_loss.received = 45

        sa.set_performance_results({
            'latency': [],
            'jitter': None,
            'packet_loss': packet_loss
        })
        sa.analyze()

        assert any('packet loss' in i.title.lower() for i in sa.issues)

    def test_score_minimum_zero(self, mock_deps):
        ns, ps, dns = mock_deps
        ps.get_dangerous_ports.return_value = [
            PortInfo(port=p, state='open', service='Svc', risk_level='critical', description='D')
            for p in [23, 445, 3389, 135]
        ]
        ps.get_recommendation.return_value = 'Fix it'

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        assert sa.security_score >= 0

    def test_get_summary(self, analyzer):
        analyzer.analyze()
        summary = analyzer.get_summary()

        assert 'security_score' in summary
        assert 'total_issues' in summary
        assert 'critical_issues' in summary
        assert 'high_risk_issues' in summary
        assert 'fixable_issues' in summary

    def test_get_critical_issues(self, mock_deps):
        ns, ps, dns = mock_deps
        ps.get_dangerous_ports.return_value = [
            PortInfo(port=23, state='open', service='Telnet', risk_level='critical', description='Telnet'),
            PortInfo(port=135, state='open', service='RPC', risk_level='high', description='RPC'),
        ]
        ps.get_recommendation.return_value = 'Fix'

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        critical = sa.get_critical_issues()
        assert all(i.risk_level == RiskLevel.CRITICAL for i in critical)

    def test_get_fixable_issues(self, mock_deps):
        ns, ps, dns = mock_deps
        dns.dns_warnings = ['Non-public DNS']
        dns.get_dns_recommendations.return_value = []

        sa = SecurityAnalyzer(ns, ps, dns)
        sa.analyze()

        fixable = sa.get_fixable_issues()
        assert all(i.auto_fixable for i in fixable)
