import subprocess
from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.optimizer import (
    NetworkOptimizer, OptimizationResult,
    _sanitize_interface_name, _detect_wifi_interface
)
from src.network_analyzer.security_analyzer import SecurityIssue, RiskLevel


@pytest.fixture
def mock_deps():
    security_analyzer = MagicMock()
    security_analyzer.get_fixable_issues.return_value = []
    security_analyzer.get_high_risk_issues.return_value = []

    dns_analyzer = MagicMock()
    dns_analyzer.get_dns_recommendations.return_value = []
    dns_analyzer.get_best_dns_recommendation.return_value = {
        'ip': '1.1.1.1', 'name': 'Cloudflare', 'description': 'Fast'
    }

    return security_analyzer, dns_analyzer


@pytest.fixture
def optimizer(mock_deps):
    sa, dns = mock_deps
    with patch('os.geteuid', return_value=1000, create=True):
        opt = NetworkOptimizer(sa, dns)
    return opt


class TestSanitization:
    def test_sanitize_interface_name_clean(self):
        assert _sanitize_interface_name('Wi-Fi') == 'Wi-Fi'
        assert _sanitize_interface_name('Ethernet') == 'Ethernet'

    def test_sanitize_interface_name_injection(self):
        result = _sanitize_interface_name('Wi-Fi"; netsh hack')
        assert ';' not in result
        assert '"' not in result

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_detect_wifi_interface(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout='    Name                   : Wi-Fi\n    State                  : connected\n'
        )
        result = _detect_wifi_interface()
        assert result == 'Wi-Fi'

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_detect_wifi_interface_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        result = _detect_wifi_interface()
        assert result is None


class TestNetworkOptimizer:
    def test_get_optimization_plan_basic(self, optimizer):
        plan = optimizer.get_optimization_plan()
        ids = [item['id'] for item in plan]
        assert 'tcp_optimization' in ids
        assert 'dns_cache' in ids

    def test_get_optimization_plan_with_dns_recs(self, mock_deps):
        sa, dns = mock_deps
        dns.get_dns_recommendations.return_value = [{'type': 'warning', 'message': 'test'}]
        with patch('os.geteuid', return_value=1000, create=True):
            opt = NetworkOptimizer(sa, dns)
        plan = opt.get_optimization_plan()
        assert any(item['id'] == 'dns_optimization' for item in plan)

    def test_apply_unknown_optimization(self, optimizer):
        result = optimizer.apply_optimization('unknown_id')
        assert result.success is False
        assert 'Unknown' in result.message

    def test_apply_fix_dns(self, optimizer):
        result = optimizer.apply_optimization('fix_dns_security')
        assert result.success is False
        assert 'DNS' in result.message

    def test_apply_fix_other(self, optimizer):
        result = optimizer.apply_optimization('fix_port_security')
        assert result.success is False
        assert 'manual' in result.message.lower()

    def test_optimize_tcp_no_root(self, optimizer):
        optimizer._is_root = False
        result = optimizer._optimize_tcp()
        assert result.success is False
        assert 'Root' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_clear_dns_cache_windows(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(returncode=0, stdout='Flushed')
        result = optimizer._clear_dns_cache()
        assert result.success is True

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_clear_dns_cache_windows_fail(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(returncode=1)
        result = optimizer._clear_dns_cache()
        assert result.success is False

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_clear_dns_cache_linux(self, mock_run, optimizer):
        optimizer._is_windows = False
        mock_run.return_value = MagicMock(returncode=0)
        result = optimizer._clear_dns_cache()
        assert result.success is True

    @patch('builtins.open', create=True)
    def test_optimize_dns_linux_root(self, mock_file, mock_deps):
        sa, dns = mock_deps
        with patch('os.geteuid', return_value=0, create=True):
            opt = NetworkOptimizer(sa, dns)

        mock_file.return_value.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value='old')))
        mock_file.return_value.__exit__ = MagicMock(return_value=False)

        result = opt._optimize_dns()
        assert result.success is True

    def test_optimize_dns_linux_no_root(self, optimizer):
        optimizer._is_windows = False
        optimizer._is_root = False
        result = optimizer._optimize_dns()
        assert result.success is False
        assert 'Root' in result.message

    @patch('src.network_analyzer.optimizer._detect_wifi_interface')
    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_optimize_dns_windows(self, mock_run, mock_detect, optimizer):
        optimizer._is_windows = True
        mock_detect.return_value = 'Wi-Fi'
        mock_run.return_value = MagicMock(returncode=0)
        result = optimizer._optimize_dns()
        assert result.success is True

    def test_get_manual_recommendations_empty(self, optimizer):
        recs = optimizer.get_manual_recommendations()
        assert recs == []

    def test_get_manual_recommendations_with_issues(self, mock_deps):
        sa, dns = mock_deps
        sa.get_high_risk_issues.return_value = [
            SecurityIssue(
                category='Port Security',
                title='Open port 23',
                description='Telnet',
                risk_level=RiskLevel.HIGH,
                recommendation='Close port',
                auto_fixable=False
            )
        ]
        with patch('os.geteuid', return_value=1000, create=True):
            opt = NetworkOptimizer(sa, dns)
        recs = opt.get_manual_recommendations()
        assert len(recs) == 1
        assert 'steps' in recs[0]

    def test_apply_all_optimizations(self, optimizer):
        with patch.object(optimizer, '_clear_dns_cache') as mock_clear:
            mock_clear.return_value = OptimizationResult(
                action='DNS Cache Clear', success=True,
                message='Cleared', requires_restart=False
            )
            results = optimizer.apply_all_optimizations()

        assert len(results) > 0
