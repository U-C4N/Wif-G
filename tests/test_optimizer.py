import subprocess
from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.optimizer import (
    NetworkOptimizer, OptimizationResult, TcpSettings, MtuResult,
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

    def test_optimize_tcp_no_root_linux(self, optimizer):
        optimizer._is_root = False
        optimizer._is_windows = False
        result = optimizer._optimize_tcp()
        assert result.success is False
        assert 'Root' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_optimize_tcp_windows_success(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='Receive Window Auto-Tuning Level  : normal\n'
                   'ECN Capability                    : enabled\n'
                   'Timestamps                        : enabled\n'
                   'Receive-Side Scaling State        : enabled\n',
            stderr=''
        )
        with patch.object(optimizer, '_optimize_nagle_windows', return_value='Nagle disabled on 1 interface(s)'):
            result = optimizer._optimize_tcp()
        assert result.success is True
        assert 'TCP optimized' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_optimize_tcp_windows_fail(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='Access denied'
        )
        result = optimizer._optimize_tcp()
        assert result.success is False
        assert 'Administrator' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_read_tcp_settings_windows(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(
            stdout='Receive Window Auto-Tuning Level    : normal\n'
                   'ECN Capability                      : disabled\n'
                   'Timestamps                          : disabled\n'
                   'Receive-Side Scaling State           : enabled\n'
                   'Chimney Offload State                : automatic\n'
        )
        settings = optimizer._read_tcp_settings_windows()
        assert settings.auto_tuning_level == 'normal'
        assert settings.ecn_capability == 'disabled'
        assert settings.timestamps == 'disabled'
        assert settings.rss == 'enabled'
        assert settings.chimney_offload == 'automatic'

    def test_optimize_mtu_already_optimal(self, optimizer):
        optimizer._is_windows = True
        with patch('src.network_analyzer.optimizer._detect_wifi_interface', return_value='Wi-Fi'):
            with patch.object(optimizer, '_read_current_mtu', return_value=1500):
                with patch.object(optimizer, '_discover_optimal_mtu', return_value=1500):
                    result = optimizer._optimize_mtu()
        assert result.success is True
        assert 'already optimal' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_optimize_mtu_change_success(self, mock_run, optimizer):
        optimizer._is_windows = True
        mock_run.return_value = MagicMock(returncode=0, stderr='')
        with patch.object(optimizer, '_read_current_mtu', return_value=1500):
            with patch.object(optimizer, '_discover_optimal_mtu', return_value=1472):
                with patch('src.network_analyzer.optimizer._detect_wifi_interface', return_value='Wi-Fi'):
                    result = optimizer._optimize_mtu()
        assert result.success is True
        assert '1472' in result.message

    def test_optimize_mtu_not_windows(self, optimizer):
        optimizer._is_windows = False
        result = optimizer._optimize_mtu()
        assert result.success is False
        assert 'Windows' in result.message

    def test_optimize_mtu_discovery_failed(self, optimizer):
        optimizer._is_windows = True
        with patch('src.network_analyzer.optimizer._detect_wifi_interface', return_value='Wi-Fi'):
            with patch.object(optimizer, '_read_current_mtu', return_value=1500):
                with patch.object(optimizer, '_discover_optimal_mtu', return_value=None):
                    result = optimizer._optimize_mtu()
        assert result.success is False
        assert 'Could not discover' in result.message

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_ping_with_df_success(self, mock_run, optimizer):
        mock_run.return_value = MagicMock(returncode=0, stdout='Reply from 8.8.8.8: bytes=1472')
        assert optimizer._ping_with_df('8.8.8.8', 1472) is True

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_ping_with_df_fragment_needed(self, mock_run, optimizer):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='Packet needs to be fragmented but DF set.'
        )
        assert optimizer._ping_with_df('8.8.8.8', 1473) is False

    @patch('src.network_analyzer.optimizer.subprocess.run')
    def test_discover_optimal_mtu(self, mock_run, optimizer):
        def ping_side_effect(cmd, **kwargs):
            payload_str = cmd[3]  # -l {size}
            size = int(payload_str) + 28
            if size <= 1472:
                return MagicMock(returncode=0, stdout='Reply from 8.8.8.8')
            return MagicMock(returncode=1, stdout='Packet needs to be fragmented')

        mock_run.side_effect = ping_side_effect
        result = optimizer._discover_optimal_mtu('8.8.8.8')
        assert result == 1472

    def test_optimization_plan_includes_mtu_on_windows(self, optimizer):
        optimizer._is_windows = True
        plan = optimizer.get_optimization_plan()
        ids = [item['id'] for item in plan]
        assert 'mtu_optimization' in ids

    def test_optimization_plan_no_mtu_on_linux(self, optimizer):
        optimizer._is_windows = False
        plan = optimizer.get_optimization_plan()
        ids = [item['id'] for item in plan]
        assert 'mtu_optimization' not in ids

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
