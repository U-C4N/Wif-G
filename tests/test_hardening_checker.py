from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.hardening_checker import (
    HardeningChecker, HardeningIssue
)


class TestHardeningChecker:
    @patch('src.network_analyzer.hardening_checker.platform')
    def test_init(self, mock_platform):
        mock_platform.system.return_value = 'Windows'
        checker = HardeningChecker(open_ports=[445, 3389])
        assert checker.issues == []
        assert checker.smb_config == {}
        assert checker.rdp_config == {}

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_smb1_enabled_critical(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'SMB1' in cmd:
                result.returncode = 0
                result.stdout = '    SMB1    REG_DWORD    0x1'
            elif 'RequireSecuritySignature' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    RequireSecuritySignature    REG_DWORD    0x0'
                )
            elif 'powershell' in cmd:
                result.returncode = 1
                result.stdout = ''
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        issues = checker.check_smb_security()

        smb1_issues = [
            i for i in issues if i.check_name == 'SMBv1 Protocol'
        ]
        assert len(smb1_issues) == 1
        assert smb1_issues[0].status == 'VULNERABLE'
        assert smb1_issues[0].risk_level == 'critical'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_smb1_disabled_secure(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'SMB1' in cmd:
                result.returncode = 0
                result.stdout = '    SMB1    REG_DWORD    0x0'
            elif 'RequireSecuritySignature' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    RequireSecuritySignature    REG_DWORD    0x1'
                )
            elif 'powershell' in cmd:
                result.returncode = 1
                result.stdout = ''
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        issues = checker.check_smb_security()

        smb1_issues = [
            i for i in issues if i.check_name == 'SMBv1 Protocol'
        ]
        assert len(smb1_issues) == 1
        assert smb1_issues[0].status == 'SECURE'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_smb_signing_not_required(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'SMB1' in cmd:
                result.returncode = 0
                result.stdout = '    SMB1    REG_DWORD    0x0'
            elif 'RequireSecuritySignature' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    RequireSecuritySignature    REG_DWORD    0x0'
                )
            elif 'powershell' in cmd:
                result.returncode = 1
                result.stdout = ''
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        issues = checker.check_smb_security()

        signing_issues = [
            i for i in issues if i.check_name == 'SMB Signing'
        ]
        assert len(signing_issues) == 1
        assert signing_issues[0].risk_level == 'high'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_smb_port_open_warning(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(returncode=1, stdout='')

        checker = HardeningChecker(open_ports=[445])
        issues = checker.check_smb_security()

        port_issues = [
            i for i in issues if i.check_name == 'SMB Port Exposure'
        ]
        assert len(port_issues) == 1
        assert port_issues[0].risk_level == 'high'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_rdp_enabled_nla_disabled(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'fDenyTSConnections' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    fDenyTSConnections    REG_DWORD    0x0'
                )
            elif 'UserAuthentication' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    UserAuthentication    REG_DWORD    0x0'
                )
            elif 'SecurityLayer' in cmd:
                result.returncode = 0
                result.stdout = '    SecurityLayer    REG_DWORD    0x0'
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        issues = checker.check_rdp_security()

        nla_issues = [
            i for i in issues
            if 'NLA' in i.check_name or 'Network Level' in i.check_name
        ]
        assert len(nla_issues) == 1
        assert nla_issues[0].status == 'VULNERABLE'
        assert nla_issues[0].risk_level == 'high'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_rdp_security_layer_vulnerable(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'fDenyTSConnections' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    fDenyTSConnections    REG_DWORD    0x0'
                )
            elif 'UserAuthentication' in cmd:
                result.returncode = 0
                result.stdout = (
                    '    UserAuthentication    REG_DWORD    0x1'
                )
            elif 'SecurityLayer' in cmd:
                result.returncode = 0
                result.stdout = '    SecurityLayer    REG_DWORD    0x0'
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        issues = checker.check_rdp_security()

        sec_layer_issues = [
            i for i in issues if 'Security Layer' in i.check_name
        ]
        assert len(sec_layer_issues) == 1
        assert sec_layer_issues[0].status == 'VULNERABLE'

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_rdp_port_open(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(returncode=1, stdout='')

        checker = HardeningChecker(open_ports=[3389])
        issues = checker.check_rdp_security()

        port_issues = [
            i for i in issues if 'Port' in i.check_name
        ]
        assert len(port_issues) == 1

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_get_hardening_report(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'
        mock_run.return_value = MagicMock(returncode=1, stdout='')

        checker = HardeningChecker(open_ports=[445, 3389])
        report = checker.get_hardening_report()

        assert 'total_checks' in report
        assert 'critical_issues' in report
        assert 'high_issues' in report
        assert 'vulnerable_items' in report
        assert 'smb_config' in report
        assert 'rdp_config' in report
        assert 'issues' in report

    @patch('src.network_analyzer.hardening_checker.platform')
    def test_non_windows_returns_empty(self, mock_platform):
        mock_platform.system.return_value = 'Linux'

        checker = HardeningChecker()
        smb_issues = checker.check_smb_security()
        rdp_issues = checker.check_rdp_security()

        assert smb_issues == []
        assert rdp_issues == []

    @patch('src.network_analyzer.hardening_checker.platform')
    @patch('src.network_analyzer.hardening_checker.subprocess.run')
    def test_powershell_fallback(self, mock_run, mock_platform):
        mock_platform.system.return_value = 'Windows'

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if 'powershell' in cmd:
                result.returncode = 0
                result.stdout = (
                    'EnableSMB1Protocol    : False\n'
                    'RequireSecuritySignature : True\n'
                    'EncryptData           : True\n'
                )
            elif 'reg' in cmd:
                raise FileNotFoundError("reg not found")
            else:
                result.returncode = 1
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect

        checker = HardeningChecker()
        checker.check_smb_security()

        assert checker.smb_config.get('smb1_enabled') is False
        assert checker.smb_config.get('encryption_required') is True
