import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HardeningIssue:
    protocol: str
    check_name: str
    status: str
    risk_level: str
    description: str
    recommendation: str


class HardeningChecker:
    def __init__(self, open_ports: Optional[List[int]] = None):
        self._open_ports = open_ports or []
        self._issues: List[HardeningIssue] = []
        self._smb_config: Dict = {}
        self._rdp_config: Dict = {}
        self._is_windows = platform.system() == 'Windows'

    @property
    def issues(self) -> List[HardeningIssue]:
        return self._issues

    @property
    def smb_config(self) -> Dict:
        return self._smb_config

    @property
    def rdp_config(self) -> Dict:
        return self._rdp_config

    def check_smb_security(self) -> List[HardeningIssue]:
        smb_issues: List[HardeningIssue] = []

        if not self._is_windows:
            return smb_issues

        self._smb_config = self._get_smb_config()

        smb1_enabled = self._smb_config.get('smb1_enabled')
        if smb1_enabled is True:
            smb_issues.append(HardeningIssue(
                protocol='SMB',
                check_name='SMBv1 Protocol',
                status='VULNERABLE',
                risk_level='critical',
                description=(
                    'SMBv1 is enabled. This protocol has known critical '
                    'vulnerabilities (EternalBlue/WannaCry).'
                ),
                recommendation=(
                    'Disable SMBv1: Run PowerShell as Admin and execute '
                    'Disable-WindowsOptionalFeature -Online '
                    '-FeatureName SMB1Protocol'
                )
            ))
        elif smb1_enabled is False:
            smb_issues.append(HardeningIssue(
                protocol='SMB',
                check_name='SMBv1 Protocol',
                status='SECURE',
                risk_level='low',
                description='SMBv1 is disabled.',
                recommendation='No action needed.'
            ))

        signing = self._smb_config.get('signing_required')
        if signing is False:
            smb_issues.append(HardeningIssue(
                protocol='SMB',
                check_name='SMB Signing',
                status='VULNERABLE',
                risk_level='high',
                description=(
                    'SMB signing is not required. This allows '
                    'man-in-the-middle attacks on SMB connections.'
                ),
                recommendation=(
                    'Enable SMB signing via Group Policy: Computer '
                    'Configuration > Policies > Windows Settings > '
                    'Security Settings > Local Policies > Security Options > '
                    '"Microsoft network server: Digitally sign communications '
                    '(always)" = Enabled'
                )
            ))

        encryption = self._smb_config.get('encryption_required')
        if encryption is False:
            smb_issues.append(HardeningIssue(
                protocol='SMB',
                check_name='SMB Encryption',
                status='WARNING',
                risk_level='medium',
                description='SMB encryption is not required.',
                recommendation=(
                    'Consider enabling SMB encryption for sensitive shares '
                    'using Set-SmbServerConfiguration '
                    '-EncryptData $true'
                )
            ))

        if 445 in self._open_ports:
            smb_issues.append(HardeningIssue(
                protocol='SMB',
                check_name='SMB Port Exposure',
                status='WARNING',
                risk_level='high',
                description='SMB port 445 is open and accessible.',
                recommendation=(
                    'Block SMB port 445 from external access using '
                    'Windows Firewall. SMB should only be accessible '
                    'within trusted networks.'
                )
            ))

        self._issues.extend(smb_issues)
        return smb_issues

    def _get_smb_config(self) -> Dict:
        config: Dict = {
            'smb1_enabled': None,
            'signing_required': None,
            'encryption_required': None,
        }

        config.update(self._check_smb_via_registry())

        if config['smb1_enabled'] is None:
            ps_config = self._check_smb_via_powershell()
            for key, value in ps_config.items():
                if config.get(key) is None:
                    config[key] = value

        return config

    def _check_smb_via_registry(self) -> Dict:
        config: Dict = {
            'smb1_enabled': None,
            'signing_required': None,
        }

        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Services'
                 r'\LanmanServer\Parameters',
                 '/v', 'SMB1'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'SMB1\s+REG_DWORD\s+0x(\d+)',
                                  result.stdout)
                if match:
                    config['smb1_enabled'] = int(match.group(1), 16) != 0
            else:
                config['smb1_enabled'] = True
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Registry SMB1 check failed: %s", e)

        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Services'
                 r'\LanmanServer\Parameters',
                 '/v', 'RequireSecuritySignature'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(
                    r'RequireSecuritySignature\s+REG_DWORD\s+0x(\d+)',
                    result.stdout
                )
                if match:
                    config['signing_required'] = int(match.group(1), 16) != 0
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Registry SMB signing check failed: %s", e)

        return config

    def _check_smb_via_powershell(self) -> Dict:
        config: Dict = {
            'smb1_enabled': None,
            'signing_required': None,
            'encryption_required': None,
        }

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-SmbServerConfiguration | '
                 'Select-Object EnableSMB1Protocol,'
                 'RequireSecuritySignature,EncryptData | '
                 'Format-List'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                output = result.stdout
                smb1_match = re.search(
                    r'EnableSMB1Protocol\s*:\s*(True|False)', output
                )
                if smb1_match:
                    config['smb1_enabled'] = smb1_match.group(1) == 'True'

                signing_match = re.search(
                    r'RequireSecuritySignature\s*:\s*(True|False)', output
                )
                if signing_match:
                    config['signing_required'] = (
                        signing_match.group(1) == 'True'
                    )

                enc_match = re.search(
                    r'EncryptData\s*:\s*(True|False)', output
                )
                if enc_match:
                    config['encryption_required'] = (
                        enc_match.group(1) == 'True'
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("PowerShell SMB config check failed: %s", e)

        return config

    def check_rdp_security(self) -> List[HardeningIssue]:
        rdp_issues: List[HardeningIssue] = []

        if not self._is_windows:
            return rdp_issues

        self._rdp_config = self._get_rdp_config()

        rdp_enabled = self._rdp_config.get('rdp_enabled')
        if rdp_enabled is True:
            rdp_issues.append(HardeningIssue(
                protocol='RDP',
                check_name='RDP Service',
                status='WARNING',
                risk_level='medium',
                description='Remote Desktop is enabled on this machine.',
                recommendation=(
                    'If RDP is not needed, disable it in System Properties '
                    '> Remote tab. If needed, ensure it is protected by '
                    'VPN or firewall rules.'
                )
            ))

        nla_enabled = self._rdp_config.get('nla_enabled')
        if rdp_enabled and nla_enabled is False:
            rdp_issues.append(HardeningIssue(
                protocol='RDP',
                check_name='Network Level Authentication (NLA)',
                status='VULNERABLE',
                risk_level='high',
                description=(
                    'Network Level Authentication is disabled for RDP. '
                    'This allows attackers to interact with the login screen '
                    'without first authenticating.'
                ),
                recommendation=(
                    'Enable NLA: System Properties > Remote tab > '
                    'check "Allow connections only from computers running '
                    'Remote Desktop with Network Level Authentication"'
                )
            ))

        security_layer = self._rdp_config.get('security_layer')
        if security_layer is not None and security_layer == 0:
            rdp_issues.append(HardeningIssue(
                protocol='RDP',
                check_name='RDP Security Layer',
                status='VULNERABLE',
                risk_level='high',
                description=(
                    'RDP is using the legacy RDP Security Layer (value=0) '
                    'instead of TLS. This is vulnerable to '
                    'man-in-the-middle attacks.'
                ),
                recommendation=(
                    'Set Security Layer to TLS (2) via Group Policy: '
                    'Computer Configuration > Admin Templates > '
                    'Windows Components > Remote Desktop Services > '
                    'Remote Desktop Session Host > Security > '
                    '"Require use of specific security layer" = SSL/TLS'
                )
            ))

        if 3389 in self._open_ports:
            rdp_issues.append(HardeningIssue(
                protocol='RDP',
                check_name='RDP Port Exposure',
                status='WARNING',
                risk_level='high',
                description=(
                    'RDP is accessible on the default port 3389. '
                    'This port is heavily targeted by brute-force attacks.'
                ),
                recommendation=(
                    'Change the default RDP port or restrict access via '
                    'firewall to trusted IPs only. Use a VPN for remote '
                    'access instead of exposing RDP directly.'
                )
            ))

        self._issues.extend(rdp_issues)
        return rdp_issues

    def _get_rdp_config(self) -> Dict:
        config: Dict = {
            'rdp_enabled': None,
            'nla_enabled': None,
            'security_layer': None,
        }

        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control'
                 r'\Terminal Server',
                 '/v', 'fDenyTSConnections'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(
                    r'fDenyTSConnections\s+REG_DWORD\s+0x(\d+)',
                    result.stdout
                )
                if match:
                    config['rdp_enabled'] = int(match.group(1), 16) == 0
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Registry RDP enabled check failed: %s", e)

        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control'
                 r'\Terminal Server\WinStations\RDP-Tcp',
                 '/v', 'UserAuthentication'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(
                    r'UserAuthentication\s+REG_DWORD\s+0x(\d+)',
                    result.stdout
                )
                if match:
                    config['nla_enabled'] = int(match.group(1), 16) == 1
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Registry NLA check failed: %s", e)

        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control'
                 r'\Terminal Server\WinStations\RDP-Tcp',
                 '/v', 'SecurityLayer'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(
                    r'SecurityLayer\s+REG_DWORD\s+0x(\d+)',
                    result.stdout
                )
                if match:
                    config['security_layer'] = int(match.group(1), 16)
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError) as e:
            logger.debug("Registry RDP security layer check failed: %s", e)

        return config

    def get_hardening_report(self) -> Dict:
        if not self._issues:
            self.check_smb_security()
            self.check_rdp_security()

        critical = [i for i in self._issues if i.risk_level == 'critical']
        high = [i for i in self._issues if i.risk_level == 'high']
        vulnerable = [i for i in self._issues if i.status == 'VULNERABLE']

        return {
            'total_checks': len(self._issues),
            'critical_issues': len(critical),
            'high_issues': len(high),
            'vulnerable_items': len(vulnerable),
            'smb_config': self._smb_config,
            'rdp_config': self._rdp_config,
            'issues': [
                {
                    'protocol': i.protocol,
                    'check_name': i.check_name,
                    'status': i.status,
                    'risk_level': i.risk_level,
                    'description': i.description,
                    'recommendation': i.recommendation,
                }
                for i in self._issues
            ],
        }
