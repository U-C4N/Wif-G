from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.wifi_manager import (
    WiFiProfileManager, WiFiProfile, SecurityLevel, _sanitize_profile_name,
)


@pytest.fixture
def manager():
    mgr = WiFiProfileManager()
    mgr._is_windows = True
    return mgr


class TestSanitizeProfileName:
    def test_normal_name(self):
        assert _sanitize_profile_name('MyWiFi') == 'MyWiFi'

    def test_name_with_spaces(self):
        assert _sanitize_profile_name('My Home WiFi') == 'My Home WiFi'

    def test_name_with_special_chars(self):
        assert _sanitize_profile_name('WiFi@Home!#$') == 'WiFiHome'

    def test_name_with_parens_dash(self):
        assert _sanitize_profile_name('WiFi (5GHz) - Fast') == 'WiFi (5GHz) - Fast'

    def test_empty_name(self):
        assert _sanitize_profile_name('') == ''


class TestWiFiProfileManager:
    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_list_profile_names(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Profiles on interface Wi-Fi:\n'
                '\n'
                'Group policy profiles (read only)\n'
                '---------------------------------\n'
                '    <None>\n'
                '\n'
                'User profiles\n'
                '-------------\n'
                '    All User Profile     : HomeWiFi\n'
                '    All User Profile     : OfficeNet\n'
                '    All User Profile     : CafeSpot\n'
            ),
            returncode=0
        )

        names = manager._list_profile_names()

        assert names == ['HomeWiFi', 'OfficeNet', 'CafeSpot']

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_list_profile_names_turkish_locale(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Wi-Fi arabirimindeki profiller:\n'
                '\n'
                '    Tum Kullanici Profili     : EvWiFi\n'
                '    Tum Kullanici Profili     : IsYeri\n'
            ),
            returncode=0
        )

        names = manager._list_profile_names()

        assert names == ['EvWiFi', 'IsYeri']

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_analyze_profile_wpa2(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Profile HomeWiFi on interface Wi-Fi:\n'
                '    Authentication         : WPA2-Personal\n'
                '    Cipher                 : CCMP\n'
                '    Key Content            : mysecretpass\n'
                '    Connection mode        : Connect automatically\n'
            ),
            returncode=0
        )

        profile = manager.analyze_profile('HomeWiFi')

        assert profile is not None
        assert profile.name == 'HomeWiFi'
        assert profile.security_level == SecurityLevel.WPA2
        assert profile.authentication == 'WPA2-Personal'
        assert profile.cipher == 'CCMP'
        assert profile.password == 'mysecretpass'
        assert profile.rating == 'ok'

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_analyze_profile_wpa3(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Profile SecureNet on interface Wi-Fi:\n'
                '    Authentication         : WPA3-Personal\n'
                '    Cipher                 : GCMP\n'
                '    Connection mode        : Connect manually\n'
            ),
            returncode=0
        )

        profile = manager.analyze_profile('SecureNet')

        assert profile is not None
        assert profile.security_level == SecurityLevel.WPA3
        assert profile.rating == 'safe'

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_analyze_profile_open(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Profile FreeWiFi on interface Wi-Fi:\n'
                '    Authentication         : Open\n'
                '    Cipher                 : None\n'
                '    Connection mode        : Connect manually\n'
            ),
            returncode=0
        )

        profile = manager.analyze_profile('FreeWiFi')

        assert profile is not None
        assert profile.security_level == SecurityLevel.OPEN
        assert profile.rating == 'dangerous'

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_analyze_profile_wep(self, mock_run, manager):
        mock_run.return_value = MagicMock(
            stdout=(
                'Profile OldRouter on interface Wi-Fi:\n'
                '    Authentication         : WEP\n'
                '    Cipher                 : WEP\n'
                '    Connection mode        : Connect automatically\n'
            ),
            returncode=0
        )

        profile = manager.analyze_profile('OldRouter')

        assert profile is not None
        assert profile.security_level == SecurityLevel.WEP
        assert profile.rating == 'dangerous'

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_analyze_profile_failure(self, mock_run, manager):
        mock_run.return_value = MagicMock(stdout='', returncode=1)

        profile = manager.analyze_profile('BadProfile')

        assert profile is None

    def test_get_insecure_profiles(self, manager):
        manager._profiles = [
            WiFiProfile('Safe', SecurityLevel.WPA3, 'WPA3-Personal', 'GCMP', None, 'auto', 'safe', ''),
            WiFiProfile('OK', SecurityLevel.WPA2, 'WPA2-Personal', 'CCMP', None, 'auto', 'ok', ''),
            WiFiProfile('Bad', SecurityLevel.OPEN, 'Open', 'None', None, 'manual', 'dangerous', ''),
            WiFiProfile('Weak', SecurityLevel.WPA, 'WPA-Personal', 'TKIP', None, 'auto', 'weak', ''),
        ]

        insecure = manager.get_insecure_profiles()

        assert len(insecure) == 2
        assert insecure[0].name == 'Bad'
        assert insecure[1].name == 'Weak'

    def test_get_secure_profiles(self, manager):
        manager._profiles = [
            WiFiProfile('Safe', SecurityLevel.WPA3, 'WPA3-Personal', 'GCMP', None, 'auto', 'safe', ''),
            WiFiProfile('OK', SecurityLevel.WPA2, 'WPA2-Personal', 'CCMP', None, 'auto', 'ok', ''),
            WiFiProfile('Bad', SecurityLevel.OPEN, 'Open', 'None', None, 'manual', 'dangerous', ''),
        ]

        secure = manager.get_secure_profiles()

        assert len(secure) == 2
        assert secure[0].name == 'Safe'
        assert secure[1].name == 'OK'

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_delete_profile_success(self, mock_run, manager):
        manager._profiles = [
            WiFiProfile('BadNet', SecurityLevel.OPEN, 'Open', 'None', None, 'manual', 'dangerous', ''),
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr='')

        result = manager.delete_profile('BadNet')

        assert result is True
        assert len(manager._profiles) == 0

    @patch('src.network_analyzer.wifi_manager.subprocess.run')
    def test_delete_profile_failure(self, mock_run, manager):
        mock_run.return_value = MagicMock(returncode=1, stderr='Profile not found')

        result = manager.delete_profile('NonExistent')

        assert result is False

    def test_get_summary(self, manager):
        manager._profiles = [
            WiFiProfile('A', SecurityLevel.WPA3, '', '', None, '', 'safe', ''),
            WiFiProfile('B', SecurityLevel.WPA2, '', '', None, '', 'ok', ''),
            WiFiProfile('C', SecurityLevel.WPA2, '', '', None, '', 'ok', ''),
            WiFiProfile('D', SecurityLevel.OPEN, '', '', None, '', 'dangerous', ''),
            WiFiProfile('E', SecurityLevel.WEP, '', '', None, '', 'dangerous', ''),
        ]

        summary = manager.get_summary()

        assert summary['total_profiles'] == 5
        assert summary['safe'] == 1
        assert summary['ok'] == 2
        assert summary['dangerous'] == 2

    def test_not_windows(self):
        mgr = WiFiProfileManager()
        mgr._is_windows = False

        assert mgr.get_all_profiles() == []
        assert mgr.analyze_profile('test') is None
        assert mgr.delete_profile('test') is False
