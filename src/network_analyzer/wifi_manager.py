import subprocess
import re
import logging
import platform
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    WPA3 = 'WPA3'
    WPA2 = 'WPA2'
    WPA = 'WPA'
    WEP = 'WEP'
    OPEN = 'Open'
    UNKNOWN = 'Unknown'


SECURITY_RATINGS = {
    SecurityLevel.WPA3: ('safe', 'WPA3 - En guevenli kablosuz sifreleme standardi'),
    SecurityLevel.WPA2: ('ok', 'WPA2 - Yeterli guevenlik, WPA3 tercih edilir'),
    SecurityLevel.WPA: ('weak', 'WPA - Eski ve zayif, WPA2/WPA3 kullanin'),
    SecurityLevel.WEP: ('dangerous', 'WEP - Cok zayif sifreleme, kolayca kirilabiir'),
    SecurityLevel.OPEN: ('dangerous', 'Acik ag - Sifreleme yok, tum trafik goruelebilir'),
    SecurityLevel.UNKNOWN: ('unknown', 'Guevenlik tueri belirlenemedi'),
}


def _sanitize_profile_name(name: str) -> str:
    """Sanitize profile name to prevent injection."""
    return re.sub(r'[^a-zA-Z0-9_ \-().\u00c0-\u024f\u0400-\u04ff]', '', name)


@dataclass
class WiFiProfile:
    name: str
    security_level: SecurityLevel
    authentication: str
    cipher: str
    password: Optional[str]
    connection_mode: str
    rating: str
    rating_description: str


class WiFiProfileManager:
    def __init__(self):
        self._profiles: List[WiFiProfile] = []
        self._is_windows = platform.system() == 'Windows'

    def get_all_profiles(self) -> List[WiFiProfile]:
        """List all saved WiFi profiles with their security details."""
        if not self._is_windows:
            logger.warning("WiFi profile management is only supported on Windows")
            return []

        self._profiles = []
        profile_names = self._list_profile_names()

        for name in profile_names:
            profile = self.analyze_profile(name)
            if profile:
                self._profiles.append(profile)

        return self._profiles

    def _list_profile_names(self) -> List[str]:
        """Get all saved WiFi profile names via netsh."""
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                timeout=10
            )
            names = []
            for line in result.stdout.split('\n'):
                match = re.search(r'All User Profile\s*:\s*(.+)', line)
                if not match:
                    match = re.search(r'Tum Kullanici Profili\s*:\s*(.+)', line)
                if match:
                    name = match.group(1).strip()
                    if name:
                        names.append(name)
            return names
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not list WiFi profiles: %s", e)
            return []

    def analyze_profile(self, name: str) -> Optional[WiFiProfile]:
        """Analyze a single WiFi profile's security details."""
        if not self._is_windows:
            return None

        sanitized = _sanitize_profile_name(name)
        if not sanitized:
            return None

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profile',
                 f'name={sanitized}', 'key=clear'],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
            if result.returncode != 0:
                logger.debug("Could not get profile details for '%s'", sanitized)
                return None

            authentication = self._parse_field(output, r'Authentication\s*:\s*(.+)')
            if not authentication:
                authentication = self._parse_field(output, r'Kimlik Do.rulama\s*:\s*(.+)')
            authentication = authentication or 'Unknown'

            cipher = self._parse_field(output, r'Cipher\s*:\s*(.+)')
            if not cipher:
                cipher = self._parse_field(output, r'ifre\s*:\s*(.+)')
            cipher = cipher or 'Unknown'

            password = self._parse_field(output, r'Key Content\s*:\s*(.+)')
            if not password:
                password = self._parse_field(output, r'Anahtar .eri.i\s*:\s*(.+)')

            connection_mode = self._parse_field(output, r'Connection mode\s*:\s*(.+)')
            if not connection_mode:
                connection_mode = self._parse_field(output, r'Ba.lant. modu\s*:\s*(.+)')
            connection_mode = connection_mode or 'Unknown'

            security_level = self._classify_security(authentication, cipher)
            rating, rating_desc = SECURITY_RATINGS[security_level]

            return WiFiProfile(
                name=name,
                security_level=security_level,
                authentication=authentication,
                cipher=cipher,
                password=password,
                connection_mode=connection_mode,
                rating=rating,
                rating_description=rating_desc,
            )

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not analyze profile '%s': %s", sanitized, e)
            return None

    def _parse_field(self, output: str, pattern: str) -> Optional[str]:
        """Parse a field from netsh output using regex."""
        match = re.search(pattern, output)
        if match:
            value = match.group(1).strip()
            return value if value else None
        return None

    def _classify_security(self, authentication: str, cipher: str) -> SecurityLevel:
        """Classify the security level based on auth and cipher."""
        auth_lower = authentication.lower()
        cipher_lower = cipher.lower()

        if 'wpa3' in auth_lower:
            return SecurityLevel.WPA3
        if 'wpa2' in auth_lower:
            return SecurityLevel.WPA2
        if 'wpa' in auth_lower:
            return SecurityLevel.WPA
        if 'wep' in cipher_lower or 'wep' in auth_lower:
            return SecurityLevel.WEP
        if 'open' in auth_lower or 'acik' in auth_lower:
            return SecurityLevel.OPEN

        return SecurityLevel.UNKNOWN

    def get_insecure_profiles(self) -> List[WiFiProfile]:
        """Return profiles with dangerous or weak security."""
        if not self._profiles:
            self.get_all_profiles()
        return [p for p in self._profiles if p.rating in ('dangerous', 'weak')]

    def get_secure_profiles(self) -> List[WiFiProfile]:
        """Return profiles with safe or ok security."""
        if not self._profiles:
            self.get_all_profiles()
        return [p for p in self._profiles if p.rating in ('safe', 'ok')]

    def delete_profile(self, name: str) -> bool:
        """Delete a saved WiFi profile. Returns True if successful."""
        if not self._is_windows:
            logger.warning("WiFi profile deletion is only supported on Windows")
            return False

        sanitized = _sanitize_profile_name(name)
        if not sanitized:
            return False

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'delete', 'profile', f'name={sanitized}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self._profiles = [p for p in self._profiles if p.name != name]
                logger.info("Deleted WiFi profile: %s", sanitized)
                return True
            else:
                logger.warning("Failed to delete profile '%s': %s",
                               sanitized, result.stderr.strip())
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.debug("Could not delete profile '%s': %s", sanitized, e)
            return False

    @property
    def profiles(self) -> List[WiFiProfile]:
        return self._profiles

    def get_summary(self) -> Dict:
        """Return a summary of all profiles by security rating."""
        if not self._profiles:
            self.get_all_profiles()

        return {
            'total_profiles': len(self._profiles),
            'safe': len([p for p in self._profiles if p.rating == 'safe']),
            'ok': len([p for p in self._profiles if p.rating == 'ok']),
            'weak': len([p for p in self._profiles if p.rating == 'weak']),
            'dangerous': len([p for p in self._profiles if p.rating == 'dangerous']),
            'unknown': len([p for p in self._profiles if p.rating == 'unknown']),
        }
