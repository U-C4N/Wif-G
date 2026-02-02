import logging
from typing import Any, Dict, List, Optional

from .database import ScanDatabase

logger = logging.getLogger(__name__)


class ScanHistory:
    def __init__(self, db_path: Optional[str] = None):
        self._db = ScanDatabase(db_path)

    def save_current_scan(self, scan_data: Dict[str, Any],
                          security_score: int, total_issues: int) -> int:
        return self._db.save_scan(scan_data, security_score, total_issues)

    def get_comparison(self) -> Optional[Dict[str, Any]]:
        """Compare latest scan with previous scan."""
        latest = self._db.get_latest_scan()
        previous = self._db.get_previous_scan()

        if latest is None:
            return None

        if previous is None:
            return {
                'has_previous': False,
                'current': latest,
                'previous': None,
                'delta': None,
            }

        delta = self._calculate_delta(latest, previous)

        return {
            'has_previous': True,
            'current': latest,
            'previous': previous,
            'delta': delta,
        }

    def _calculate_delta(self, current: Dict, previous: Dict) -> Dict[str, Any]:
        score_diff = current['security_score'] - previous['security_score']
        issues_diff = current['total_issues'] - previous['total_issues']

        # Compare open ports
        current_ports = set()
        previous_ports = set()

        current_data = current.get('scan_data', {})
        previous_data = previous.get('scan_data', {})

        for p in current_data.get('ports', {}).get('open_ports', []):
            current_ports.add(p.get('port'))
        for p in previous_data.get('ports', {}).get('open_ports', []):
            previous_ports.add(p.get('port'))

        new_ports = current_ports - previous_ports
        closed_ports = previous_ports - current_ports

        return {
            'score_change': score_diff,
            'score_direction': 'improved' if score_diff > 0 else ('declined' if score_diff < 0 else 'unchanged'),
            'issues_change': issues_diff,
            'new_open_ports': list(new_ports),
            'newly_closed_ports': list(closed_ports),
            'previous_timestamp': previous['timestamp'],
        }

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._db.list_scans(limit)

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        return self._db.get_scan_by_id(scan_id)

    def clear_history(self) -> int:
        return self._db.clear_history()
