import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.expanduser('~'), '.wifg', 'history.db')


class ScanDatabase:
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    security_score INTEGER,
                    total_issues INTEGER,
                    scan_data TEXT NOT NULL
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp
                ON scans(timestamp)
            ''')

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def save_scan(self, scan_data: Dict[str, Any], security_score: int, total_issues: int) -> int:
        timestamp = datetime.now().isoformat()
        data_json = json.dumps(scan_data, default=str)

        with self._connect() as conn:
            cursor = conn.execute(
                'INSERT INTO scans (timestamp, security_score, total_issues, scan_data) VALUES (?, ?, ?, ?)',
                (timestamp, security_score, total_issues, data_json)
            )
            scan_id = cursor.lastrowid
            logger.info("Scan saved with ID %d", scan_id)
            return scan_id

    def get_latest_scan(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT id, timestamp, security_score, total_issues, scan_data FROM scans ORDER BY id DESC LIMIT 1'
            ).fetchone()

        if row is None:
            return None

        return {
            'id': row[0],
            'timestamp': row[1],
            'security_score': row[2],
            'total_issues': row[3],
            'scan_data': json.loads(row[4]),
        }

    def get_previous_scan(self) -> Optional[Dict[str, Any]]:
        """Get the second most recent scan (for comparison)."""
        with self._connect() as conn:
            row = conn.execute(
                'SELECT id, timestamp, security_score, total_issues, scan_data FROM scans ORDER BY id DESC LIMIT 1 OFFSET 1'
            ).fetchone()

        if row is None:
            return None

        return {
            'id': row[0],
            'timestamp': row[1],
            'security_score': row[2],
            'total_issues': row[3],
            'scan_data': json.loads(row[4]),
        }

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT id, timestamp, security_score, total_issues, scan_data FROM scans WHERE id = ?',
                (scan_id,)
            ).fetchone()

        if row is None:
            return None

        return {
            'id': row[0],
            'timestamp': row[1],
            'security_score': row[2],
            'total_issues': row[3],
            'scan_data': json.loads(row[4]),
        }

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT id, timestamp, security_score, total_issues FROM scans ORDER BY id DESC LIMIT ?',
                (limit,)
            ).fetchall()

        return [
            {
                'id': row[0],
                'timestamp': row[1],
                'security_score': row[2],
                'total_issues': row[3],
            }
            for row in rows
        ]

    def delete_scan(self, scan_id: int) -> bool:
        with self._connect() as conn:
            cursor = conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            return cursor.rowcount > 0

    def clear_history(self) -> int:
        with self._connect() as conn:
            cursor = conn.execute('DELETE FROM scans')
            return cursor.rowcount
