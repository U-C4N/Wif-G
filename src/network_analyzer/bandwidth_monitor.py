import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ProcessBandwidth:
    pid: int
    name: str
    bytes_sent: int
    bytes_recv: int
    send_rate_kbps: float
    recv_rate_kbps: float
    connections: int


@dataclass
class BandwidthSnapshot:
    timestamp: float
    processes: Dict[int, Dict]


class BandwidthMonitor:
    """Monitor per-process network bandwidth usage on Windows and Linux."""

    def __init__(self):
        self._snapshots: List[BandwidthSnapshot] = []
        self._results: List[ProcessBandwidth] = []

    def start_monitoring(
        self,
        duration: float = 30.0,
        interval: float = 1.0
    ) -> List[ProcessBandwidth]:
        """Monitor bandwidth for the given duration, sampling at interval seconds."""
        self._snapshots = []
        self._results = []

        start_time = time.time()
        end_time = start_time + duration

        # Take initial snapshot
        self._snapshots.append(self._take_snapshot())

        while time.time() < end_time:
            time.sleep(interval)
            self._snapshots.append(self._take_snapshot())

        self._results = self._calculate_results()
        return self._results

    def get_top_consumers(self, count: int = 10) -> List[ProcessBandwidth]:
        """Return top bandwidth consumers sorted by total rate (send + recv)."""
        sorted_results = sorted(
            self._results,
            key=lambda p: p.send_rate_kbps + p.recv_rate_kbps,
            reverse=True
        )
        return sorted_results[:count]

    def get_process_bandwidth(self, pid: int) -> Optional[ProcessBandwidth]:
        """Get bandwidth info for a specific process."""
        for result in self._results:
            if result.pid == pid:
                return result
        return None

    def _take_snapshot(self) -> BandwidthSnapshot:
        """Capture current per-process network connection state."""
        processes: Dict[int, Dict] = {}

        # Map connections to PIDs
        pid_connections: Dict[int, int] = {}
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid and conn.pid > 0:
                    pid_connections[conn.pid] = pid_connections.get(conn.pid, 0) + 1
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError) as e:
            logger.debug("Cannot enumerate connections: %s", e)

        # Get IO counters for each process with connections
        for pid, conn_count in pid_connections.items():
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    io = proc.io_counters()
                    processes[pid] = {
                        'name': name,
                        'bytes_sent': io.write_bytes,
                        'bytes_recv': io.read_bytes,
                        'connections': conn_count,
                    }
                except (psutil.AccessDenied, AttributeError):
                    # io_counters not available or access denied
                    processes[pid] = {
                        'name': name,
                        'bytes_sent': 0,
                        'bytes_recv': 0,
                        'connections': conn_count,
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return BandwidthSnapshot(
            timestamp=time.time(),
            processes=processes
        )

    def _calculate_results(self) -> List[ProcessBandwidth]:
        """Calculate bandwidth rates from snapshots."""
        if len(self._snapshots) < 2:
            return []

        first = self._snapshots[0]
        last = self._snapshots[-1]
        duration = last.timestamp - first.timestamp

        if duration <= 0:
            return []

        results: List[ProcessBandwidth] = []

        # Find PIDs present in both first and last snapshots
        all_pids = set(first.processes.keys()) | set(last.processes.keys())

        for pid in all_pids:
            first_data = first.processes.get(pid)
            last_data = last.processes.get(pid)

            if not last_data:
                continue

            name = last_data['name']

            if first_data:
                delta_sent = max(0, last_data['bytes_sent'] - first_data['bytes_sent'])
                delta_recv = max(0, last_data['bytes_recv'] - first_data['bytes_recv'])
            else:
                delta_sent = last_data['bytes_sent']
                delta_recv = last_data['bytes_recv']

            send_rate_kbps = round((delta_sent / duration) / 1024, 2)
            recv_rate_kbps = round((delta_recv / duration) / 1024, 2)

            # Only include processes with actual bandwidth usage
            if send_rate_kbps > 0 or recv_rate_kbps > 0:
                results.append(ProcessBandwidth(
                    pid=pid,
                    name=name,
                    bytes_sent=delta_sent,
                    bytes_recv=delta_recv,
                    send_rate_kbps=send_rate_kbps,
                    recv_rate_kbps=recv_rate_kbps,
                    connections=last_data['connections'],
                ))

        return results
