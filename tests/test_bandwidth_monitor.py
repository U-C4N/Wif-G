import time
from unittest.mock import patch, MagicMock
import pytest

from src.network_analyzer.bandwidth_monitor import (
    BandwidthMonitor, ProcessBandwidth, BandwidthSnapshot
)


@pytest.fixture
def monitor():
    return BandwidthMonitor()


class TestBandwidthMonitor:
    def test_init(self, monitor):
        assert monitor._snapshots == []
        assert monitor._results == []

    @patch.object(BandwidthMonitor, '_take_snapshot')
    def test_start_monitoring(self, mock_snapshot, monitor):
        mock_snapshot.return_value = BandwidthSnapshot(
            timestamp=time.time(),
            processes={
                100: {
                    'name': 'chrome.exe',
                    'bytes_sent': 1000,
                    'bytes_recv': 5000,
                    'connections': 3,
                }
            }
        )

        results = monitor.start_monitoring(duration=1.0, interval=0.5)
        assert isinstance(results, list)
        assert mock_snapshot.call_count >= 2

    @patch.object(BandwidthMonitor, '_take_snapshot')
    def test_start_monitoring_with_delta(self, mock_snapshot, monitor):
        now = time.time()
        mock_snapshot.side_effect = [
            BandwidthSnapshot(
                timestamp=now,
                processes={
                    100: {
                        'name': 'chrome.exe',
                        'bytes_sent': 1000,
                        'bytes_recv': 5000,
                        'connections': 3,
                    }
                }
            ),
            BandwidthSnapshot(
                timestamp=now + 1.0,
                processes={
                    100: {
                        'name': 'chrome.exe',
                        'bytes_sent': 2024,
                        'bytes_recv': 15360,
                        'connections': 3,
                    }
                }
            ),
        ]

        results = monitor.start_monitoring(duration=0.5, interval=0.5)
        assert len(results) == 1
        assert results[0].pid == 100
        assert results[0].name == 'chrome.exe'
        assert results[0].send_rate_kbps == 1.0  # (2024-1000)/1.0/1024
        assert results[0].recv_rate_kbps == 10.12  # (15360-5000)/1.0/1024

    def test_get_top_consumers_empty(self, monitor):
        assert monitor.get_top_consumers() == []

    def test_get_top_consumers_sorted(self, monitor):
        monitor._results = [
            ProcessBandwidth(pid=1, name='low', bytes_sent=0, bytes_recv=0,
                             send_rate_kbps=1.0, recv_rate_kbps=1.0, connections=1),
            ProcessBandwidth(pid=2, name='high', bytes_sent=0, bytes_recv=0,
                             send_rate_kbps=100.0, recv_rate_kbps=200.0, connections=5),
            ProcessBandwidth(pid=3, name='mid', bytes_sent=0, bytes_recv=0,
                             send_rate_kbps=10.0, recv_rate_kbps=10.0, connections=2),
        ]

        top = monitor.get_top_consumers(count=2)
        assert len(top) == 2
        assert top[0].name == 'high'
        assert top[1].name == 'mid'

    def test_get_process_bandwidth_found(self, monitor):
        monitor._results = [
            ProcessBandwidth(pid=42, name='test.exe', bytes_sent=100, bytes_recv=200,
                             send_rate_kbps=5.0, recv_rate_kbps=10.0, connections=1),
        ]
        result = monitor.get_process_bandwidth(42)
        assert result is not None
        assert result.name == 'test.exe'

    def test_get_process_bandwidth_not_found(self, monitor):
        monitor._results = []
        result = monitor.get_process_bandwidth(9999)
        assert result is None

    def test_calculate_results_insufficient_snapshots(self, monitor):
        monitor._snapshots = [
            BandwidthSnapshot(timestamp=time.time(), processes={})
        ]
        assert monitor._calculate_results() == []

    def test_calculate_results_zero_duration(self, monitor):
        now = time.time()
        monitor._snapshots = [
            BandwidthSnapshot(timestamp=now, processes={}),
            BandwidthSnapshot(timestamp=now, processes={}),
        ]
        assert monitor._calculate_results() == []

    @patch('src.network_analyzer.bandwidth_monitor.psutil')
    def test_take_snapshot(self, mock_psutil, monitor):
        mock_conn = MagicMock()
        mock_conn.pid = 100
        mock_psutil.net_connections.return_value = [mock_conn]

        mock_proc = MagicMock()
        mock_proc.name.return_value = 'test.exe'
        mock_io = MagicMock()
        mock_io.write_bytes = 500
        mock_io.read_bytes = 1000
        mock_proc.io_counters.return_value = mock_io
        mock_psutil.Process.return_value = mock_proc

        snapshot = monitor._take_snapshot()
        assert isinstance(snapshot, BandwidthSnapshot)
        assert 100 in snapshot.processes
        assert snapshot.processes[100]['name'] == 'test.exe'
        assert snapshot.processes[100]['bytes_sent'] == 500
        assert snapshot.processes[100]['bytes_recv'] == 1000

    @patch('src.network_analyzer.bandwidth_monitor.psutil')
    def test_take_snapshot_access_denied(self, mock_psutil, monitor):
        import psutil as real_psutil
        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.net_connections.side_effect = real_psutil.AccessDenied(pid=0)

        snapshot = monitor._take_snapshot()
        assert snapshot.processes == {}

    def test_calculate_results_new_process(self, monitor):
        """Process appears only in last snapshot."""
        now = time.time()
        monitor._snapshots = [
            BandwidthSnapshot(timestamp=now, processes={}),
            BandwidthSnapshot(
                timestamp=now + 1.0,
                processes={
                    200: {
                        'name': 'new.exe',
                        'bytes_sent': 1024,
                        'bytes_recv': 2048,
                        'connections': 1,
                    }
                }
            ),
        ]
        results = monitor._calculate_results()
        assert len(results) == 1
        assert results[0].pid == 200
        assert results[0].send_rate_kbps == 1.0
        assert results[0].recv_rate_kbps == 2.0
