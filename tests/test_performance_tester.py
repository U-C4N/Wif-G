import asyncio
import socket
from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from src.network_analyzer.performance_tester import (
    PerformanceTests, LatencyResult, JitterResult,
    PacketLossResult, BandwidthResult
)


@pytest.fixture
def perf_tester():
    return PerformanceTests(gateway='192.168.1.1')


class TestPerformanceTests:
    def test_init_with_gateway(self, perf_tester):
        assert perf_tester._gateway == '192.168.1.1'

    def test_init_without_gateway(self):
        tester = PerformanceTests()
        assert tester._gateway is None

    @pytest.mark.asyncio
    async def test_tcp_ping_success(self, perf_tester):
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = (AsyncMock(), mock_writer)
            result = await perf_tester._tcp_ping('8.8.8.8', 2.0)

        assert result is not None
        assert isinstance(result, float)
        assert result >= 0

    @pytest.mark.asyncio
    async def test_tcp_ping_failure(self, perf_tester):
        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError()
            result = await perf_tester._tcp_ping('unreachable.host', 0.1)

        assert result is None

    @pytest.mark.asyncio
    async def test_latency_test_with_results(self, perf_tester):
        with patch.object(perf_tester, '_measure_latencies', new_callable=AsyncMock) as mock_measure:
            mock_measure.return_value = [10.0, 12.0, 11.0, 13.0, 9.0]
            results = await perf_tester.latency_test(targets=['8.8.8.8'], samples=5)

        assert len(results) == 1
        assert results[0].target == '8.8.8.8'
        assert results[0].avg_latency > 0
        assert results[0].min_latency == 9.0
        assert results[0].max_latency == 13.0
        assert results[0].samples == 5

    @pytest.mark.asyncio
    async def test_latency_test_unreachable(self, perf_tester):
        with patch.object(perf_tester, '_measure_latencies', new_callable=AsyncMock) as mock_measure:
            mock_measure.return_value = []
            results = await perf_tester.latency_test(targets=['unreachable'], samples=5)

        assert len(results) == 1
        assert results[0].avg_latency == -1

    @pytest.mark.asyncio
    async def test_jitter_test(self, perf_tester):
        with patch.object(perf_tester, '_measure_latencies', new_callable=AsyncMock) as mock_measure:
            mock_measure.return_value = [10.0, 15.0, 12.0, 18.0, 11.0]
            result = await perf_tester.jitter_test(target='8.8.8.8', samples=5)

        assert result.target == '8.8.8.8'
        assert result.jitter > 0
        assert result.samples == 5

    @pytest.mark.asyncio
    async def test_jitter_test_insufficient_samples(self, perf_tester):
        with patch.object(perf_tester, '_measure_latencies', new_callable=AsyncMock) as mock_measure:
            mock_measure.return_value = [10.0]
            result = await perf_tester.jitter_test()

        assert result.jitter == -1
        assert result.samples == 0

    @pytest.mark.asyncio
    async def test_packet_loss_test(self, perf_tester):
        with patch.object(perf_tester, '_tcp_probe', new_callable=AsyncMock) as mock_probe:
            # 48 out of 50 succeed
            mock_probe.side_effect = [True] * 48 + [False] * 2
            result = await perf_tester.packet_loss_test(probes=50)

        assert result.sent == 50
        assert result.received == 48
        assert result.loss_percentage == 4.0

    @pytest.mark.asyncio
    async def test_packet_loss_test_no_loss(self, perf_tester):
        with patch.object(perf_tester, '_tcp_probe', new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = True
            result = await perf_tester.packet_loss_test(probes=10)

        assert result.loss_percentage == 0.0

    @pytest.mark.asyncio
    async def test_tcp_probe_success(self, perf_tester):
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = (AsyncMock(), mock_writer)
            result = await perf_tester._tcp_probe('8.8.8.8', 1.0)

        assert result is True

    @pytest.mark.asyncio
    async def test_tcp_probe_failure(self, perf_tester):
        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError()
            result = await perf_tester._tcp_probe('unreachable', 0.1)

        assert result is False

    @pytest.mark.asyncio
    async def test_bandwidth_estimate_fallback(self, perf_tester):
        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError()
            with patch.object(perf_tester, '_fallback_bandwidth_test', new_callable=AsyncMock) as mock_fallback:
                mock_fallback.return_value = 0
                result = await perf_tester.bandwidth_estimate(test_duration=1.0)

        assert isinstance(result, BandwidthResult)

    def test_default_targets(self):
        tester = PerformanceTests()
        assert '8.8.8.8' in tester.DEFAULT_TARGETS
        assert '1.1.1.1' in tester.DEFAULT_TARGETS
