import asyncio
import socket
import struct
import time
import logging
import statistics
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LatencyResult:
    target: str
    avg_latency: float
    min_latency: float
    max_latency: float
    samples: int


@dataclass
class JitterResult:
    target: str
    jitter: float
    samples: int


@dataclass
class PacketLossResult:
    target: str
    sent: int
    received: int
    loss_percentage: float


@dataclass
class BandwidthResult:
    download_speed_mbps: float
    test_duration: float
    bytes_received: int


@dataclass
class TracerouteHop:
    hop_number: int
    ip: Optional[str]
    latency: Optional[float]
    hostname: Optional[str]


class PerformanceTests:
    DEFAULT_TARGETS = ['8.8.8.8', '1.1.1.1']

    def __init__(self, gateway: Optional[str] = None):
        self._gateway = gateway

    async def latency_test(
        self,
        targets: Optional[List[str]] = None,
        samples: int = 10,
        timeout: float = 2.0
    ) -> List[LatencyResult]:
        if targets is None:
            targets = self.DEFAULT_TARGETS.copy()
            if self._gateway:
                targets.insert(0, self._gateway)

        results = []
        for target in targets:
            latencies = await self._measure_latencies(target, samples, timeout)
            if latencies:
                results.append(LatencyResult(
                    target=target,
                    avg_latency=round(statistics.mean(latencies), 2),
                    min_latency=round(min(latencies), 2),
                    max_latency=round(max(latencies), 2),
                    samples=len(latencies)
                ))
            else:
                results.append(LatencyResult(
                    target=target,
                    avg_latency=-1,
                    min_latency=-1,
                    max_latency=-1,
                    samples=0
                ))
        return results

    async def _measure_latencies(
        self,
        target: str,
        samples: int,
        timeout: float
    ) -> List[float]:
        latencies = []

        for _ in range(samples):
            latency = await self._tcp_ping(target, timeout)
            if latency is not None:
                latencies.append(latency)
            await asyncio.sleep(0.1)

        return latencies

    async def _tcp_ping(self, target: str, timeout: float) -> Optional[float]:
        port = 80
        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            end = time.perf_counter()
            writer.close()
            await writer.wait_closed()
            return (end - start) * 1000
        except (socket.error, asyncio.TimeoutError, OSError, ConnectionRefusedError):
            try:
                start = time.perf_counter()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, 443),
                    timeout=timeout
                )
                end = time.perf_counter()
                writer.close()
                await writer.wait_closed()
                return (end - start) * 1000
            except (socket.error, asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

    async def jitter_test(
        self,
        target: str = '8.8.8.8',
        samples: int = 20,
        timeout: float = 2.0
    ) -> JitterResult:
        latencies = await self._measure_latencies(target, samples, timeout)

        if len(latencies) < 2:
            return JitterResult(target=target, jitter=-1, samples=0)

        differences = []
        for i in range(1, len(latencies)):
            diff = abs(latencies[i] - latencies[i-1])
            differences.append(diff)

        jitter = statistics.mean(differences) if differences else 0

        return JitterResult(
            target=target,
            jitter=round(jitter, 2),
            samples=len(latencies)
        )

    async def packet_loss_test(
        self,
        target: str = '8.8.8.8',
        probes: int = 50,
        timeout: float = 1.0
    ) -> PacketLossResult:
        successful = 0

        tasks = []
        for _ in range(probes):
            tasks.append(self._tcp_probe(target, timeout))

        results = await asyncio.gather(*tasks)
        successful = sum(1 for r in results if r)

        loss_pct = ((probes - successful) / probes) * 100

        return PacketLossResult(
            target=target,
            sent=probes,
            received=successful,
            loss_percentage=round(loss_pct, 2)
        )

    async def _tcp_probe(self, target: str, timeout: float) -> bool:
        for port in [80, 443]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (socket.error, asyncio.TimeoutError, OSError, ConnectionRefusedError):
                continue
        return False

    async def bandwidth_estimate(
        self,
        test_duration: float = 5.0,
        target_host: str = 'speedtest.tele2.net',
        target_port: int = 80
    ) -> BandwidthResult:
        total_bytes = 0
        start_time = time.perf_counter()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=5.0
            )

            request = (
                f"GET /1MB.zip HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()

            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= test_duration:
                    break

                try:
                    chunk = await asyncio.wait_for(
                        reader.read(65536),
                        timeout=1.0
                    )
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                except asyncio.TimeoutError:
                    break

            writer.close()
            await writer.wait_closed()

        except (socket.error, asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
            logger.debug("Primary bandwidth test failed: %s", e)
            total_bytes = await self._fallback_bandwidth_test(test_duration)

        end_time = time.perf_counter()
        actual_duration = end_time - start_time

        if actual_duration > 0 and total_bytes > 0:
            speed_bps = (total_bytes * 8) / actual_duration
            speed_mbps = speed_bps / 1_000_000
        else:
            speed_mbps = 0

        return BandwidthResult(
            download_speed_mbps=round(speed_mbps, 2),
            test_duration=round(actual_duration, 2),
            bytes_received=total_bytes
        )

    async def _fallback_bandwidth_test(self, test_duration: float) -> int:
        total_bytes = 0
        start_time = time.perf_counter()

        targets = [
            ('google.com', 80),
            ('cloudflare.com', 80),
        ]

        for host, port in targets:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0
                )

                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()

                while time.perf_counter() - start_time < test_duration:
                    try:
                        chunk = await asyncio.wait_for(
                            reader.read(32768),
                            timeout=1.0
                        )
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                    except asyncio.TimeoutError:
                        break

                writer.close()
                await writer.wait_closed()
                break

            except (socket.error, asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
                logger.debug("Fallback bandwidth test failed for %s: %s", host, e)
                continue

        return total_bytes

    async def traceroute_lite(
        self,
        target: str = '8.8.8.8',
        max_hops: int = 15,
        timeout: float = 2.0
    ) -> List[TracerouteHop]:
        hops = []

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return hops

        for ttl in range(1, max_hops + 1):
            hop_result = await self._probe_ttl(target_ip, ttl, timeout)
            hops.append(TracerouteHop(
                hop_number=ttl,
                ip=hop_result.get('ip'),
                latency=hop_result.get('latency'),
                hostname=hop_result.get('hostname')
            ))

            if hop_result.get('ip') == target_ip:
                break

        return hops

    async def _probe_ttl(
        self,
        target: str,
        ttl: int,
        timeout: float
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {'ip': None, 'latency': None, 'hostname': None}

        try:
            loop = asyncio.get_running_loop()
            probe_result = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_ttl_probe, target, ttl),
                timeout=timeout
            )
            return probe_result
        except asyncio.TimeoutError:
            return result
        except Exception:
            return result

    def _sync_ttl_probe(self, target: str, ttl: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {'ip': None, 'latency': None, 'hostname': None}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(1.5)

            dest_port = 33434 + ttl

            start = time.perf_counter()
            sock.sendto(b'', (target, dest_port))

            try:
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                recv_sock.settimeout(1.5)

                data, addr = recv_sock.recvfrom(512)
                end = time.perf_counter()

                result['ip'] = addr[0]
                result['latency'] = round((end - start) * 1000, 2)

                try:
                    hostname = socket.gethostbyaddr(addr[0])[0]
                    result['hostname'] = hostname
                except (socket.herror, socket.gaierror):
                    pass

                recv_sock.close()
            except socket.timeout:
                pass
            except PermissionError:
                result = self._tcp_ttl_probe(target, ttl)

            sock.close()

        except (socket.error, OSError) as e:
            logger.debug("TTL probe failed for ttl=%d: %s", ttl, e)
            result = self._tcp_ttl_probe(target, ttl)

        return result

    def _tcp_ttl_probe(self, target: str, ttl: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {'ip': None, 'latency': None, 'hostname': None}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(1.0)

            start = time.perf_counter()
            try:
                sock.connect((target, 80))
                end = time.perf_counter()
                result['ip'] = target
                result['latency'] = round((end - start) * 1000, 2)
            except socket.timeout:
                pass
            except socket.error as e:
                if ttl > 10:
                    result['ip'] = target

            sock.close()
        except (socket.error, PermissionError) as e:
            logger.debug("TCP TTL probe failed for ttl=%d: %s", ttl, e)

        return result

    def run_latency_test(
        self,
        targets: Optional[List[str]] = None,
        samples: int = 10
    ) -> List[LatencyResult]:
        return asyncio.run(self.latency_test(targets, samples))

    def run_jitter_test(
        self,
        target: str = '8.8.8.8',
        samples: int = 20
    ) -> JitterResult:
        return asyncio.run(self.jitter_test(target, samples))

    def run_packet_loss_test(
        self,
        target: str = '8.8.8.8',
        probes: int = 50
    ) -> PacketLossResult:
        return asyncio.run(self.packet_loss_test(target, probes))

    def run_bandwidth_estimate(
        self,
        test_duration: float = 5.0
    ) -> BandwidthResult:
        return asyncio.run(self.bandwidth_estimate(test_duration))

    def run_traceroute_lite(
        self,
        target: str = '8.8.8.8',
        max_hops: int = 15
    ) -> List[TracerouteHop]:
        return asyncio.run(self.traceroute_lite(target, max_hops))
