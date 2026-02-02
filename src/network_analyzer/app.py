import asyncio
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .network_scanner import NetworkScanner
from .port_scanner import PortScanner
from .dns_analyzer import DNSAnalyzer
from .performance_tester import PerformanceTests
from .security_analyzer import SecurityAnalyzer
from .optimizer import NetworkOptimizer
from .config import load_config, get_nested
from .report_exporter import ReportExporter
from .history import ScanHistory

logger = logging.getLogger(__name__)


class AnalysisResults:
    """Holds all scan results for the current analysis session."""
    def __init__(self):
        self.network: Optional[Dict[str, Any]] = None
        self.dns: Optional[Dict[str, Any]] = None
        self.performance: Optional[Dict[str, Any]] = None
        self.ports: Optional[Dict[str, Any]] = None
        self.security: Optional[Dict[str, Any]] = None
        self.optimization_plan: Optional[List[Dict]] = None
        self.manual_recommendations: Optional[List[Dict]] = None


class NetworkAnalyzerEngine:
    """Core business logic - no UI code."""

    def __init__(self, config: Optional[Dict] = None):
        self._config = config or load_config()
        self._network_scanner = NetworkScanner()
        self._port_scanner = PortScanner(
            timeout=get_nested(self._config, 'port_scanner', 'timeout', default=1.0)
        )
        self._port_scanner.MAX_WORKERS = get_nested(
            self._config, 'port_scanner', 'max_workers', default=50
        )
        self._dns_analyzer = DNSAnalyzer()
        self._performance_tester: Optional[PerformanceTests] = None
        self._performance_results: Optional[Dict] = None
        self._security_analyzer: Optional[SecurityAnalyzer] = None
        self._optimizer: Optional[NetworkOptimizer] = None
        self._results = AnalysisResults()

    @property
    def results(self) -> AnalysisResults:
        return self._results

    @property
    def network_scanner(self) -> NetworkScanner:
        return self._network_scanner

    @property
    def port_scanner(self) -> PortScanner:
        return self._port_scanner

    @property
    def dns_analyzer(self) -> DNSAnalyzer:
        return self._dns_analyzer

    @property
    def security_analyzer(self) -> Optional[SecurityAnalyzer]:
        return self._security_analyzer

    @property
    def optimizer(self) -> Optional[NetworkOptimizer]:
        return self._optimizer

    def scan_network(self) -> Dict[str, Any]:
        self._network_scanner.scan()
        stats = self._network_scanner.get_network_stats()

        result = {
            'ssid': self._network_scanner.ssid,
            'signal_strength': self._network_scanner.signal_strength,
            'local_ip': self._network_scanner.local_ip,
            'gateway': self._network_scanner.gateway,
            'interfaces': self._network_scanner.interfaces,
            'stats': stats,
        }
        self._results.network = result
        return result

    def scan_dns(self) -> Dict[str, Any]:
        self._dns_analyzer.analyze()

        servers = []
        for dns in self._dns_analyzer.current_dns:
            servers.append({
                'ip': dns.ip,
                'provider': dns.provider,
                'response_time': dns.response_time,
                'is_public_resolver': dns.is_public_resolver,
            })

        result = {
            'servers': servers,
            'warnings': self._dns_analyzer.dns_warnings,
        }
        self._results.dns = result
        return result

    def run_performance_tests(self) -> Dict[str, Any]:
        gateway = self._network_scanner.gateway
        self._performance_tester = PerformanceTests(gateway=gateway)

        samples = get_nested(self._config, 'performance', 'latency_samples', default=10)
        jitter_samples = get_nested(self._config, 'performance', 'jitter_samples', default=20)
        probes = get_nested(self._config, 'performance', 'packet_loss_probes', default=50)
        bw_duration = get_nested(self._config, 'performance', 'bandwidth_duration', default=5.0)

        latency_results = asyncio.run(self._performance_tester.latency_test(samples=samples))
        jitter_result = asyncio.run(self._performance_tester.jitter_test(samples=jitter_samples))
        packet_loss_result = asyncio.run(self._performance_tester.packet_loss_test(probes=probes))
        bandwidth_result = asyncio.run(self._performance_tester.bandwidth_estimate(test_duration=bw_duration))

        self._performance_results = {
            'latency': latency_results,
            'jitter': jitter_result,
            'packet_loss': packet_loss_result,
            'bandwidth': bandwidth_result,
        }

        # Serializable version
        result = {
            'latency': [asdict(r) for r in latency_results],
            'jitter': asdict(jitter_result),
            'packet_loss': asdict(packet_loss_result),
            'bandwidth': asdict(bandwidth_result),
        }
        self._results.performance = result
        return result

    def scan_ports(self) -> Dict[str, Any]:
        target = self._network_scanner.gateway or 'localhost'
        self._port_scanner.target = target

        scan_type = get_nested(self._config, 'port_scanner', 'scan_type', default='common')
        if scan_type == 'quick':
            self._port_scanner.quick_scan()
        elif scan_type == 'range':
            start = get_nested(self._config, 'port_scanner', 'port_range_start', default=1)
            end = get_nested(self._config, 'port_scanner', 'port_range_end', default=1024)
            self._port_scanner.scan_port_range(start, end)
        else:
            self._port_scanner.scan_common_ports()

        open_ports = [asdict(p) for p in self._port_scanner.open_ports]
        dangerous_ports = [asdict(p) for p in self._port_scanner.get_dangerous_ports()]

        result = {
            'target': target,
            'open_ports': open_ports,
            'dangerous_ports': dangerous_ports,
        }
        self._results.ports = result
        return result

    def analyze_security(self) -> Dict[str, Any]:
        self._security_analyzer = SecurityAnalyzer(
            self._network_scanner,
            self._port_scanner,
            self._dns_analyzer,
            self._performance_tester
        )

        if self._performance_results:
            self._security_analyzer.set_performance_results(self._performance_results)

        self._security_analyzer.analyze()
        summary = self._security_analyzer.get_summary()

        issues = []
        for issue in self._security_analyzer.issues:
            issues.append({
                'category': issue.category,
                'title': issue.title,
                'description': issue.description,
                'risk_level': issue.risk_level.name,
                'recommendation': issue.recommendation,
                'auto_fixable': issue.auto_fixable,
            })

        result = {
            'score': summary['security_score'],
            'issues': issues,
            'summary': summary,
        }
        self._results.security = result
        return result

    def get_optimization_plan(self) -> Dict[str, Any]:
        if self._security_analyzer is None:
            return {'plan': [], 'manual_recommendations': []}

        self._optimizer = NetworkOptimizer(
            self._security_analyzer,
            self._dns_analyzer
        )

        plan = self._optimizer.get_optimization_plan()
        manual_recs = self._optimizer.get_manual_recommendations()

        self._results.optimization_plan = plan
        self._results.manual_recommendations = manual_recs

        return {
            'plan': plan,
            'manual_recommendations': manual_recs,
        }

    def apply_optimizations(self) -> List[Dict[str, Any]]:
        if self._optimizer is None:
            return []

        results = self._optimizer.apply_all_optimizations()
        return [asdict(r) for r in results]

    def run_full_analysis(self) -> AnalysisResults:
        self.scan_network()
        self.scan_dns()
        self.run_performance_tests()
        self.scan_ports()
        self.analyze_security()
        self.get_optimization_plan()
        return self._results

    def export_report(self, format: str = 'json',
                      output_dir: Optional[str] = None) -> str:
        out_dir = output_dir or get_nested(self._config, 'export', 'output_dir', default='./reports')
        prefix = get_nested(self._config, 'export', 'filename_prefix', default='wifg')

        exporter = ReportExporter(output_dir=out_dir, filename_prefix=prefix)

        if self._results.network:
            exporter.set_data('network', self._results.network)
        if self._results.dns:
            exporter.set_data('dns', self._results.dns)
        if self._results.ports:
            exporter.set_data('ports', self._results.ports)
        if self._results.performance:
            exporter.set_data('performance', self._results.performance)
        if self._results.security:
            exporter.set_data('security', self._results.security)

        if format == 'html':
            return exporter.export_html()
        else:
            return exporter.export_json()

    def save_to_history(self, db_path: Optional[str] = None) -> int:
        history = ScanHistory(db_path)
        score = 0
        issues = 0
        if self._results.security:
            score = self._results.security.get('score', 0)
            issues = self._results.security.get('summary', {}).get('total_issues', 0)

        scan_data = {}
        if self._results.network:
            scan_data['network'] = self._results.network
        if self._results.dns:
            scan_data['dns'] = self._results.dns
        if self._results.ports:
            scan_data['ports'] = self._results.ports
        if self._results.performance:
            scan_data['performance'] = self._results.performance
        if self._results.security:
            scan_data['security'] = self._results.security

        return history.save_current_scan(scan_data, score, issues)
