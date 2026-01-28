from typing import Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

from .network_scanner import NetworkScanner
from .port_scanner import PortScanner, PortInfo
from .dns_analyzer import DNSAnalyzer

if TYPE_CHECKING:
    from .performance_tester import PerformanceTests, LatencyResult, PacketLossResult, JitterResult


class RiskLevel(Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class SecurityIssue:
    category: str
    title: str
    description: str
    risk_level: RiskLevel
    recommendation: str
    auto_fixable: bool


class SecurityAnalyzer:
    def __init__(
        self,
        network_scanner: NetworkScanner,
        port_scanner: PortScanner,
        dns_analyzer: DNSAnalyzer,
        performance_tester: Optional["PerformanceTests"] = None
    ):
        self._network_scanner = network_scanner
        self._port_scanner = port_scanner
        self._dns_analyzer = dns_analyzer
        self._performance_tester = performance_tester
        self._performance_results: Optional[Dict] = None
        self._issues: List[SecurityIssue] = []
        self._security_score: int = 100
    
    def set_performance_results(self, results: Dict) -> None:
        self._performance_results = results
        
    def analyze(self) -> None:
        self._issues = []
        self._security_score = 100
        
        self._analyze_ports()
        self._analyze_dns()
        self._analyze_network()
        self._analyze_performance()
        self._calculate_score()
        
    def _analyze_ports(self) -> None:
        dangerous_ports = self._port_scanner.get_dangerous_ports()
        
        for port_info in dangerous_ports:
            severity = RiskLevel.CRITICAL if port_info.risk_level == 'critical' else RiskLevel.HIGH
            
            self._issues.append(SecurityIssue(
                category='Port Security',
                title=f'Dangerous port open: {port_info.port} ({port_info.service})',
                description=port_info.description,
                risk_level=severity,
                recommendation=self._port_scanner.get_recommendation(port_info),
                auto_fixable=False
            ))
            
    def _analyze_dns(self) -> None:
        for warning in self._dns_analyzer.dns_warnings:
            self._issues.append(SecurityIssue(
                category='DNS Security',
                title='Insecure DNS configuration',
                description=warning,
                risk_level=RiskLevel.MEDIUM,
                recommendation='Switch to a known public DNS provider (Cloudflare, Google)',
                auto_fixable=True
            ))
            
        dns_recs = self._dns_analyzer.get_dns_recommendations()
        for rec in dns_recs:
            if rec['type'] == 'warning':
                self._issues.append(SecurityIssue(
                    category='DNS Security',
                    title=rec['message'],
                    description='Your DNS traffic may be unencrypted',
                    risk_level=RiskLevel.MEDIUM,
                    recommendation=rec['suggestion'],
                    auto_fixable=True
                ))
                
    def _analyze_network(self) -> None:
        stats = self._network_scanner.get_network_stats()
        
        if stats['errors_in'] > 100 or stats['errors_out'] > 100:
            self._issues.append(SecurityIssue(
                category='Network Health',
                title='High network error rate',
                description=f"Incoming errors: {stats['errors_in']}, Outgoing errors: {stats['errors_out']}",
                risk_level=RiskLevel.MEDIUM,
                recommendation='Check your network connection and cables',
                auto_fixable=False
            ))
            
        if stats['drop_in'] > 50 or stats['drop_out'] > 50:
            self._issues.append(SecurityIssue(
                category='Network Health',
                title='Packet loss detected',
                description=f"Dropped packets - Incoming: {stats['drop_in']}, Outgoing: {stats['drop_out']}",
                risk_level=RiskLevel.LOW,
                recommendation='Restart your router or contact your ISP',
                auto_fixable=False
            ))
            
        signal = self._network_scanner.signal_strength
        if signal is not None and signal < -70:
            self._issues.append(SecurityIssue(
                category='WiFi Quality',
                title='Weak WiFi signal',
                description=f'Signal strength: {signal} dBm (weak)',
                risk_level=RiskLevel.LOW,
                recommendation='Move closer to the router or use a WiFi extender',
                auto_fixable=False
            ))
    
    def _analyze_performance(self) -> None:
        if not self._performance_results:
            return
            
        latency_results = self._performance_results.get('latency', [])
        for result in latency_results:
            if result.avg_latency > 200 and result.avg_latency != -1:
                self._issues.append(SecurityIssue(
                    category='Network Performance',
                    title=f'High latency to {result.target}',
                    description=f'Average latency: {result.avg_latency}ms (high latency can indicate network issues)',
                    risk_level=RiskLevel.MEDIUM,
                    recommendation='Check your network connection or contact ISP',
                    auto_fixable=False
                ))
            elif result.avg_latency > 100 and result.avg_latency != -1:
                self._issues.append(SecurityIssue(
                    category='Network Performance',
                    title=f'Elevated latency to {result.target}',
                    description=f'Average latency: {result.avg_latency}ms',
                    risk_level=RiskLevel.LOW,
                    recommendation='Consider optimizing network settings',
                    auto_fixable=False
                ))
                
        jitter_result = self._performance_results.get('jitter')
        if jitter_result and jitter_result.jitter > 30 and jitter_result.jitter != -1:
            self._issues.append(SecurityIssue(
                category='Network Performance',
                title='High network jitter detected',
                description=f'Jitter: {jitter_result.jitter}ms (unstable connection)',
                risk_level=RiskLevel.MEDIUM,
                recommendation='High jitter affects real-time applications, check network stability',
                auto_fixable=False
            ))
            
        packet_loss = self._performance_results.get('packet_loss')
        if packet_loss:
            if packet_loss.loss_percentage > 5:
                self._issues.append(SecurityIssue(
                    category='Network Performance',
                    title='High packet loss detected',
                    description=f'Packet loss: {packet_loss.loss_percentage}% ({packet_loss.sent - packet_loss.received}/{packet_loss.sent} packets lost)',
                    risk_level=RiskLevel.HIGH,
                    recommendation='Significant packet loss - check cables, router, or contact ISP',
                    auto_fixable=False
                ))
            elif packet_loss.loss_percentage > 1:
                self._issues.append(SecurityIssue(
                    category='Network Performance',
                    title='Moderate packet loss detected',
                    description=f'Packet loss: {packet_loss.loss_percentage}%',
                    risk_level=RiskLevel.MEDIUM,
                    recommendation='Some packet loss detected - monitor for degradation',
                    auto_fixable=False
                ))
            
    def _calculate_score(self) -> None:
        deductions = {
            RiskLevel.LOW: 5,
            RiskLevel.MEDIUM: 10,
            RiskLevel.HIGH: 20,
            RiskLevel.CRITICAL: 30
        }
        
        for issue in self._issues:
            self._security_score -= deductions[issue.risk_level]
            
        self._security_score = max(0, self._security_score)
        
    @property
    def issues(self) -> List[SecurityIssue]:
        return self._issues
        
    @property
    def security_score(self) -> int:
        return self._security_score
        
    def get_critical_issues(self) -> List[SecurityIssue]:
        return [i for i in self._issues if i.risk_level == RiskLevel.CRITICAL]
        
    def get_high_risk_issues(self) -> List[SecurityIssue]:
        return [i for i in self._issues if i.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        
    def get_fixable_issues(self) -> List[SecurityIssue]:
        return [i for i in self._issues if i.auto_fixable]
        
    def get_summary(self) -> Dict:
        return {
            'security_score': self._security_score,
            'total_issues': len(self._issues),
            'critical_issues': len(self.get_critical_issues()),
            'high_risk_issues': len(self.get_high_risk_issues()),
            'fixable_issues': len(self.get_fixable_issues())
        }
