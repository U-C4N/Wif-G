import json
import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportExporter:
    def __init__(self, output_dir: str = './reports', filename_prefix: str = 'wifg'):
        self._output_dir = output_dir
        self._filename_prefix = filename_prefix
        self._scan_data: Dict[str, Any] = {}

    def set_data(self, key: str, value: Any) -> None:
        self._scan_data[key] = value

    def set_network_info(self, ssid: Optional[str], signal: Optional[int],
                         local_ip: Optional[str], gateway: Optional[str],
                         interfaces: Dict, stats: Dict) -> None:
        self._scan_data['network'] = {
            'ssid': ssid,
            'signal_strength': signal,
            'local_ip': local_ip,
            'gateway': gateway,
            'interfaces': interfaces,
            'stats': stats,
        }

    def set_dns_info(self, dns_servers: List[Dict], warnings: List[str]) -> None:
        self._scan_data['dns'] = {
            'servers': dns_servers,
            'warnings': warnings,
        }

    def set_port_info(self, open_ports: List[Dict], dangerous_ports: List[Dict]) -> None:
        self._scan_data['ports'] = {
            'open_ports': open_ports,
            'dangerous_ports': dangerous_ports,
        }

    def set_performance_info(self, latency: List[Dict], jitter: Dict,
                              packet_loss: Dict, bandwidth: Dict) -> None:
        self._scan_data['performance'] = {
            'latency': latency,
            'jitter': jitter,
            'packet_loss': packet_loss,
            'bandwidth': bandwidth,
        }

    def set_security_info(self, score: int, issues: List[Dict], summary: Dict) -> None:
        self._scan_data['security'] = {
            'score': score,
            'issues': issues,
            'summary': summary,
        }

    def _ensure_output_dir(self) -> None:
        os.makedirs(self._output_dir, exist_ok=True)

    def _generate_filename(self, extension: str) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{self._filename_prefix}_{timestamp}.{extension}"

    def export_json(self) -> str:
        self._ensure_output_dir()
        filename = self._generate_filename('json')
        filepath = os.path.join(self._output_dir, filename)

        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'Wif-G Network Analyzer',
                'version': '1.0',
            },
            **self._scan_data,
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        logger.info("JSON report exported to %s", filepath)
        return filepath

    def export_html(self) -> str:
        self._ensure_output_dir()
        filename = self._generate_filename('html')
        filepath = os.path.join(self._output_dir, filename)

        html = self._build_html()

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info("HTML report exported to %s", filepath)
        return filepath

    def export_pdf(self) -> str:
        """Export scan results as a PDF report.

        Uses weasyprint to convert the HTML report to PDF.
        Falls back to a simple reportlab-based PDF if weasyprint
        is not available.
        """
        self._ensure_output_dir()
        filename = self._generate_filename('pdf')
        filepath = os.path.join(self._output_dir, filename)

        # Strategy 1: weasyprint (converts existing HTML to PDF)
        try:
            from weasyprint import HTML as WeasyprintHTML
            html_content = self._build_html_for_pdf()
            WeasyprintHTML(string=html_content).write_pdf(filepath)
            logger.info("PDF report exported via weasyprint to %s", filepath)
            return filepath
        except ImportError:
            logger.debug("weasyprint not available, trying reportlab")
        except Exception as e:
            logger.warning("weasyprint PDF generation failed: %s", e)

        # Strategy 2: reportlab (direct PDF generation)
        try:
            return self._export_pdf_reportlab(filepath)
        except ImportError:
            raise ImportError(
                "PDF export requires either 'weasyprint' or 'reportlab'. "
                "Install one with: pip install weasyprint  OR  pip install reportlab"
            )

    def _build_html_for_pdf(self) -> str:
        """Build HTML optimized for PDF conversion (white background, print-friendly)."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        network = self._scan_data.get('network', {})
        dns = self._scan_data.get('dns', {})
        ports = self._scan_data.get('ports', {})
        performance = self._scan_data.get('performance', {})
        security = self._scan_data.get('security', {})

        score = security.get('score', 'N/A')
        score_color = '#4CAF50' if isinstance(score, int) and score >= 80 else (
            '#FF9800' if isinstance(score, int) and score >= 60 else '#F44336'
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wif-G Network Analysis Report</title>
    <style>
        @page {{ size: A4; margin: 2cm; }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #ffffff; color: #333; padding: 20px; font-size: 11pt; }}
        .container {{ max-width: 100%; }}
        h1 {{ color: #1a237e; text-align: center; margin-bottom: 5px; font-size: 1.8em; }}
        .subtitle {{ text-align: center; color: #666; margin-bottom: 25px; font-size: 0.9em; }}
        .section {{ background: #f8f9fa; border-radius: 8px; padding: 15px; margin-bottom: 15px; border: 1px solid #dee2e6; page-break-inside: avoid; }}
        .section h2 {{ color: #1a237e; margin-bottom: 12px; border-bottom: 2px solid #1a237e; padding-bottom: 5px; font-size: 1.2em; }}
        .score-box {{ text-align: center; padding: 20px; }}
        .score {{ font-size: 3em; font-weight: bold; color: {score_color}; }}
        .score-label {{ font-size: 1em; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 10pt; }}
        th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #e8eaf6; color: #1a237e; font-weight: 600; }}
        .risk-critical {{ color: #F44336; font-weight: bold; }}
        .risk-high {{ color: #FF5722; font-weight: bold; }}
        .risk-medium {{ color: #FF9800; }}
        .risk-low {{ color: #4CAF50; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 4px 0; }}
        .info-label {{ color: #666; }}
        .info-value {{ color: #333; font-weight: 500; }}
        .warning {{ background: #fff3e0; border-left: 3px solid #FF9800; padding: 8px; margin: 5px 0; border-radius: 3px; font-size: 10pt; }}
        .issue {{ padding: 10px; margin: 6px 0; border-radius: 5px; border-left: 4px solid; font-size: 10pt; }}
        .issue-critical {{ border-color: #F44336; background: #ffebee; }}
        .issue-high {{ border-color: #FF5722; background: #fbe9e7; }}
        .issue-medium {{ border-color: #FF9800; background: #fff3e0; }}
        .issue-low {{ border-color: #4CAF50; background: #e8f5e9; }}
        footer {{ text-align: center; color: #999; margin-top: 20px; padding: 10px; font-size: 9pt; border-top: 1px solid #dee2e6; }}
        .header-bar {{ background: #1a237e; color: white; padding: 15px; text-align: center; border-radius: 8px; margin-bottom: 20px; }}
        .header-bar h1 {{ color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <h1>Wif-G Network Analysis Report</h1>
            <p class="subtitle" style="color: #ccc;">Generated: {timestamp}</p>
        </div>
"""
        # Security Score
        html += f"""
        <div class="section">
            <div class="score-box">
                <div class="score">{score}/100</div>
                <div class="score-label">Security Score</div>
            </div>
        </div>
"""
        # Network Information
        if network:
            html += """
        <div class="section">
            <h2>Network Information</h2>
"""
            for label, key in [('SSID', 'ssid'), ('Signal Strength', 'signal_strength'),
                               ('Local IP', 'local_ip'), ('Gateway', 'gateway')]:
                val = network.get(key, 'N/A')
                if key == 'signal_strength' and val is not None:
                    val = f"{val} dBm"
                html += f'            <div class="info-row"><span class="info-label">{label}</span><span class="info-value">{val}</span></div>\n'
            html += "        </div>\n"

        # DNS Information
        if dns:
            html += """
        <div class="section">
            <h2>DNS Analysis</h2>
            <table>
                <tr><th>Server</th><th>Provider</th><th>Response Time</th><th>Type</th></tr>
"""
            for server in dns.get('servers', []):
                rt = f"{server.get('response_time', 'N/A')}ms" if server.get('response_time') else 'N/A'
                stype = 'Public' if server.get('is_public_resolver') else 'ISP/Private'
                html += f"                <tr><td>{server.get('ip', 'N/A')}</td><td>{server.get('provider', 'N/A')}</td><td>{rt}</td><td>{stype}</td></tr>\n"
            html += "            </table>\n"
            for w in dns.get('warnings', []):
                html += f'            <div class="warning">{w}</div>\n'
            html += "        </div>\n"

        # Open Ports
        if ports and ports.get('open_ports'):
            html += """
        <div class="section">
            <h2>Port Scan Results</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Risk Level</th></tr>
"""
            for port in ports['open_ports']:
                risk_class = f"risk-{port.get('risk_level', 'medium')}"
                html += f"                <tr><td>{port.get('port', 'N/A')}</td><td>{port.get('service', 'N/A')}</td><td class=\"{risk_class}\">{port.get('risk_level', 'N/A').upper()}</td></tr>\n"
            html += "            </table>\n        </div>\n"

        # Performance
        if performance:
            html += """
        <div class="section">
            <h2>Performance Results</h2>
"""
            if performance.get('latency'):
                html += "            <table><tr><th>Target</th><th>Avg</th><th>Min</th><th>Max</th></tr>\n"
                for l in performance['latency']:
                    html += f"                <tr><td>{l.get('target','N/A')}</td><td>{l.get('avg_latency','N/A')}ms</td><td>{l.get('min_latency','N/A')}ms</td><td>{l.get('max_latency','N/A')}ms</td></tr>\n"
                html += "            </table>\n"

            jitter = performance.get('jitter', {})
            if jitter:
                html += f'            <div class="info-row"><span class="info-label">Jitter</span><span class="info-value">{jitter.get("jitter", "N/A")}ms</span></div>\n'

            pl = performance.get('packet_loss', {})
            if pl:
                html += f'            <div class="info-row"><span class="info-label">Packet Loss</span><span class="info-value">{pl.get("loss_percentage", "N/A")}%</span></div>\n'

            bw = performance.get('bandwidth', {})
            if bw:
                html += f'            <div class="info-row"><span class="info-label">Bandwidth</span><span class="info-value">{bw.get("download_speed_mbps", "N/A")} Mbps</span></div>\n'

            html += "        </div>\n"

        # Security Issues
        if security and security.get('issues'):
            html += """
        <div class="section">
            <h2>Security Issues</h2>
"""
            for issue in security['issues']:
                risk = issue.get('risk_level', 'medium').lower()
                html += f"""            <div class="issue issue-{risk}">
                <strong>[{risk.upper()}] {issue.get('title', 'N/A')}</strong><br>
                <span style="color:#666">{issue.get('category', '')}</span><br>
                {issue.get('description', '')}<br>
                <span style="color:#4CAF50"><strong>Recommendation:</strong> {issue.get('recommendation', '')}</span>
            </div>
"""
            html += "        </div>\n"

        html += """
        <footer>
            Generated by Wif-G Network Analyzer v1.0
        </footer>
    </div>
</body>
</html>"""
        return html

    def _export_pdf_reportlab(self, filepath: str) -> str:
        """Generate a PDF report using reportlab."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
            TableStyle, HRFlowable,
        )
        from reportlab.lib import colors

        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            leftMargin=2 * cm, rightMargin=2 * cm,
            topMargin=2 * cm, bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Title'],
            textColor=HexColor('#1a237e'), fontSize=22, spaceAfter=6,
        )
        heading_style = ParagraphStyle(
            'CustomHeading', parent=styles['Heading2'],
            textColor=HexColor('#1a237e'), fontSize=14, spaceBefore=12, spaceAfter=6,
        )
        normal_style = styles['Normal']
        small_style = ParagraphStyle(
            'Small', parent=normal_style, fontSize=9, textColor=HexColor('#666666'),
        )

        elements = []
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Title
        elements.append(Paragraph("Wif-G Network Analysis Report", title_style))
        elements.append(Paragraph(f"Generated: {timestamp}", small_style))
        elements.append(Spacer(1, 12))

        security = self._scan_data.get('security', {})
        score = security.get('score', 'N/A')

        # Security Score
        if isinstance(score, int):
            if score >= 80:
                sc = '#4CAF50'
            elif score >= 60:
                sc = '#FF9800'
            else:
                sc = '#F44336'
            score_style = ParagraphStyle(
                'Score', parent=styles['Title'],
                textColor=HexColor(sc), fontSize=36, alignment=1,
            )
            elements.append(Paragraph(f"{score}/100", score_style))
            elements.append(Paragraph("Security Score", ParagraphStyle(
                'ScoreLabel', parent=normal_style, alignment=1, textColor=HexColor('#666666'),
            )))
            elements.append(Spacer(1, 12))

        elements.append(HRFlowable(width="100%", color=HexColor('#1a237e')))
        elements.append(Spacer(1, 6))

        # Network
        network = self._scan_data.get('network', {})
        if network:
            elements.append(Paragraph("Network Information", heading_style))
            net_data = [
                ['SSID', str(network.get('ssid', 'N/A'))],
                ['Signal', f"{network.get('signal_strength', 'N/A')} dBm" if network.get('signal_strength') else 'N/A'],
                ['Local IP', str(network.get('local_ip', 'N/A'))],
                ['Gateway', str(network.get('gateway', 'N/A'))],
            ]
            t = RLTable(net_data, colWidths=[4 * cm, 12 * cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#e8eaf6')),
                ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#1a237e')),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 10))

        # DNS
        dns = self._scan_data.get('dns', {})
        if dns and dns.get('servers'):
            elements.append(Paragraph("DNS Analysis", heading_style))
            dns_data = [['Server', 'Provider', 'Response Time', 'Type']]
            for server in dns['servers']:
                rt = f"{server.get('response_time', 'N/A')}ms" if server.get('response_time') else 'N/A'
                stype = 'Public' if server.get('is_public_resolver') else 'ISP/Private'
                dns_data.append([server.get('ip', 'N/A'), server.get('provider', 'N/A'), rt, stype])
            t = RLTable(dns_data, colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e8eaf6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#1a237e')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 10))

        # Ports
        ports = self._scan_data.get('ports', {})
        if ports and ports.get('open_ports'):
            elements.append(Paragraph("Port Scan Results", heading_style))
            port_data = [['Port', 'Service', 'Risk Level']]
            risk_colors = {
                'low': HexColor('#4CAF50'),
                'medium': HexColor('#FF9800'),
                'high': HexColor('#FF5722'),
                'critical': HexColor('#F44336'),
            }
            for p in ports['open_ports']:
                port_data.append([
                    str(p.get('port', 'N/A')),
                    p.get('service', 'N/A'),
                    p.get('risk_level', 'N/A').upper(),
                ])
            t = RLTable(port_data, colWidths=[3 * cm, 6 * cm, 7 * cm])
            style_commands = [
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e8eaf6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#1a237e')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ]
            for idx, p in enumerate(ports['open_ports'], 1):
                risk = p.get('risk_level', 'medium').lower()
                if risk in risk_colors:
                    style_commands.append(('TEXTCOLOR', (2, idx), (2, idx), risk_colors[risk]))
            t.setStyle(TableStyle(style_commands))
            elements.append(t)
            elements.append(Spacer(1, 10))

        # Performance
        performance = self._scan_data.get('performance', {})
        if performance:
            elements.append(Paragraph("Performance Results", heading_style))
            if performance.get('latency'):
                perf_data = [['Target', 'Avg', 'Min', 'Max']]
                for l in performance['latency']:
                    perf_data.append([
                        l.get('target', 'N/A'),
                        f"{l.get('avg_latency', 'N/A')}ms",
                        f"{l.get('min_latency', 'N/A')}ms",
                        f"{l.get('max_latency', 'N/A')}ms",
                    ])
                t = RLTable(perf_data, colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e8eaf6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#1a237e')),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
                ]))
                elements.append(t)

            summary_parts = []
            jitter = performance.get('jitter', {})
            if jitter and jitter.get('jitter') is not None:
                summary_parts.append(f"Jitter: {jitter['jitter']}ms")
            pl = performance.get('packet_loss', {})
            if pl:
                summary_parts.append(f"Packet Loss: {pl.get('loss_percentage', 'N/A')}%")
            bw = performance.get('bandwidth', {})
            if bw and bw.get('download_speed_mbps'):
                summary_parts.append(f"Bandwidth: {bw['download_speed_mbps']:.2f} Mbps")
            if summary_parts:
                elements.append(Spacer(1, 4))
                elements.append(Paragraph("  |  ".join(summary_parts), normal_style))
            elements.append(Spacer(1, 10))

        # Security Issues
        if security and security.get('issues'):
            elements.append(Paragraph("Security Issues", heading_style))
            for issue in security['issues']:
                risk = issue.get('risk_level', 'MEDIUM').upper()
                risk_color_map = {
                    'LOW': '#4CAF50', 'MEDIUM': '#FF9800',
                    'HIGH': '#FF5722', 'CRITICAL': '#F44336',
                }
                rc = risk_color_map.get(risk, '#333')
                text = (
                    f'<font color="{rc}"><b>[{risk}]</b></font> '
                    f'{issue.get("title", "N/A")}<br/>'
                    f'<font color="#666">{issue.get("category", "")}</font><br/>'
                    f'{issue.get("description", "")}<br/>'
                    f'<font color="#4CAF50"><b>Recommendation:</b> {issue.get("recommendation", "")}</font>'
                )
                elements.append(Paragraph(text, normal_style))
                elements.append(Spacer(1, 6))

        # Footer
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", color=HexColor('#dee2e6')))
        elements.append(Paragraph(
            "Generated by Wif-G Network Analyzer v1.0",
            ParagraphStyle('Footer', parent=normal_style, alignment=1,
                           textColor=HexColor('#999999'), fontSize=8),
        ))

        doc.build(elements)
        logger.info("PDF report exported via reportlab to %s", filepath)
        return filepath

    def _build_html(self) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        network = self._scan_data.get('network', {})
        dns = self._scan_data.get('dns', {})
        ports = self._scan_data.get('ports', {})
        performance = self._scan_data.get('performance', {})
        security = self._scan_data.get('security', {})

        score = security.get('score', 'N/A')
        score_color = '#4CAF50' if isinstance(score, int) and score >= 80 else (
            '#FF9800' if isinstance(score, int) and score >= 60 else '#F44336'
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wif-G Network Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; text-align: center; margin-bottom: 5px; font-size: 2em; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .section {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #0f3460; }}
        .section h2 {{ color: #00d4ff; margin-bottom: 15px; border-bottom: 1px solid #0f3460; padding-bottom: 8px; }}
        .score-box {{ text-align: center; padding: 30px; }}
        .score {{ font-size: 4em; font-weight: bold; color: {score_color}; }}
        .score-label {{ font-size: 1.2em; color: #888; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #0f3460; }}
        th {{ color: #00d4ff; font-weight: 600; }}
        .risk-critical {{ color: #F44336; font-weight: bold; }}
        .risk-high {{ color: #FF5722; font-weight: bold; }}
        .risk-medium {{ color: #FF9800; }}
        .risk-low {{ color: #4CAF50; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 5px 0; }}
        .info-label {{ color: #888; }}
        .info-value {{ color: #e0e0e0; }}
        .warning {{ background: #332200; border-left: 3px solid #FF9800; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .issue {{ padding: 12px; margin: 8px 0; border-radius: 5px; border-left: 4px solid; }}
        .issue-critical {{ border-color: #F44336; background: #2d1515; }}
        .issue-high {{ border-color: #FF5722; background: #2d1b15; }}
        .issue-medium {{ border-color: #FF9800; background: #2d2515; }}
        .issue-low {{ border-color: #4CAF50; background: #152d15; }}
        footer {{ text-align: center; color: #555; margin-top: 30px; padding: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Wif-G Network Analysis Report</h1>
        <p class="subtitle">Generated: {timestamp}</p>
"""

        # Security Score
        html += f"""
        <div class="section">
            <div class="score-box">
                <div class="score">{score}/100</div>
                <div class="score-label">Security Score</div>
            </div>
        </div>
"""

        # Network Information
        if network:
            html += """
        <div class="section">
            <h2>Network Information</h2>
"""
            for label, key in [('SSID', 'ssid'), ('Signal Strength', 'signal_strength'),
                               ('Local IP', 'local_ip'), ('Gateway', 'gateway')]:
                val = network.get(key, 'N/A')
                if key == 'signal_strength' and val is not None:
                    val = f"{val} dBm"
                html += f'            <div class="info-row"><span class="info-label">{label}</span><span class="info-value">{val}</span></div>\n'
            html += "        </div>\n"

        # DNS Information
        if dns:
            html += """
        <div class="section">
            <h2>DNS Analysis</h2>
            <table>
                <tr><th>Server</th><th>Provider</th><th>Response Time</th><th>Type</th></tr>
"""
            for server in dns.get('servers', []):
                rt = f"{server.get('response_time', 'N/A')}ms" if server.get('response_time') else 'N/A'
                stype = 'Public' if server.get('is_public_resolver') else 'ISP/Private'
                html += f"                <tr><td>{server.get('ip', 'N/A')}</td><td>{server.get('provider', 'N/A')}</td><td>{rt}</td><td>{stype}</td></tr>\n"
            html += "            </table>\n"
            for w in dns.get('warnings', []):
                html += f'            <div class="warning">{w}</div>\n'
            html += "        </div>\n"

        # Open Ports
        if ports and ports.get('open_ports'):
            html += """
        <div class="section">
            <h2>Port Scan Results</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Risk Level</th></tr>
"""
            for port in ports['open_ports']:
                risk_class = f"risk-{port.get('risk_level', 'medium')}"
                html += f"                <tr><td>{port.get('port', 'N/A')}</td><td>{port.get('service', 'N/A')}</td><td class=\"{risk_class}\">{port.get('risk_level', 'N/A').upper()}</td></tr>\n"
            html += "            </table>\n        </div>\n"

        # Performance
        if performance:
            html += """
        <div class="section">
            <h2>Performance Results</h2>
"""
            if performance.get('latency'):
                html += "            <h3 style='color:#888;margin:10px 0'>Latency</h3>\n"
                html += "            <table><tr><th>Target</th><th>Avg</th><th>Min</th><th>Max</th></tr>\n"
                for l in performance['latency']:
                    html += f"                <tr><td>{l.get('target','N/A')}</td><td>{l.get('avg_latency','N/A')}ms</td><td>{l.get('min_latency','N/A')}ms</td><td>{l.get('max_latency','N/A')}ms</td></tr>\n"
                html += "            </table>\n"

            jitter = performance.get('jitter', {})
            if jitter:
                html += f'            <div class="info-row"><span class="info-label">Jitter</span><span class="info-value">{jitter.get("jitter", "N/A")}ms</span></div>\n'

            pl = performance.get('packet_loss', {})
            if pl:
                html += f'            <div class="info-row"><span class="info-label">Packet Loss</span><span class="info-value">{pl.get("loss_percentage", "N/A")}%</span></div>\n'

            bw = performance.get('bandwidth', {})
            if bw:
                html += f'            <div class="info-row"><span class="info-label">Bandwidth</span><span class="info-value">{bw.get("download_speed_mbps", "N/A")} Mbps</span></div>\n'

            html += "        </div>\n"

        # Security Issues
        if security and security.get('issues'):
            html += """
        <div class="section">
            <h2>Security Issues</h2>
"""
            for issue in security['issues']:
                risk = issue.get('risk_level', 'medium').lower()
                html += f"""            <div class="issue issue-{risk}">
                <strong>[{risk.upper()}] {issue.get('title', 'N/A')}</strong><br>
                <span style="color:#888">{issue.get('category', '')}</span><br>
                {issue.get('description', '')}<br>
                <span style="color:#4CAF50">Recommendation: {issue.get('recommendation', '')}</span>
            </div>
"""
            html += "        </div>\n"

        html += """
        <footer>
            Generated by Wif-G Network Analyzer v1.0
        </footer>
    </div>
</body>
</html>"""

        return html
