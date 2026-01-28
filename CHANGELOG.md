# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Windows support with PowerShell integration
- macOS support
- Web dashboard
- Export reports (JSON, CSV, PDF)
- IPv6 support

## [1.0.0] - 2025-01-28

### Added
- Initial release
- Network scanner with WiFi detection
- Port scanner with 200 concurrent threads
- DNS analyzer with public resolver detection
- Performance testing suite (latency, jitter, packet loss, bandwidth)
- Security analyzer with 0-100 scoring system
- Network optimizer with automatic DNS switching
- Colorful CLI interface
- Async operations for better performance
- Comprehensive documentation

### Features

#### Network Scanner
- WiFi SSID and signal strength detection
- Network interface enumeration
- Gateway detection
- Real-time network statistics
- Active connection monitoring

#### Port Scanner
- 47 common ports coverage
- Risk level classification (Critical/High/Medium/Low)
- Dangerous port detection (Telnet, SMB, RDP, etc.)
- Service identification
- Concurrent scanning (200 threads)

#### DNS Analyzer
- Current DNS server detection
- Response time measurement
- Public vs ISP DNS identification
- Security warnings
- Smart recommendations

#### Performance Tester
- Multi-target latency testing
- Jitter analysis (20 samples)
- Packet loss detection (50 probes)
- Bandwidth estimation
- Async/await implementation

#### Security Analyzer
- Comprehensive security scoring (0-100)
- Multi-category risk assessment
- Port security analysis
- DNS security checks
- Network health monitoring
- Actionable recommendations

#### Network Optimizer
- Automatic DNS optimization
- TCP buffer optimization
- DNS cache clearing
- Root/non-root support
- Manual recommendation system

### Technical
- Python 3.11+ support
- Cross-platform support (Linux focus)
- Modular architecture
- Clean code structure
- Comprehensive error handling

### Documentation
- Detailed README with examples
- Architecture diagram (Mermaid)
- Module documentation
- Contributing guidelines
- MIT License

## [0.1.0] - 2025-01-15

### Added
- Project initialization
- Basic structure
- Core modules skeleton

---

## Version History

- **1.0.0**: Initial stable release with full feature set
- **0.1.0**: Project foundation

## Links

- [Homepage](https://github.com/U-C4N/Wif-G)
- [Issue Tracker](https://github.com/U-C4N/Wif-G/issues)
- [Releases](https://github.com/U-C4N/Wif-G/releases)
