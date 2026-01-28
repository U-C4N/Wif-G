# Security Policy

## Supported Versions

Currently supported versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. Do Not Open a Public Issue
**Please do not report security vulnerabilities through public GitHub issues.**

### 2. Report Privately
Send your report to:
- **GitHub Security Advisories**: Use the [private vulnerability reporting](https://github.com/U-C4N/Wif-G/security/advisories) feature
- **Email**: Create a private disclosure (recommended for critical issues)

### 3. Include Details
Please provide:
- Type of vulnerability
- Full path of source file(s) related to the issue
- Location of affected source code (tag/branch/commit)
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if available)
- Impact assessment
- Suggested fix (if any)

### 4. Response Timeline
- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Critical issues within 30 days

## Security Best Practices

### For Users

1. **Run with Appropriate Privileges**
   ```bash
   # Only use sudo when necessary
   sudo python3 main.py
   ```

2. **Keep Dependencies Updated**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

3. **Verify Source**
   ```bash
   # Always clone from official repository
   git clone https://github.com/U-C4N/Wif-G.git
   ```

4. **Review Permissions**
   - Port scanning may require firewall exceptions
   - Network modifications need admin rights
   - Be cautious with optimization features

### For Developers

1. **Code Review**
   - All PRs require review before merge
   - Security-sensitive changes need extra scrutiny

2. **Dependency Scanning**
   ```bash
   # Check for known vulnerabilities
   pip install safety
   safety check
   ```

3. **Static Analysis**
   ```bash
   # Security linting
   bandit -r src/
   ```

4. **Input Validation**
   - Always validate user inputs
   - Sanitize command-line arguments
   - Prevent injection attacks

## Known Security Considerations

### Network Scanning
- Port scanning may trigger IDS/IPS alerts
- Some networks block or rate-limit scanning
- Ensure you have permission to scan the network

### Privilege Escalation
- Tool requires sudo for full functionality
- Minimal privilege principle applied where possible
- Root operations clearly documented

### Data Handling
- No sensitive data is stored permanently
- Network credentials are never collected
- Temporary files cleaned up on exit

## Responsible Disclosure

We believe in responsible disclosure:
1. Report the vulnerability privately
2. Allow reasonable time for fix development
3. Coordinate public disclosure timing
4. Credit researchers appropriately (if desired)

## Security Updates

Security patches are released as:
- **Critical**: Immediate patch release
- **High**: Within 7 days
- **Medium**: Next minor version
- **Low**: Next major version

## Acknowledgments

We appreciate security researchers who help keep Wif-G safe:
- [List will be updated as reports come in]

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

**Last Updated**: 2025-01-28
