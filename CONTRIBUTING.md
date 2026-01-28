# Contributing to Wif-G

Thank you for your interest! This is a guide for anyone who wants to contribute to the Wif-G project.

## 🚀 Ways to Contribute

### 1. Bug Reports
- Open a new issue on the [Issues](https://github.com/U-C4N/Wif-G/issues) page
- Provide a clear and detailed title
- Include steps to reproduce the bug
- Explain the expected and actual behaviors
- Share your system information (OS, Python version)

### 2. Feature Requests
- Use the `[Feature Request]` label when opening an issue
- Give a detailed description of the feature
- Specify use cases
- Add code samples or mockups if possible

### 3. Code Contributions

#### Setting Up Development Environment

```bash
# Fork and clone the project
git clone https://github.com/YOUR_GITHUB_USERNAME/Wif-G.git
cd Wif-G

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

#### Branch Strategy

```bash
# For a new feature
git checkout -b feature/amazing-feature

# For a bug fix
git checkout -b fix/issue-123

# For documentation
git checkout -b docs/update-readme
```

#### Code Standards

1. **Python Style Guide (PEP 8)**
   ```bash
   # Use Black for code formatting
   black src/
   
   # Use Flake8 for linting
   flake8 src/
   ```

2. **Type Hints Usage**
   ```python
   def scan_port(self, port: int) -> Optional[PortInfo]:
       """Performs a port scan."""
       pass
   ```

3. **Docstring Standard**
   ```python
   def analyze_security(self) -> Dict[str, Any]:
       """
       Performs security analysis.
       
       Returns:
           Dict[str, Any]: Security report
           
       Raises:
           SecurityError: If analysis fails
       """
       pass
   ```

4. **Test Coverage**
   ```bash
   # Run the tests
   pytest tests/
   
   # Coverage report
   pytest --cov=src tests/
   ```

#### Commit Messages

Please use the Conventional Commits format:

```
type(scope): subject

body

footer
```

**Examples:**
```bash
feat(port-scanner): add IPv6 support

- Added IPv6 address detection
- Updated port scanning logic
- Added unit tests

Closes #123

fix(dns): resolve timeout issue on slow networks

perf(optimizer): improve TCP optimization speed

docs(readme): add installation troubleshooting section
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code formatting (no logic change)
- `refactor`: Refactoring code
- `perf`: Performance improvement
- `test`: Adding/fixing tests
- `chore`: Build, dependency updates

#### Pull Request Process

1. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

2. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```

3. **Open the Pull Request**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Write a detailed explanation of your changes
   - Link relevant issues

4. **PR Template**
   ```markdown
   ## Description
   What changed in this PR?
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   How was this tested?
   
   ## Checklist
   - [ ] Code complies with PEP 8
   - [ ] Tests added/updated
   - [ ] Documentation updated
   - [ ] Commit messages follow the standard
   ```

### 4. Documentation Contributions

- Update the README
- Improve code comments
- Add usage examples
- Contribute to API documentation

### 5. Review & Testing

- Review other PRs
- Verify bug reports
- Test on different operating systems

## 📋 Development Rules

### Code Quality
- Each function should do one thing
- Maximum function length: 50 lines
- Maximum module length: 500 lines
- Cyclomatic complexity: < 10

### Security
- Always validate user input
- Never log sensitive info
- Beware of SQL injection, XSS, and other vulnerabilities
- Regularly update dependencies

### Performance
- Prefer using async/await
- Avoid unnecessary loops
- Prevent memory leaks
- Properly clean up resources (close, cleanup)

### Error Handling
```python
try:
    result = risky_operation()
except SpecificError as e:
    logger.error(f"Operation failed: {e}")
    # Graceful degradation
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise
```

## 🧪 Writing Tests

### Unit Test Example
```python
import pytest
from src.network_analyzer import NetworkScanner

def test_network_scanner_initialization():
    scanner = NetworkScanner()
    assert scanner is not None
    assert scanner.interfaces == {}

def test_scan_interfaces():
    scanner = NetworkScanner()
    scanner.scan()
    assert len(scanner.interfaces) > 0

@pytest.mark.parametrize("port,expected", [
    (80, "HTTP"),
    (443, "HTTPS"),
    (22, "SSH"),
])
def test_port_service_mapping(port, expected):
    from src.network_analyzer import PortScanner
    scanner = PortScanner()
    service = scanner.COMMON_PORTS[port][0]
    assert service == expected
```

## 🎨 Style Guide

### Import Order
```python
# Standard library
import os
import sys
from typing import Dict, List

# Third-party
import psutil
import netifaces

# Local
from src.network_analyzer import NetworkScanner
```

### Naming Conventions
- Classes: `PascalCase` (e.g., PortScanner)
- Functions/Methods: `snake_case` (e.g., scan_network)
- Constants: `UPPER_SNAKE_CASE` (e.g., MAX_WORKERS)
- Private: `_leading_underscore` (e.g., _internal_method)

## 🐛 Bug Fix Workflow

1. Reproduce the issue
2. Write a failing test case
3. Fix the bug
4. Make sure the test passes
5. Add a regression test

## 📦 Release Process

1. Bump the version (semantic versioning)
2. Update CHANGELOG.md
3. Create a tag (e.g., `v1.0.0`)
4. Publish GitHub Release notes
5. (In the future) Upload to PyPI

## 💬 Communication

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions
- **Email**: For private topics

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thanks

Every contribution matters! From small fixes to major features, everything moves the project forward.

**Happy Coding! 🚀**
