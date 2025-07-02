# Contributing to Sud0Hunt

Thank you for your interest in contributing to Sud0Hunt! We welcome contributions from the community.

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/Sud0-x/Sud0Hunt.git
   cd Sud0Hunt
   ```
3. **Create a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Types of Contributions

### Plugin Development
Create new scanning plugins to extend Sud0Hunt's capabilities:

- **Subdomain enumeration** improvements
- **New vulnerability checks**
- **Additional technology detection**
- **Custom reporting formats**

### Core Improvements
- Performance optimizations
- Bug fixes
- Code quality improvements
- Documentation updates

### Feature Requests
- New CLI options
- Enhanced reporting
- Better error handling
- UI/UX improvements

## 📝 Development Guidelines

### Code Style
- Follow **PEP 8** Python style guidelines
- Use **type hints** where appropriate
- Add **docstrings** to functions and classes
- Keep functions focused and modular

### Plugin Structure
When creating a new plugin, follow this template:

```python
"""
Your Plugin Name
Brief description of what it does
"""

import asyncio
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
PLUGIN_CLASS_NAME = "YourPluginName"

class YourPluginName:
    """Plugin for [description]"""
    
    async def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Main scan method"""
        logger.info(f"Starting [plugin name] scan on {target}")
        
        # Your scanning logic here
        results = []
        
        # Return results in standard format
        return results
```

### Testing
- Test your changes with various targets
- Ensure plugins handle errors gracefully
- Verify async operations work correctly
- Test with different timeout values

## 🔄 Submission Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the guidelines above

3. **Test thoroughly**:
   ```bash
   python cli.py -t example.com --your-new-feature
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add: brief description of your changes"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub

## 📋 Pull Request Guidelines

### Title Format
- `Add: New feature description`
- `Fix: Bug description`
- `Update: Component being updated`
- `Docs: Documentation changes`

### Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested with multiple targets
- [ ] Verified async functionality
- [ ] No errors in logging

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
```

## 🧩 Plugin Development Guide

### 1. Choose Your Plugin Type
- **Reconnaissance**: Information gathering (subdomains, ports, etc.)
- **Vulnerability**: Security issue detection
- **Detection**: Technology/service identification
- **Analysis**: Data processing and correlation

### 2. Plugin Requirements
- Must have `PLUGIN_CLASS_NAME` constant
- Must implement `async def scan()` method
- Should return list of dictionaries
- Must handle timeouts and errors gracefully

### 3. Result Format
```python
{
    'type': 'Finding Type',
    'severity': 'low|medium|high|critical',  # For vulnerabilities
    'target': 'specific target URL/IP',
    'description': 'Human readable description',
    'evidence': 'Supporting evidence',
    'confidence': 'low|medium|high'  # For detections
}
```

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Sud0Hunt version**
2. **Python version**
3. **Operating system**
4. **Command that caused the issue**
5. **Expected vs actual behavior**
6. **Error messages/logs**
7. **Steps to reproduce**

## 💡 Feature Requests

For new features, please provide:

1. **Clear description** of the feature
2. **Use case** and motivation
3. **Expected behavior**
4. **Possible implementation** ideas
5. **Priority level** (nice-to-have vs critical)

## 📖 Documentation

Help improve documentation by:

- Fixing typos and grammar
- Adding usage examples
- Improving plugin documentation
- Creating tutorials or guides
- Updating the README

## 🤝 Community Guidelines

- Be respectful and inclusive
- Help others in discussions
- Follow responsible disclosure for security issues
- Keep discussions focused and constructive
- Use clear, descriptive commit messages

## 📞 Getting Help

If you need help:

1. Check existing **issues** and **pull requests**
2. Read the **documentation** thoroughly
3. Create a **new issue** with detailed information
4. Contact maintainers: **sud0x.dev@proton.me**

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- Special thanks for major features

---

Thank you for contributing to Sud0Hunt! Together we can build the best bug bounty reconnaissance tool. 🎯
