# 📦 Sud0Hunt

## 🧠 What this tool does:
Sud0Hunt is an **advanced automated bug bounty reconnaissance & vulnerability hunting toolkit** built in Python.

It helps security researchers and bug bounty hunters by:
- Finding subdomains of a target domain
- Scanning open ports & grabbing banners
- Detecting known vulnerabilities automatically
- Identifying technologies & frameworks
- Creating detailed JSON & HTML reports
- Running everything from a modern CLI interface with colors & summary tables

## ✨ Features

- **🌐 Subdomain Enumeration**: DNS brute force + Certificate Transparency logs (crt.sh)
- **🔌 Port Scanning**: Asynchronous port scanning with banner grabbing
- **🚨 Vulnerability Detection**: SQL injection, XSS, directory traversal, exposed files
- **🛠️ Technology Detection**: CMS, frameworks, server software identification
- **📊 Beautiful Reports**: JSON and HTML reports with modern styling
- **⚡ Fast & Concurrent**: Multi-threaded/async operations for speed
- **🎨 Modern CLI**: Rich terminal interface with progress bars and colored output

## 🚀 Installation

```bash
git clone https://github.com/Sud0-x/Sud0Hunt.git
cd Sud0Hunt

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt

chmod +x cli.py
```

## 🎯 Usage

### Basic Usage
```bash
# Full scan on a single target
python cli.py -t example.com --full-scan

# Multiple targets
python cli.py -t example.com,test.com --full-scan

# Specific scan types
python cli.py -t example.com --subdomain-enum --port-scan
python cli.py -t example.com --vuln-scan --tech-detect
```

### Advanced Options
```bash
# Custom output formats
python cli.py -t example.com --full-scan -o json,html

# Performance tuning
python cli.py -t example.com --full-scan --threads 50 --timeout 15

# Silent mode (no terminal output)
python cli.py -t example.com --full-scan --no-terminal
```

### CLI Options

```
-t, --targets           Comma-separated list of target domains (required)

Scan Options:
  --full-scan           Run all scan modules
  --subdomain-enum      Run subdomain enumeration only
  --port-scan           Run port scanning only  
  --vuln-scan           Run vulnerability scanning only
  --tech-detect         Run technology detection only

Output Options:
  -o, --output          Output formats: json,html (default: json)
  --no-terminal         Skip terminal output, save to file only

Performance Options:
  --threads             Number of concurrent threads (default: 20)
  --timeout             Request timeout in seconds (default: 10)

Info Options:
  --version             Show version
  --help                Show help message
```

## 📊 Example Output

```bash
$ python cli.py -t example.com --full-scan

███████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔════╝██║   ██║██╔══██╗██╔═████╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████╗██║   ██║██║  ██║██║██╔██║███████║██║   ██║██╔██╗ ██║   ██║   
╚════██║██║   ██║██║  ██║████╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   
███████║╚██████╔╝██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   

    Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter
    Author: sud0x.dev@proton.me | License: MIT

🎯 Starting scan on 1 target(s)
Targets: example.com
Scans: subdomain_enum, port_scan, vuln_scan, tech_detect

✅ Scan completed in 45.32 seconds

                           🎯 Scan Summary
┏━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
║ Category      ║ Count ║ Details                                         ║
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Subdomains    │    15 │ 12 alive                                       │
│ Open Ports    │     8 │ Across 3 hosts                                 │
│ Vulnerabilities│     3 │ 0 critical, 1 high                            │
│ Technologies  │     5 │ 4 unique                                        │
└───────────────┴───────┴─────────────────────────────────────────────────────┘

📄 Reports saved to:
  • JSON: reports/scan_results.json
  • HTML: reports/scan_results.html
```

## 🔧 Architecture

Sud0Hunt follows a modular plugin-based architecture:

```
Sud0Hunt/
├── cli.py                 # Main CLI interface
├── core/                  # Core scanning engine
│   ├── scanner.py         # Coordinates scanning tasks
│   ├── plugin_manager.py  # Loads and manages plugins
│   └── utils.py           # Helper functions & HTML report generation
├── plugins/               # Scanning modules
│   ├── subdomain_enum.py  # Subdomain enumeration
│   ├── port_scan.py       # Port scanning & banner grabbing
│   ├── vuln_scan.py       # Vulnerability detection
│   └── technology_detect.py # Technology identification
└── reports/               # Output directory for results
```

## 🛠️ Adding Custom Plugins

Sud0Hunt supports custom plugins. Create a new file in `plugins/` directory:

```python
# plugins/my_plugin.py
PLUGIN_CLASS_NAME = "MyPlugin"

class MyPlugin:
    async def scan(self, target: str, timeout: int = 10, **kwargs):
        # Your custom scanning logic here
        return [
            {
                'type': 'Custom Finding',
                'target': target,
                'description': 'Custom vulnerability found',
                'severity': 'medium'
            }
        ]
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒 Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 📧 Contact

- **Author**: sud0x.dev@proton.me
- **GitHub**: [Sud0Hunt Repository](https://github.com/Sud0-x/Sud0Hunt)

---

*Built with ❤️ for the bug bounty community*
