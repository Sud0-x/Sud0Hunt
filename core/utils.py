"""
Utility functions for Sud0Hunt
"""

import logging
import re
import socket
from typing import List, Dict, Any
from urllib.parse import urlparse

def setup_logging(level: int = logging.INFO) -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('reports/sud0hunt.log'),
            logging.StreamHandler()
        ]
    )

def validate_targets(targets: List[str]) -> List[str]:
    """Validate and normalize target domains"""
    valid_targets = []
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    for target in targets:
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        
        # Remove port if present
        if ':' in target:
            target = target.split(':')[0]
        
        # Validate domain format
        if domain_pattern.match(target):
            valid_targets.append(target)
        else:
            logging.warning(f"Invalid domain format: {target}")
    
    return valid_targets

def is_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a port is open on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def generate_html_report(results: Dict[str, Any]) -> str:
    """Generate HTML report from scan results"""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sud0Hunt Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        .scan-info {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }
        .scan-info h2 {
            color: #495057;
            margin-top: 0;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h3 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            font-size: 1.5em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .severity-critical {
            background: #e74c3c !important;
            color: white;
            font-weight: bold;
        }
        .severity-high {
            background: #f39c12 !important;
            color: white;
            font-weight: bold;
        }
        .severity-medium {
            background: #f1c40f !important;
            color: black;
            font-weight: bold;
        }
        .severity-low {
            background: #27ae60 !important;
            color: white;
            font-weight: bold;
        }
        .status-alive {
            color: #27ae60;
            font-weight: bold;
        }
        .status-dead {
            color: #e74c3c;
            font-weight: bold;
        }
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Sud0Hunt Scan Report</h1>
            <p>Advanced Bug Bounty Reconnaissance Results</p>
        </div>
        
        <div class="scan-info">
            <h2>📊 Scan Information</h2>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <p><strong>Targets:</strong> {targets}</p>
            <p><strong>Scan Types:</strong> {scan_types}</p>
            <p><strong>Total Time:</strong> {total_time:.2f} seconds</p>
        </div>
        
        <div class="content">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{subdomain_count}</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{port_count}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_count}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{tech_count}</div>
                    <div class="stat-label">Technologies</div>
                </div>
            </div>
            
            {subdomains_section}
            {ports_section}
            {vulnerabilities_section}
            {technologies_section}
        </div>
        
        <div class="footer">
            <p>Generated by Sud0Hunt - Advanced Bug Bounty Reconnaissance Tool</p>
            <p>Contact: sud0x.dev@proton.me</p>
        </div>
    </div>
</body>
</html>
    """
    
    # Build sections
    sections = {
        'subdomains_section': build_subdomains_section(results.get('subdomains', [])),
        'ports_section': build_ports_section(results.get('ports', [])),
        'vulnerabilities_section': build_vulnerabilities_section(results.get('vulnerabilities', [])),
        'technologies_section': build_technologies_section(results.get('technologies', []))
    }
    
    # Fill template
    scan_info = results.get('scan_info', {})
    html_content = html_template.format(
        timestamp=scan_info.get('timestamp', 'N/A'),
        targets=', '.join(scan_info.get('targets', [])),
        scan_types=', '.join(scan_info.get('scan_types', [])),
        total_time=scan_info.get('total_time', 0),
        subdomain_count=len(results.get('subdomains', [])),
        port_count=len(results.get('ports', [])),
        vuln_count=len(results.get('vulnerabilities', [])),
        tech_count=len(results.get('technologies', [])),
        **sections
    )
    
    return html_content

def build_subdomains_section(subdomains: List[Dict[str, Any]]) -> str:
    """Build HTML section for subdomains"""
    if not subdomains:
        return '<div class="section"><h3>🌐 Subdomains</h3><p>No subdomains found.</p></div>'
    
    rows = []
    for subdomain in subdomains[:50]:  # Limit to first 50
        status = 'alive' if subdomain.get('alive') else 'dead'
        status_text = '✅ Alive' if subdomain.get('alive') else '❌ Dead'
        rows.append(f"""
        <tr>
            <td>{subdomain.get('domain', 'N/A')}</td>
            <td class="status-{status}">{status_text}</td>
            <td>{subdomain.get('ip', 'N/A')}</td>
        </tr>
        """)
    
    table_html = f"""
    <div class="section">
        <h3>🌐 Discovered Subdomains</h3>
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Status</th>
                    <th>IP Address</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        {f'<p><em>Showing first 50 of {len(subdomains)} subdomains</em></p>' if len(subdomains) > 50 else ''}
    </div>
    """
    
    return table_html

def build_ports_section(ports: List[Dict[str, Any]]) -> str:
    """Build HTML section for ports"""
    if not ports:
        return '<div class="section"><h3>🔌 Open Ports</h3><p>No open ports found.</p></div>'
    
    rows = []
    for port in ports:
        rows.append(f"""
        <tr>
            <td>{port.get('host', 'N/A')}</td>
            <td>{port.get('port', 'N/A')}</td>
            <td>{port.get('service', 'N/A')}</td>
            <td>{port.get('banner', 'N/A')[:100]}{'...' if len(port.get('banner', '')) > 100 else ''}</td>
        </tr>
        """)
    
    table_html = f"""
    <div class="section">
        <h3>🔌 Open Ports</h3>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """
    
    return table_html

def build_vulnerabilities_section(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Build HTML section for vulnerabilities"""
    if not vulnerabilities:
        return '<div class="section"><h3>🚨 Vulnerabilities</h3><p>No vulnerabilities found.</p></div>'
    
    rows = []
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'low')
        rows.append(f"""
        <tr>
            <td class="severity-{severity}">{severity.upper()}</td>
            <td>{vuln.get('type', 'N/A')}</td>
            <td>{vuln.get('target', 'N/A')}</td>
            <td>{vuln.get('description', 'N/A')}</td>
        </tr>
        """)
    
    table_html = f"""
    <div class="section">
        <h3>🚨 Detected Vulnerabilities</h3>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """
    
    return table_html

def build_technologies_section(technologies: List[Dict[str, Any]]) -> str:
    """Build HTML section for technologies"""
    if not technologies:
        return '<div class="section"><h3>🛠️ Technologies</h3><p>No technologies detected.</p></div>'
    
    rows = []
    for tech in technologies:
        rows.append(f"""
        <tr>
            <td>{tech.get('name', 'N/A')}</td>
            <td>{tech.get('version', 'N/A')}</td>
            <td>{tech.get('confidence', 'N/A')}</td>
            <td>{tech.get('target', 'N/A')}</td>
        </tr>
        """)
    
    table_html = f"""
    <div class="section">
        <h3>🛠️ Detected Technologies</h3>
        <table>
            <thead>
                <tr>
                    <th>Technology</th>
                    <th>Version</th>
                    <th>Confidence</th>
                    <th>Target</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """
    
    return table_html
