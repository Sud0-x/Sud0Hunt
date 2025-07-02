"""
Port Scanning Plugin
Scans open ports and grabs banners using asyncio
"""

import asyncio
import socket
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

PLUGIN_CLASS_NAME = "PortScanPlugin"

class PortScanPlugin:
    """Plugin for performing asynchronous port scanning"""
    
    # Optimized port list - prioritized by likelihood of being open
    DEFAULT_PORTS = [
        # Most common web ports (highest priority)
        80, 443, 8080, 8443,
        # Common service ports
        22, 21, 25, 53, 110, 143, 993, 995,
        # Database and admin ports
        3306, 5432, 3389, 445, 135, 139,
        # Alternative web ports
        8000, 8888, 9000, 9090, 9443
    ]
    
    # Service mapping for common ports
    SERVICE_MAP = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 135: 'rpc', 139: 'netbios', 143: 'imap',
        443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
        8080: 'http-alt', 8443: 'https-alt', 8888: 'http-alt', 9090: 'websm',
        9443: 'websm-https'
    }
    
    async def scan(self, host: str, timeout: int = 5, **kwargs) -> List[Dict[str, Any]]:
        """Scan a host for open ports and grab banners"""
        ports = kwargs.get('ports', self.DEFAULT_PORTS)
        results = []
        
        logger.info(f"Starting port scan on {host} with {len(ports)} ports")
        
        semaphore = asyncio.Semaphore(50)  # Limit concurrency
        tasks = []
        for port in ports:
            task = self._scan_port(host, port, semaphore, timeout)
            tasks.append(task)
        
        if tasks:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in scan_results:
                if result and not isinstance(result, Exception):
                    results.append(result)
        
        logger.info(f"Found {len(results)} open ports on {host}")
        return results
    
    async def _scan_port(self, host: str, port: int, semaphore: asyncio.Semaphore, timeout: int) -> Dict[str, Any]:
        """Scan a single port to check if it is open and fetch the banner"""
        async with semaphore:
            try:
                # Use very fast timeout for port checking (1 second max)
                fast_timeout = min(timeout, 1)
                loop = asyncio.get_event_loop()
                
                is_open = await asyncio.wait_for(
                    loop.run_in_executor(None, self._is_port_open, host, port, fast_timeout),
                    timeout=fast_timeout + 0.5
                )
                
                if not is_open:
                    return None
                
                # Only grab banner for open ports
                banner = await asyncio.wait_for(
                    loop.run_in_executor(None, self._grab_banner, host, port, fast_timeout),
                    timeout=2.0
                )
                service = self._get_service_name(port)
                
                return {
                    'host': host,
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner
                }
            except Exception:
                return None
    
    def _is_port_open(self, host: str, port: int, timeout: int) -> bool:
        """Check if a port is open using a blocking call"""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                return True
        except Exception:
            return False
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for a port"""
        # First try our custom mapping
        if port in self.SERVICE_MAP:
            return self.SERVICE_MAP[port]
        
        # Try socket.getservbyport as fallback
        try:
            return socket.getservbyport(port, 'tcp')
        except OSError:
            return 'unknown'
    
    def _grab_banner(self, host: str, port: int, timeout: int) -> str:
        """Grab the banner from an open port with service-specific probes"""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(3.0)
                
                # Service-specific banner grabbing
                if port in [80, 8080, 8000, 8888]:
                    # HTTP probe
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif port in [443, 8443, 9443]:
                    # HTTPS probe (just connection info)
                    return f"HTTPS service detected on {host}:{port}"
                elif port == 22:
                    # SSH probe
                    pass  # SSH sends banner immediately
                elif port == 21:
                    # FTP probe
                    pass  # FTP sends banner immediately
                elif port == 25:
                    # SMTP probe
                    pass  # SMTP sends banner immediately
                elif port == 3306:
                    # MySQL probe
                    pass  # MySQL sends handshake immediately
                elif port == 5432:
                    # PostgreSQL probe
                    pass  # PostgreSQL may not send immediate banner
                
                # Read response
                banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                
                # Parse and extract version information
                if banner:
                    version_info = self._extract_version_info(banner, port)
                    if version_info:
                        return f"{banner[:200]} [Version: {version_info}]"
                    return banner[:200] if len(banner) > 200 else banner
                else:
                    return f"Service running on port {port} (no banner)"
                    
        except Exception as e:
            return f"Service detected on port {port} - {str(e)[:30]}"
    
    def _extract_version_info(self, banner: str, port: int) -> str:
        """Extract version information from service banners"""
        import re
        
        version_patterns = {
            # Web servers
            'apache': r'Apache/([\d.]+)',
            'nginx': r'nginx/([\d.]+)',
            'iis': r'Microsoft-IIS/([\d.]+)',
            # SSH
            'openssh': r'OpenSSH_([\d.]+)',
            'ssh': r'SSH-([\d.]+)',
            # FTP
            'vsftpd': r'vsftpd ([\d.]+)',
            'filezilla': r'FileZilla Server ([\d.]+)',
            # Mail servers
            'postfix': r'Postfix ([\d.]+)',
            'sendmail': r'Sendmail ([\d.]+)',
            # Databases
            'mysql': r'([\d.]+)-([\w-]+)',
            'postgresql': r'PostgreSQL ([\d.]+)',
            # Other
            'php': r'PHP/([\d.]+)',
        }
        
        for service, pattern in version_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return f"{service.upper()} {match.group(1)}"
        
        return ""
