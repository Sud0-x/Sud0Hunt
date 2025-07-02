"""
Advanced Security Checks Plugin
Additional security checks specifically for pentesters
"""

import asyncio
import aiohttp
import logging
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)
PLUGIN_CLASS_NAME = "SecurityChecksPlugin"

class SecurityChecksPlugin:
    """Plugin for advanced security checks"""
    
    def __init__(self):
        # Common backup file extensions
        self.backup_extensions = [
            '.bak', '.old', '.backup', '.orig', '.copy', '.tmp', '~',
            '.swp', '.save', '.conf.bak', '.config.old'
        ]
        
        # Common sensitive files
        self.sensitive_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', '.htpasswd',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php'
        ]
        
        # Common admin paths
        self.admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/wp-login.php',
            '/manager', '/phpmyadmin', '/cpanel', '/webmail',
            '/admin.php', '/login.php', '/console', '/dashboard'
        ]
        
        # API endpoints to check
        self.api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/swagger.json', '/api-docs',
            '/openapi.json', '/v1/swagger.json'
        ]

    async def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Run advanced security checks"""
        logger.info(f"Starting advanced security checks on {target}")
        
        findings = []
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                
                # Check for sensitive files
                sensitive_findings = await self._check_sensitive_files(session, target)
                findings.extend(sensitive_findings)
                
                # Check for backup files
                backup_findings = await self._check_backup_files(session, target)
                findings.extend(backup_findings)
                
                # Check admin interfaces
                admin_findings = await self._check_admin_interfaces(session, target)
                findings.extend(admin_findings)
                
                # Check API endpoints
                api_findings = await self._check_api_endpoints(session, target)
                findings.extend(api_findings)
                
                # Check for information disclosure
                info_findings = await self._check_information_disclosure(session, target)
                findings.extend(info_findings)
        
        except Exception as e:
            logger.error(f"Advanced security checks error for {target}: {e}")
        
        logger.info(f"Found {len(findings)} additional security issues on {target}")
        return findings
    
    async def _check_sensitive_files(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files"""
        findings = []
        
        for filename in self.sensitive_files[:6]:  # Limit for speed
            try:
                test_url = urljoin(target, filename)
                async with session.get(test_url, allow_redirects=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        severity = 'medium'
                        if filename in ['robots.txt', 'sitemap.xml']:
                            severity = 'low'
                        elif 'phpinfo' in filename or 'info.php' in filename:
                            severity = 'high'
                        
                        findings.append({
                            'type': 'Sensitive File Exposed',
                            'severity': severity,
                            'target': test_url,
                            'description': f'Sensitive file exposed: {filename}',
                            'evidence': f'HTTP {response.status} - File accessible'
                        })
            
            except Exception:
                continue
            
            await asyncio.sleep(0.05)
        
        return findings
    
    async def _check_backup_files(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for backup files"""
        findings = []
        
        # Common filenames to check for backups
        base_files = ['index', 'config', 'database', 'db', 'admin']
        
        for base_file in base_files[:3]:  # Limit for speed
            for ext in self.backup_extensions[:3]:
                try:
                    filename = f"{base_file}{ext}"
                    test_url = urljoin(target, filename)
                    
                    async with session.head(test_url, allow_redirects=False) as response:
                        if response.status == 200:
                            findings.append({
                                'type': 'Backup File Exposed',
                                'severity': 'high',
                                'target': test_url,
                                'description': f'Backup file found: {filename}',
                                'evidence': f'HTTP {response.status} - Backup file accessible'
                            })
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.05)
        
        return findings
    
    async def _check_admin_interfaces(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for admin interfaces"""
        findings = []
        
        for path in self.admin_paths[:6]:  # Limit for speed
            try:
                test_url = urljoin(target, path)
                async with session.get(test_url, allow_redirects=False) as response:
                    if response.status in [200, 401, 403]:
                        content = await response.text()
                        
                        # Check for admin indicators
                        admin_indicators = [
                            'login', 'password', 'username', 'admin', 'dashboard',
                            'control panel', 'management', 'phpmyadmin'
                        ]
                        
                        if any(indicator in content.lower() for indicator in admin_indicators):
                            severity = 'medium'
                            if response.status == 200:
                                severity = 'high'
                            
                            findings.append({
                                'type': 'Admin Interface Found',
                                'severity': severity,
                                'target': test_url,
                                'description': f'Admin interface discovered: {path}',
                                'evidence': f'HTTP {response.status} - Admin login page detected'
                            })
            
            except Exception:
                continue
            
            await asyncio.sleep(0.1)
        
        return findings
    
    async def _check_api_endpoints(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for API endpoints"""
        findings = []
        
        for endpoint in self.api_endpoints[:4]:  # Limit for speed
            try:
                test_url = urljoin(target, endpoint)
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for API indicators
                        api_indicators = [
                            'swagger', 'openapi', 'api', 'json', 'xml',
                            'rest', 'graphql', 'endpoints'
                        ]
                        
                        if any(indicator in content.lower() for indicator in api_indicators):
                            findings.append({
                                'type': 'API Endpoint Found',
                                'severity': 'medium',
                                'target': test_url,
                                'description': f'API endpoint discovered: {endpoint}',
                                'evidence': f'HTTP {response.status} - API documentation or endpoint found'
                            })
            
            except Exception:
                continue
            
            await asyncio.sleep(0.1)
        
        return findings
    
    async def _check_information_disclosure(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        findings = []
        
        try:
            # Check main page for information disclosure
            async with session.get(target) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                # Check for server version disclosure
                server_header = headers.get('Server', '')
                if server_header and any(version_indicator in server_header for version_indicator in ['/', '\\', 'v', 'version']):
                    findings.append({
                        'type': 'Server Version Disclosure',
                        'severity': 'low',
                        'target': target,
                        'description': 'Server version information disclosed',
                        'evidence': f'Server header: {server_header}'
                    })
                
                # Check for powered-by headers
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    findings.append({
                        'type': 'Technology Disclosure',
                        'severity': 'low',
                        'target': target,
                        'description': 'Technology stack information disclosed',
                        'evidence': f'X-Powered-By header: {powered_by}'
                    })
                
                # Check for debug information in content
                debug_indicators = [
                    'debug', 'error', 'exception', 'stack trace',
                    'sql error', 'warning', 'notice'
                ]
                
                content_lower = content.lower()
                for indicator in debug_indicators:
                    if indicator in content_lower:
                        findings.append({
                            'type': 'Debug Information Leak',
                            'severity': 'medium',
                            'target': target,
                            'description': f'Debug information found in response: {indicator}',
                            'evidence': f'Debug indicator "{indicator}" found in page content'
                        })
                        break  # Only report one to avoid spam
        
        except Exception:
            pass
        
        return findings
