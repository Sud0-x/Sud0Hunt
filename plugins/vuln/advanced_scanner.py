"""
Plugin: Advanced Vulnerability Scanner
Comprehensive vulnerability detection with multiple request methods, timing analysis, and response comparison
Author: sud0x.dev@proton.me | License: MIT
"""

import asyncio
import aiohttp
import json
import logging
import os
import time
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import hashlib
import re

logger = logging.getLogger(__name__)


class AdvancedVulnerabilityScanner:
    """Professional advanced vulnerability scanner with comprehensive detection capabilities"""
    
    def __init__(self, exploit_db_path: str = None):
        """Initialize advanced scanner with exploit database"""
        self.exploit_db = self._load_exploit_db(exploit_db_path)
        self.session_cookies = {}
        self.response_cache = {}
        self.timing_baseline = {}
        self.max_retries = 3
        self.timeout = 10
        
        # Create response storage directory
        self.response_dir = Path("responses")
        self.response_dir.mkdir(exist_ok=True)
    
    def _load_exploit_db(self, db_path: Optional[str] = None) -> Dict[str, Any]:
        """Load exploit database from JSON file"""
        if not db_path:
            db_path = Path(__file__).parent.parent.parent / "data" / "exploits_db.json"
        
        try:
            with open(db_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            logger.error(f"Failed to load exploit database: {e}")
            return {}
    
    async def scan_target(self, target: str, methods: List[str] = None, 
                         concurrency: int = 10) -> List[Dict[str, Any]]:
        """Perform comprehensive vulnerability scan on target"""
        logger.info(f"Starting advanced vulnerability scan on: {target}")
        
        if not methods:
            methods = ['sql_injection', 'xss', 'ssti', 'command_injection', 'xxe', 'directory_traversal']
        
        vulnerabilities = []
        
        # Create session with custom settings
        connector = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            cookies=self.session_cookies
        ) as session:
            
            # Establish timing baseline
            await self._establish_timing_baseline(session, target)
            
            # Run vulnerability scans concurrently
            scan_tasks = []
            
            if 'sql_injection' in methods:
                scan_tasks.append(self._scan_sql_injection(session, target))
            
            if 'xss' in methods:
                scan_tasks.append(self._scan_xss(session, target))
            
            if 'ssti' in methods:
                scan_tasks.append(self._scan_ssti(session, target))
            
            if 'command_injection' in methods:
                scan_tasks.append(self._scan_command_injection(session, target))
            
            if 'xxe' in methods:
                scan_tasks.append(self._scan_xxe(session, target))
            
            if 'directory_traversal' in methods:
                scan_tasks.append(self._scan_directory_traversal(session, target))
            
            # Execute all scans concurrently
            if scan_tasks:
                scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for result in scan_results:
                    if isinstance(result, list):
                        vulnerabilities.extend(result)
                    elif isinstance(result, Exception):
                        logger.error(f"Scan task failed: {result}")
        
        logger.info(f"Advanced scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def _establish_timing_baseline(self, session: aiohttp.ClientSession, target: str):
        """Establish timing baseline for time-based attacks"""
        logger.debug(f"Establishing timing baseline for: {target}")
        
        timing_samples = []
        for _ in range(3):
            start_time = time.time()
            try:
                async with session.get(target) as response:
                    await response.text()
                    timing_samples.append(time.time() - start_time)
            except Exception:
                pass
            
            await asyncio.sleep(0.5)
        
        if timing_samples:
            self.timing_baseline[target] = sum(timing_samples) / len(timing_samples)
        else:
            self.timing_baseline[target] = 1.0  # Default baseline
    
    async def _scan_sql_injection(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Comprehensive SQL injection scanning with multiple techniques"""
        logger.info(f"Scanning for SQL injection: {target}")
        vulnerabilities = []
        
        sql_data = self.exploit_db.get('sql_injection', {})
        test_params = ['id', 'page', 'search', 'q', 'user', 'category', 'filter']
        
        # Test different SQL injection types
        for vuln_type in ['error_based', 'time_based', 'boolean_based', 'union_based']:
            payloads = self._get_sql_payloads(sql_data, vuln_type)
            
            for param in test_params:
                for payload in payloads[:5]:  # Limit for performance
                    
                    # Test GET requests
                    vuln = await self._test_sql_payload(session, target, param, payload, 'GET', vuln_type)
                    if vuln:
                        vulnerabilities.append(vuln)
                    
                    # Test POST requests
                    vuln = await self._test_sql_payload(session, target, param, payload, 'POST', vuln_type)
                    if vuln:
                        vulnerabilities.append(vuln)
                    
                    await asyncio.sleep(0.1)  # Rate limiting
        
        return vulnerabilities
    
    async def _test_sql_payload(self, session: aiohttp.ClientSession, target: str, 
                               param: str, payload: str, method: str, vuln_type: str) -> Optional[Dict[str, Any]]:
        """Test individual SQL injection payload"""
        
        try:
            if method == 'GET':
                test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
                request_func = session.get(test_url)
            else:  # POST
                data = {param: payload}
                request_func = session.post(target, data=data)
            
            # Execute request with retry logic
            response_data = await self._execute_request_with_retry(request_func)
            if not response_data:
                return None
            
            response, content, timing = response_data
            
            # Save response for manual review
            await self._save_response(target, param, payload, response, content)
            
            # Analyze response for SQL injection indicators
            vulnerability = None
            
            if vuln_type == 'error_based':
                vulnerability = self._analyze_sql_errors(target, param, payload, response, content, method)
            elif vuln_type == 'time_based':
                vulnerability = self._analyze_timing_attack(target, param, payload, timing, method)
            elif vuln_type == 'boolean_based':
                vulnerability = self._analyze_boolean_sqli(target, param, payload, response, content, method)
            elif vuln_type == 'union_based':
                vulnerability = self._analyze_union_sqli(target, param, payload, response, content, method)
            
            return vulnerability
            
        except Exception as e:
            logger.debug(f"Error testing SQL payload {payload}: {e}")
            return None
    
    def _get_sql_payloads(self, sql_data: Dict, vuln_type: str) -> List[str]:
        """Get SQL payloads for specific vulnerability type"""
        if vuln_type == 'error_based':
            payloads = []
            for db_type in sql_data.get('error_based', {}).values():
                payloads.extend(db_type[:3])  # Top 3 per database
            return payloads
        
        return sql_data.get(vuln_type, [])
    
    def _analyze_sql_errors(self, target: str, param: str, payload: str, 
                           response, content: str, method: str) -> Optional[Dict[str, Any]]:
        """Analyze response for SQL error indicators"""
        
        error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'PostgreSQL.*ERROR',
            r'ORA-[0-9][0-9][0-9][0-9]',
            r'Microsoft OLE DB Provider',
            r'ADODB.Field error'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning(f"SQL injection detected: {target}?{param}={payload[:30]}...")
                
                return {
                    'type': 'SQL Injection (Error-based)',
                    'severity': 'high',
                    'target': f"{target}?{param}={payload[:50]}...",
                    'method': method,
                    'parameter': param,
                    'description': f'Error-based SQL injection via parameter "{param}"',
                    'evidence': f'Database error pattern: {pattern}',
                    'payload': payload,
                    'response_status': response.status,
                    'exploit_suggestions': self._get_sql_exploit_suggestions(target)
                }
        
        return None
    
    def _analyze_timing_attack(self, target: str, param: str, payload: str, 
                              timing: float, method: str) -> Optional[Dict[str, Any]]:
        """Analyze response timing for time-based SQL injection"""
        
        baseline = self.timing_baseline.get(target, 1.0)
        
        # Consider it a timing attack if response is significantly slower
        if timing > baseline + 4.0:  # 4 second delay threshold
            logger.warning(f"Time-based SQL injection detected: {target}?{param}={payload[:30]}...")
            
            return {
                'type': 'SQL Injection (Time-based)',
                'severity': 'high',
                'target': f"{target}?{param}={payload[:50]}...",
                'method': method,
                'parameter': param,
                'description': f'Time-based SQL injection via parameter "{param}"',
                'evidence': f'Response delay: {timing:.2f}s (baseline: {baseline:.2f}s)',
                'payload': payload,
                'timing': timing,
                'exploit_suggestions': self._get_sql_exploit_suggestions(target)
            }
        
        return None
    
    def _analyze_boolean_sqli(self, target: str, param: str, payload: str, 
                             response, content: str, method: str) -> Optional[Dict[str, Any]]:
        """Analyze response for boolean-based SQL injection"""
        
        # Get baseline response with normal parameter
        baseline_key = f"{target}_{param}_baseline"
        if baseline_key not in self.response_cache:
            return None
        
        baseline_content = self.response_cache[baseline_key]
        
        # Compare response lengths and content
        if abs(len(content) - len(baseline_content)) > 100:  # Significant difference
            return {
                'type': 'SQL Injection (Boolean-based)',
                'severity': 'medium',
                'target': f"{target}?{param}={payload[:50]}...",
                'method': method,
                'parameter': param,
                'description': f'Boolean-based SQL injection via parameter "{param}"',
                'evidence': f'Response length difference: {len(content)} vs {len(baseline_content)}',
                'payload': payload,
                'response_status': response.status,
                'exploit_suggestions': self._get_sql_exploit_suggestions(target)
            }
        
        return None
    
    def _analyze_union_sqli(self, target: str, param: str, payload: str, 
                           response, content: str, method: str) -> Optional[Dict[str, Any]]:
        """Analyze response for UNION-based SQL injection"""
        
        # Look for typical UNION injection indicators
        union_indicators = [
            r'admin.*password',
            r'root.*mysql',
            r'user.*database',
            r'\d+\.\d+\.\d+',  # Version numbers
        ]
        
        for indicator in union_indicators:
            if re.search(indicator, content, re.IGNORECASE):
                return {
                    'type': 'SQL Injection (UNION-based)',
                    'severity': 'high',
                    'target': f"{target}?{param}={payload[:50]}...",
                    'method': method,
                    'parameter': param,
                    'description': f'UNION-based SQL injection via parameter "{param}"',
                    'evidence': f'Data extraction indicator: {indicator}',
                    'payload': payload,
                    'response_status': response.status,
                    'exploit_suggestions': self._get_sql_exploit_suggestions(target)
                }
        
        return None
    
    async def _scan_xss(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Comprehensive XSS scanning with context analysis"""
        logger.info(f"Scanning for XSS: {target}")
        vulnerabilities = []
        
        xss_data = self.exploit_db.get('xss', {})
        test_params = ['q', 'search', 'name', 'comment', 'message', 'data', 'content']
        
        for xss_type in ['basic', 'filter_bypass', 'context_breaking']:
            payloads = xss_data.get(xss_type, [])
            
            for param in test_params:
                for payload in payloads[:5]:  # Limit for performance
                    
                    # Test GET requests
                    vuln = await self._test_xss_payload(session, target, param, payload, 'GET')
                    if vuln:
                        vulnerabilities.append(vuln)
                    
                    # Test POST requests
                    vuln = await self._test_xss_payload(session, target, param, payload, 'POST')
                    if vuln:
                        vulnerabilities.append(vuln)
                    
                    await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _test_xss_payload(self, session: aiohttp.ClientSession, target: str, 
                               param: str, payload: str, method: str) -> Optional[Dict[str, Any]]:
        """Test individual XSS payload"""
        
        try:
            if method == 'GET':
                test_url = f"{target}?{param}={urllib.parse.quote(payload)}"
                request_func = session.get(test_url)
            else:  # POST
                data = {param: payload}
                request_func = session.post(target, data=data)
            
            response_data = await self._execute_request_with_retry(request_func)
            if not response_data:
                return None
            
            response, content, timing = response_data
            
            # Save response for manual review
            await self._save_response(target, param, payload, response, content)
            
            # Check if payload is reflected
            if payload in content or payload.replace("'", '"') in content:
                logger.warning(f"XSS detected: {target}?{param}={payload[:30]}...")
                
                # Determine XSS context
                context = self._determine_xss_context(payload, content)
                
                return {
                    'type': f'Cross-Site Scripting ({context})',
                    'severity': 'medium',
                    'target': f"{target}?{param}={payload[:50]}...",
                    'method': method,
                    'parameter': param,
                    'description': f'{context} XSS via parameter "{param}"',
                    'evidence': f'Payload reflected in response: {payload[:50]}...',
                    'payload': payload,
                    'context': context,
                    'response_status': response.status,
                    'exploit_suggestions': self._get_xss_exploit_suggestions(target)
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error testing XSS payload {payload}: {e}")
            return None
    
    def _determine_xss_context(self, payload: str, content: str) -> str:
        """Determine XSS context based on payload and response"""
        if '<script>' in payload.lower() and '<script>' in content.lower():
            return 'Script Context'
        elif 'onerror=' in payload.lower() and 'onerror=' in content.lower():
            return 'Event Handler'
        elif 'javascript:' in payload.lower():
            return 'URL Context'
        else:
            return 'Reflected'
    
    async def _execute_request_with_retry(self, request_func) -> Optional[Tuple]:
        """Execute HTTP request with retry logic"""
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                async with request_func as response:
                    content = await response.text()
                    timing = time.time() - start_time
                    return response, content, timing
            
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.debug(f"Request failed after {self.max_retries} attempts: {e}")
                    return None
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        return None
    
    async def _save_response(self, target: str, param: str, payload: str, 
                           response, content: str):
        """Save HTTP response for manual review"""
        
        # Create filename hash to avoid filesystem issues
        target_hash = hashlib.md5(f"{target}_{param}_{payload}".encode()).hexdigest()[:16]
        filename = self.response_dir / f"response_{target_hash}.json"
        
        response_data = {
            'target': target,
            'parameter': param,
            'payload': payload,
            'status_code': response.status,
            'headers': dict(response.headers),
            'content': content[:10000],  # Limit content size
            'timestamp': time.time()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(response_data, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save response: {e}")
    
    def _get_sql_exploit_suggestions(self, target: str) -> Dict[str, Any]:
        """Generate SQL injection exploit suggestions"""
        sql_data = self.exploit_db.get('sql_injection', {})
        
        return {
            'tools': ['sqlmap', 'NoSQLMap', 'jSQL Injection'],
            'payloads': {
                'union_based': sql_data.get('union_based', {}).get('exploitation', [])[:3],
                'error_based': sql_data.get('error_based', {}).get('mysql', [])[:3]
            },
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        }
    
    def _get_xss_exploit_suggestions(self, target: str) -> Dict[str, Any]:
        """Generate XSS exploit suggestions"""
        xss_data = self.exploit_db.get('xss', {})
        
        return {
            'tools': ['XSSStrike', 'Xenotix XSS Exploit Framework', 'BeEF'],
            'payloads': {
                'advanced': xss_data.get('advanced', [])[:3],
                'bypass': xss_data.get('filter_bypass', [])[:3]
            },
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting'
            ]
        }
    
    # Placeholder methods for other vulnerability types
    async def _scan_ssti(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """SSTI scanning implementation"""
        # Implementation similar to SQL injection but for SSTI
        return []
    
    async def _scan_command_injection(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Command injection scanning implementation"""
        # Implementation similar to SQL injection but for command injection
        return []
    
    async def _scan_xxe(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """XXE scanning implementation"""
        # Implementation for XXE testing with XML payloads
        return []
    
    async def _scan_directory_traversal(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Directory traversal scanning implementation"""
        # Implementation for directory traversal testing
        return []
