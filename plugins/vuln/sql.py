"""
Plugin: SQL Injection Detection
Detects SQL injection vulnerabilities using error-based and time-based techniques
Author: sud0x.dev@proton.me | License: MIT
"""

import asyncio
import aiohttp
import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class SqlInjectionDetector:
    """Professional SQL injection vulnerability detector"""
    
    def __init__(self, exploit_db: Dict[str, Any]):
        """Initialize SQL injection detector with exploit database"""
        self.exploit_db = exploit_db
        self.sql_payloads = self._load_sql_payloads()
        self.error_patterns = self._load_error_patterns()
    
    def _load_sql_payloads(self) -> List[str]:
        """Load SQL injection payloads from exploit database"""
        payloads = []
        sql_data = self.exploit_db.get('sql_injection', {})
        
        # Error-based payloads
        for db_type in sql_data.get('error_based', {}).values():
            payloads.extend(db_type[:2])  # Top 2 per database type
        
        # Union-based detection payloads
        payloads.extend(sql_data.get('union_based', {}).get('detection', [])[:2])
        
        # Time-based payloads
        payloads.extend(sql_data.get('time_based', [])[:2])
        
        return payloads
    
    def _load_error_patterns(self) -> List[str]:
        """Load SQL error patterns for detection"""
        return [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'MySQLSyntaxErrorException',
            r'PostgreSQL.*ERROR',
            r'Warning.*pg_.*',
            r'ORA-[0-9][0-9][0-9][0-9]',
            r'Microsoft OLE DB Provider',
            r'ADODB.Field error'
        ]
    
    async def check_sql_injection(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities on target"""
        logger.info(f"Scanning target for SQL injection: {target}")
        vulnerabilities = []
        
        test_params = ['id', 'page', 'search', 'q', 'user']
        
        for param in test_params:
            for payload in self.sql_payloads:
                try:
                    test_url = f"{target}?{param}={payload}"
                    
                    async with session.get(test_url, allow_redirects=False) as response:
                        content = await response.text()
                        
                        # Check for SQL error patterns
                        for pattern in self.error_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                logger.warning(f"Detected possible SQL injection at: {test_url}")
                                
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'high',
                                    'target': test_url,
                                    'description': f'SQL injection detected via parameter "{param}"',
                                    'evidence': f'Database error pattern: {pattern}',
                                    'exploit_suggestions': self._get_exploit_suggestions(test_url)
                                })
                                break
                        
                        # Check for response differences (blind SQLi indicators)
                        if response.status == 500:
                            original_url = f"{target}?{param}=1"
                            try:
                                async with session.get(original_url) as orig_response:
                                    if orig_response.status != response.status:
                                        vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'severity': 'medium',
                                            'target': test_url,
                                            'description': f'Potential blind SQL injection via parameter "{param}"',
                                            'evidence': f'Status code difference: {orig_response.status} vs {response.status}',
                                            'exploit_suggestions': self._get_exploit_suggestions(test_url)
                                        })
                            except Exception:
                                pass
                
                except Exception as e:
                    logger.debug(f"Error testing SQL injection on {test_url}: {e}")
                    continue
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        logger.info(f"SQL injection scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _get_exploit_suggestions(self, target_url: str) -> Dict[str, Any]:
        """Generate exploit suggestions for SQL injection"""
        sql_data = self.exploit_db.get('sql_injection', {})
        
        return {
            'payloads': {
                'error_based': sql_data.get('error_based', {}).get('mysql', [])[:3],
                'union_based': sql_data.get('union_based', {}).get('exploitation', [])[:3],
                'time_based': sql_data.get('time_based', [])[:3]
            },
            'tools': ['sqlmap', 'NoSQLMap', 'jSQL Injection'],
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        }
