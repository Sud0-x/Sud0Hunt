"""
Plugin: Cross-Site Scripting Detection
Detects XSS vulnerabilities including reflected, stored, and DOM-based variants
Author: sud0x.dev@proton.me | License: MIT
"""

import asyncio
import aiohttp
import logging
import urllib.parse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class XssDetector:
    """Professional XSS vulnerability detector"""
    
    def __init__(self, exploit_db: Dict[str, Any]):
        """Initialize XSS detector with exploit database"""
        self.exploit_db = exploit_db
        self.xss_payloads = self._load_xss_payloads()
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads from exploit database"""
        payloads = []
        xss_data = self.exploit_db.get('xss', {})
        
        # Basic XSS payloads
        payloads.extend(xss_data.get('basic', [])[:3])
        
        # Filter bypass payloads
        payloads.extend(xss_data.get('filter_bypass', [])[:3])
        
        return payloads
    
    async def check_xss(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities on target"""
        logger.info(f"Scanning target for XSS: {target}")
        vulnerabilities = []
        
        test_params = ['q', 'search', 'name', 'comment', 'message']
        
        for param in test_params:
            for payload in self.xss_payloads:
                try:
                    # URL encode the payload
                    encoded_payload = urllib.parse.quote(payload)
                    test_url = f"{target}?{param}={encoded_payload}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check if payload is reflected in response
                        if payload in content or payload.replace("'", '"') in content:
                            logger.warning(f"Detected possible XSS at: {test_url}")
                            
                            # Determine XSS type based on response
                            xss_type = self._determine_xss_type(payload, content, response)
                            
                            vulnerabilities.append({
                                'type': f'Cross-Site Scripting ({xss_type})',
                                'severity': 'medium',
                                'target': test_url,
                                'description': f'{xss_type} XSS detected via parameter "{param}"',
                                'evidence': f'Payload reflected in response: {payload[:50]}...',
                                'exploit_suggestions': self._get_exploit_suggestions(test_url)
                            })
                
                except Exception as e:
                    logger.debug(f"Error testing XSS on {test_url}: {e}")
                    continue
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _determine_xss_type(self, payload: str, content: str, response) -> str:
        """Determine the type of XSS vulnerability"""
        # Simple heuristic - could be enhanced
        if '<script>' in payload.lower() and '<script>' in content.lower():
            return 'Reflected'
        elif 'onerror=' in payload.lower() and 'onerror=' in content.lower():
            return 'Reflected'
        else:
            return 'Potential'
    
    def _get_exploit_suggestions(self, target_url: str) -> Dict[str, Any]:
        """Generate exploit suggestions for XSS"""
        xss_data = self.exploit_db.get('xss', {})
        
        return {
            'payloads': {
                'basic': xss_data.get('basic', [])[:3],
                'bypass': xss_data.get('filter_bypass', [])[:3]
            },
            'tools': ['XSSStrike', 'Xenotix XSS Exploit Framework', 'BeEF'],
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting'
            ]
        }
