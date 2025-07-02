"""
Plugin: Server-Side Template Injection Detection
Detects SSTI vulnerabilities across multiple template engines
Author: sud0x.dev@proton.me | License: MIT
"""

import asyncio
import aiohttp
import logging
import urllib.parse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class SstiDetector:
    """Professional SSTI vulnerability detector"""
    
    def __init__(self, exploit_db: Dict[str, Any]):
        """Initialize SSTI detector with exploit database"""
        self.exploit_db = exploit_db
        self.ssti_payloads = self._load_ssti_payloads()
        self.template_errors = self._load_template_errors()
    
    def _load_ssti_payloads(self) -> List[str]:
        """Load SSTI payloads from exploit database"""
        payloads = []
        ssti_data = self.exploit_db.get('ssti', {})
        
        # Jinja2 payloads
        payloads.extend(ssti_data.get('jinja2', [])[:3])
        
        # Twig payloads
        payloads.extend(ssti_data.get('twig', [])[:2])
        
        return payloads
    
    def _load_template_errors(self) -> List[str]:
        """Load template engine error patterns"""
        return [
            'TemplateSyntaxError',
            'UndefinedError',
            'Twig_Error',
            'Template.*error',
            'Jinja2.*error',
            'Template.*compilation.*failed'
        ]
    
    async def check_ssti(self, session: aiohttp.ClientSession, target: str) -> List[Dict[str, Any]]:
        """Check for SSTI vulnerabilities on target"""
        logger.info(f"Scanning target for SSTI: {target}")
        vulnerabilities = []
        
        test_params = ['template', 'view', 'page', 'content', 'data']
        
        for param in test_params:
            for payload in self.ssti_payloads:
                try:
                    encoded_payload = urllib.parse.quote(payload)
                    test_url = f"{target}?{param}={encoded_payload}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check for template evaluation (7*7=49)
                        if '49' in content and payload.count('7') > 0:
                            logger.warning(f"Detected SSTI template evaluation at: {test_url}")
                            
                            vulnerabilities.append({
                                'type': 'Server-Side Template Injection',
                                'severity': 'high',
                                'target': test_url,
                                'description': f'SSTI detected via parameter "{param}" - template expression evaluated',
                                'evidence': f'Mathematical expression {payload} evaluated to 49',
                                'exploit_suggestions': self._get_exploit_suggestions(test_url)
                            })
                        
                        # Check for template engine errors
                        for error_pattern in self.template_errors:
                            if error_pattern.lower() in content.lower():
                                logger.warning(f"Detected SSTI error pattern at: {test_url}")
                                
                                vulnerabilities.append({
                                    'type': 'Server-Side Template Injection',
                                    'severity': 'medium',
                                    'target': test_url,
                                    'description': f'Potential SSTI via parameter "{param}" - template error detected',
                                    'evidence': f'Template error pattern: {error_pattern}',
                                    'exploit_suggestions': self._get_exploit_suggestions(test_url)
                                })
                                break
                
                except Exception as e:
                    logger.debug(f"Error testing SSTI on {test_url}: {e}")
                    continue
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        logger.info(f"SSTI scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _get_exploit_suggestions(self, target_url: str) -> Dict[str, Any]:
        """Generate exploit suggestions for SSTI"""
        ssti_data = self.exploit_db.get('ssti', {})
        
        return {
            'payloads': {
                'jinja2': ssti_data.get('jinja2', [])[:3],
                'twig': ssti_data.get('twig', [])[:3]
            },
            'tools': ['tplmap', 'SSTImap', 'Custom Scripts'],
            'references': [
                'https://portswigger.net/research/server-side-template-injection',
                'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection'
            ]
        }
