"""
Technology Detection Plugin
Detects technologies and frameworks used on the target
"""

import asyncio
import aiohttp
import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
PLUGIN_CLASS_NAME = "TechDetectPlugin"

class TechDetectPlugin:
    """Plugin for detecting technologies and frameworks"""
    
    def __init__(self):
        self.technology_patterns = {
            'Apache': re.compile(r'Apache/([\d.]+)', re.I),
            'nginx': re.compile(r'nginx/([\d.]+)', re.I),
            'IIS': re.compile(r'Microsoft-IIS/([\d.]+)', re.I),
            'PHP': re.compile(r'PHP/([\d.]+)', re.I),
            'WordPress': re.compile(r'wp-content', re.I),
            'Joomla': re.compile(r'Joomla! ([\d.]+)', re.I),
            'Drupal': re.compile(r'Drupal ([\d.]+)', re.I),
            'Laravel': re.compile(r'Laravel', re.I),
            'Django': re.compile(r'Django', re.I),
            'React': re.compile(r'React', re.I),
            'Angular': re.compile(r'AngularJS', re.I),
            'Vue.js': re.compile(r'Vue.js', re.I),
            'ASP.NET': re.compile(r'ASP.NET', re.I)
        }
    
    async def scan(self, target: str, timeout: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Run technology detection on a target"""
        logger.info(f"Starting technology detection on {target}")
        
        technologies = []
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(target) as response:
                    text = await response.text()
                    
                    # Check server headers
                    server_header = response.headers.get('Server', '')
                    x_powered_by_header = response.headers.get('X-Powered-By', '')
                    
                    # Check for known technologies in server and X-Powered-By headers
                    techs = self._identify_technologies(server_header, x_powered_by_header, text)
                    
                    for tech in techs:
                        technologies.append(tech)
        except Exception as e:
            logger.error(f"Technology detection failed for {target}: {e}")
        
        logger.info(f"Detected {len(technologies)} technologies on {target}")
        return technologies
    
    def _identify_technologies(self, server_header: str, x_powered_by_header: str, text: str) -> List[Dict[str, Any]]:
        """Identify technologies based on headers and page content"""
        detected = {}
        
        # Check server headers first
        for name, pattern in self.technology_patterns.items():
            confidence = "medium"
            version = "N/A"
            found_in = []
            
            # Search in server header
            match = pattern.search(server_header)
            if match:
                found_in.append("Server header")
                confidence = "high"
                if match.groups():
                    version = match.group(1)
            
            # Search in X-Powered-By header
            match = pattern.search(x_powered_by_header)
            if match:
                found_in.append("X-Powered-By header")
                confidence = "high"
                if match.groups() and version == "N/A":
                    version = match.group(1)
            
            # Search in page content (lower confidence)
            match = pattern.search(text)
            if match:
                found_in.append("Page content")
                if not found_in or confidence == "medium":  # Only set if not found elsewhere
                    confidence = "medium"
                if match.groups() and version == "N/A":
                    version = match.group(1)
            
            if found_in:
                detected[name] = {
                    'name': name,
                    'version': version,
                    'confidence': confidence,
                    'target': server_header if "Server header" in found_in else x_powered_by_header if "X-Powered-By header" in found_in else "Page content",
                    'evidence': ", ".join(found_in)
                }
        
        # Additional specific checks
        additional_techs = self._detect_additional_technologies(text)
        detected.update(additional_techs)
        
        return list(detected.values())
    
    def _detect_additional_technologies(self, text: str) -> Dict[str, Dict[str, Any]]:
        """Detect additional technologies through specific patterns"""
        detected = {}
        
        # CMS specific checks
        if 'wp-content' in text.lower() or 'wp-includes' in text.lower():
            detected['WordPress'] = {
                'name': 'WordPress',
                'version': self._extract_wordpress_version(text),
                'confidence': 'high',
                'target': 'Page content',
                'evidence': 'WordPress-specific paths detected'
            }
        
        # JavaScript framework checks
        if 'data-reactroot' in text or 'react' in text.lower():
            detected['React'] = {
                'name': 'React',
                'version': 'N/A',
                'confidence': 'medium',
                'target': 'Page content',
                'evidence': 'React elements detected'
            }
        
        if 'ng-app' in text or 'angular' in text.lower():
            detected['AngularJS'] = {
                'name': 'AngularJS',
                'version': 'N/A',
                'confidence': 'medium',
                'target': 'Page content',
                'evidence': 'AngularJS directives detected'
            }
        
        if '__nuxt' in text or 'nuxt' in text.lower():
            detected['Nuxt.js'] = {
                'name': 'Nuxt.js',
                'version': 'N/A',
                'confidence': 'medium',
                'target': 'Page content',
                'evidence': 'Nuxt.js markers detected'
            }
        
        # CSS Framework checks
        if 'bootstrap' in text.lower():
            version_match = re.search(r'bootstrap[./]?(\d+\.\d+\.\d+)', text, re.I)
            detected['Bootstrap'] = {
                'name': 'Bootstrap',
                'version': version_match.group(1) if version_match else 'N/A',
                'confidence': 'medium',
                'target': 'Page content',
                'evidence': 'Bootstrap CSS/JS detected'
            }
        
        # Server-side technology checks
        if '.aspx' in text or 'viewstate' in text.lower():
            detected['ASP.NET'] = {
                'name': 'ASP.NET',
                'version': 'N/A',
                'confidence': 'high',
                'target': 'Page content',
                'evidence': 'ASP.NET-specific elements detected'
            }
        
        if '.jsp' in text or 'jsessionid' in text.lower():
            detected['Java/JSP'] = {
                'name': 'Java/JSP',
                'version': 'N/A',
                'confidence': 'high',
                'target': 'Page content',
                'evidence': 'JSP/Java elements detected'
            }
        
        return detected
    
    def _extract_wordpress_version(self, text: str) -> str:
        """Extract WordPress version from meta tags or other indicators"""
        # Look for generator meta tag
        version_match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', text, re.I)
        if version_match:
            return version_match.group(1)
        
        # Look for version in script/style tags
        version_match = re.search(r'wp-content/.*?ver=([\d.]+)', text, re.I)
        if version_match:
            return version_match.group(1)
        
        return 'N/A'
