"""
Subdomain Enumeration Plugin
Finds subdomains using DNS brute force and public APIs
"""

import asyncio
import aiohttp
import socket
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
PLUGIN_CLASS_NAME = "SubdomainEnumPlugin"

class SubdomainEnumPlugin:
    """Plugin for subdomain enumeration using multiple techniques"""
    
    def __init__(self):
        # Prioritized subdomain list - most common first for better efficiency
        self.common_subdomains = [
            # Top priority - most commonly found subdomains
            'www', 'api', 'admin', 'mail', 'test', 'dev', 'staging', 'beta',
            'app', 'blog', 'shop', 'secure', 'support', 'portal', 'cdn',
            # Medium priority
            'ftp', 'smtp', 'ns1', 'ns2', 'webmail', 'mobile', 'static',
            'img', 'images', 'vpn', 'help', 'cloud', 'server', 'monitor',
            # Lower priority but still valuable
            'backup', 'git', 'jenkins', 'docs', 'wiki', 'forum', 'demo'
        ]
    
    async def scan(self, domain: str, timeout: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Run subdomain enumeration on a domain"""
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        subdomains = set()
        
        # Try DNS brute force
        dns_subdomains = await self._dns_brute_force(domain, timeout)
        subdomains.update(dns_subdomains)
        
        # Try public APIs (crt.sh)
        try:
            api_subdomains = await self._crt_sh_api(domain, timeout)
            subdomains.update(api_subdomains)
        except Exception as e:
            logger.warning(f"crt.sh API failed for {domain}: {e}")
        
        # Check if subdomains are alive
        results = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent checks
        
        tasks = []
        for subdomain in subdomains:
            task = self._check_subdomain_alive(subdomain, semaphore, timeout)
            tasks.append(task)
        
        if tasks:
            alive_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in alive_results:
                if isinstance(result, dict):
                    results.append(result)
        
        logger.info(f"Found {len(results)} subdomains for {domain}")
        return results
    
    async def _dns_brute_force(self, domain: str, timeout: int) -> List[str]:
        """Perform DNS brute force with common subdomain names"""
        subdomains = []
        semaphore = asyncio.Semaphore(100)  # Limit concurrent DNS queries
        
        tasks = []
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            task = self._resolve_domain(full_domain, semaphore)
            tasks.append(task)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    subdomains.append(f"{self.common_subdomains[i]}.{domain}")
        
        return subdomains
    
    async def _resolve_domain(self, domain: str, semaphore: asyncio.Semaphore) -> str:
        """Resolve a domain to IP address with fast timeout"""
        async with semaphore:
            try:
                loop = asyncio.get_event_loop()
                # Use shorter timeout for DNS resolution - 2 seconds max
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, self._fast_dns_resolve, domain), 
                    timeout=2.0
                )
                return ip
            except Exception:
                return None
    
    def _fast_dns_resolve(self, domain: str) -> str:
        """Fast DNS resolution with custom timeout"""
        try:
            # Set a very short timeout for DNS queries
            socket.setdefaulttimeout(1.5)
            ip = socket.gethostbyname(domain)
            return ip
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    async def _crt_sh_api(self, domain: str, timeout: int) -> List[str]:
        """Query crt.sh certificate transparency logs"""
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            if name_value:
                                # Split by newlines as crt.sh can return multiple domains
                                for sub in name_value.split('\n'):
                                    sub = sub.strip()
                                    if sub and domain in sub and not sub.startswith('*'):
                                        subdomains.add(sub)
        
        except Exception as e:
            logger.error(f"crt.sh API error: {e}")
        
        return list(subdomains)
    
    async def _check_subdomain_alive(self, subdomain: str, semaphore: asyncio.Semaphore, timeout: int) -> Dict[str, Any]:
        """Check if a subdomain is alive and get its IP"""
        async with semaphore:
            try:
                # Try to resolve the domain
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
                
                # Try to make HTTP request to check if it's actually alive
                alive = await self._http_check(subdomain, timeout)
                
                return {
                    'domain': subdomain,
                    'ip': ip,
                    'alive': alive
                }
            except Exception:
                return {
                    'domain': subdomain,
                    'ip': None,
                    'alive': False
                }
    
    async def _http_check(self, subdomain: str, timeout: int) -> bool:
        """Check if subdomain responds to HTTP requests"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                for scheme in ['https', 'http']:
                    try:
                        url = f"{scheme}://{subdomain}"
                        async with session.get(url, allow_redirects=True) as response:
                            if response.status < 500:  # Any response code < 500 means it's alive
                                return True
                    except Exception:
                        continue
                return False
        except Exception:
            return False
