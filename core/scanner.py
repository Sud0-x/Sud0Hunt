"""
Core Scanner Module - Coordinates all scanning tasks
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .plugin_manager import PluginManager
from .utils import generate_html_report

console = Console()
logger = logging.getLogger(__name__)

class Scanner:
    """Main scanner class that coordinates all scanning activities"""
    
    def __init__(self, targets: List[str], threads: int = 20, timeout: int = 10, 
                 output_formats: List[str] = None, no_terminal: bool = False):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.output_formats = output_formats or ['json']
        self.no_terminal = no_terminal
        self.plugin_manager = PluginManager()
        self.results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'targets': targets,
                'scan_types': [],
                'total_time': 0
            },
            'subdomains': [],
            'ports': [],
            'vulnerabilities': [],
            'technologies': []
        }
        
        # Ensure reports directory exists
        Path('reports').mkdir(exist_ok=True)
    
    async def run_scans(self, scan_types: List[str]) -> Dict[str, Any]:
        """Run specified scan types on all targets"""
        self.results['scan_info']['scan_types'] = scan_types
        start_time = datetime.now()
        
        # Load plugins
        await self.plugin_manager.load_plugins()
        
        # Create progress display
        if not self.no_terminal:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                
                # Run each scan type
                for scan_type in scan_types:
                    task = progress.add_task(f"Running {scan_type.replace('_', ' ').title()}", total=len(self.targets))
                    
                    if scan_type == 'subdomain_enum':
                        await self._run_subdomain_enum(progress, task)
                    elif scan_type == 'port_scan':
                        await self._run_port_scan(progress, task)
                    elif scan_type == 'vuln_scan':
                        await self._run_vuln_scan(progress, task)
                    elif scan_type == 'tech_detect':
                        await self._run_tech_detect(progress, task)
                    elif scan_type == 'security_checks':
                        await self._run_security_checks(progress, task)
        else:
            # Run scans without progress display
            for scan_type in scan_types:
                if scan_type == 'subdomain_enum':
                    await self._run_subdomain_enum()
                elif scan_type == 'port_scan':
                    await self._run_port_scan()
                elif scan_type == 'vuln_scan':
                    await self._run_vuln_scan()
                elif scan_type == 'tech_detect':
                    await self._run_tech_detect()
                elif scan_type == 'security_checks':
                    await self._run_security_checks()
        
        # Calculate total time
        end_time = datetime.now()
        self.results['scan_info']['total_time'] = (end_time - start_time).total_seconds()
        
        # Save results
        await self._save_results()
        
        return self.results
    
    async def _run_subdomain_enum(self, progress=None, task=None):
        """Run subdomain enumeration on all targets"""
        logger.info("Starting subdomain enumeration")
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for target in self.targets:
            task_coro = self._run_subdomain_enum_single(target, semaphore)
            tasks.append(task_coro)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Subdomain enumeration failed for {self.targets[i]}: {result}")
            else:
                self.results['subdomains'].extend(result)
            
            if progress and task:
                progress.update(task, advance=1)
    
    async def _run_subdomain_enum_single(self, target: str, semaphore: asyncio.Semaphore):
        """Run subdomain enumeration for a single target"""
        async with semaphore:
            try:
                plugin = self.plugin_manager.get_plugin('subdomain_enum')
                if plugin:
                    return await plugin.scan(target, timeout=self.timeout)
                return []
            except Exception as e:
                logger.error(f"Subdomain enumeration error for {target}: {e}")
                return []
    
    async def _run_port_scan(self, progress=None, task=None):
        """Run port scanning on discovered hosts"""
        logger.info("Starting port scanning")
        
        # Get all unique hosts from subdomains and original targets
        hosts = set(self.targets)
        for subdomain in self.results['subdomains']:
            if subdomain.get('ip'):
                hosts.add(subdomain['ip'])
            if subdomain.get('domain'):
                hosts.add(subdomain['domain'])
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for host in hosts:
            task_coro = self._run_port_scan_single(host, semaphore)
            tasks.append(task_coro)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Port scan failed for {list(hosts)[i]}: {result}")
            else:
                self.results['ports'].extend(result)
            
            if progress and task and i < len(self.targets):
                progress.update(task, advance=1)
    
    async def _run_port_scan_single(self, host: str, semaphore: asyncio.Semaphore):
        """Run port scan for a single host"""
        async with semaphore:
            try:
                plugin = self.plugin_manager.get_plugin('port_scan')
                if plugin:
                    return await plugin.scan(host, timeout=self.timeout)
                return []
            except Exception as e:
                logger.error(f"Port scan error for {host}: {e}")
                return []
    
    async def _run_vuln_scan(self, progress=None, task=None):
        """Run vulnerability scanning on all targets AND discovered subdomains"""
        logger.info("Starting vulnerability scanning")
        
        # Get all targets including discovered subdomains
        all_targets = set(self.targets)
        for subdomain in self.results['subdomains']:
            if subdomain.get('alive') and subdomain.get('domain'):
                all_targets.add(subdomain['domain'])
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for target in all_targets:
            task_coro = self._run_vuln_scan_single(target, semaphore)
            tasks.append(task_coro)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Vulnerability scan failed for {list(all_targets)[i]}: {result}")
            else:
                self.results['vulnerabilities'].extend(result)
            
            if progress and task:
                # Update progress based on original targets count
                if i < len(self.targets):
                    progress.update(task, advance=1)
    
    async def _run_vuln_scan_single(self, target: str, semaphore: asyncio.Semaphore):
        """Run vulnerability scan for a single target"""
        async with semaphore:
            try:
                plugin = self.plugin_manager.get_plugin('vuln_scan')
                if plugin:
                    return await plugin.scan(target, timeout=self.timeout)
                return []
            except Exception as e:
                logger.error(f"Vulnerability scan error for {target}: {e}")
                return []
    
    async def _run_tech_detect(self, progress=None, task=None):
        """Run technology detection on all targets"""
        logger.info("Starting technology detection")
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for target in self.targets:
            task_coro = self._run_tech_detect_single(target, semaphore)
            tasks.append(task_coro)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Technology detection failed for {self.targets[i]}: {result}")
            else:
                self.results['technologies'].extend(result)
            
            if progress and task:
                progress.update(task, advance=1)
    
    async def _run_tech_detect_single(self, target: str, semaphore: asyncio.Semaphore):
        """Run technology detection for a single target"""
        async with semaphore:
            try:
                plugin = self.plugin_manager.get_plugin('tech_detect')
                if plugin:
                    return await plugin.scan(target, timeout=self.timeout)
                return []
            except Exception as e:
                logger.error(f"Technology detection error for {target}: {e}")
                return []
    
    async def _run_security_checks(self, progress=None, task=None):
        """Run advanced security checks on all targets"""
        logger.info("Starting advanced security checks")
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for target in self.targets:
            task_coro = self._run_security_checks_single(target, semaphore)
            tasks.append(task_coro)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Security checks failed for {self.targets[i]}: {result}")
            else:
                self.results['vulnerabilities'].extend(result)
            
            if progress and task:
                progress.update(task, advance=1)
    
    async def _run_security_checks_single(self, target: str, semaphore: asyncio.Semaphore):
        """Run advanced security checks for a single target"""
        async with semaphore:
            try:
                plugin = self.plugin_manager.get_plugin('security_checks')
                if plugin:
                    return await plugin.scan(target, timeout=self.timeout)
                return []
            except Exception as e:
                logger.error(f"Security checks error for {target}: {e}")
                return []
    
    async def _save_results(self):
        """Save scan results in specified formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in self.output_formats:
            if fmt.lower() == 'json':
                filename = f"reports/scan_results_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
                logger.info(f"JSON report saved to {filename}")
            
            elif fmt.lower() == 'html':
                filename = f"reports/scan_results_{timestamp}.html"
                html_content = generate_html_report(self.results)
                with open(filename, 'w') as f:
                    f.write(html_content)
                logger.info(f"HTML report saved to {filename}")
        
        # Also save as scan_results.json/html (latest)
        if 'json' in [f.lower() for f in self.output_formats]:
            with open("reports/scan_results.json", 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
        
        if 'html' in [f.lower() for f in self.output_formats]:
            html_content = generate_html_report(self.results)
            with open("reports/scan_results.html", 'w') as f:
                f.write(html_content)
