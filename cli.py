#!/usr/bin/env python3
"""
Sud0Hunt - Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter
Author: sud0x.dev@proton.me
License: MIT
"""

from version import get_version_info, print_version

import argparse
import asyncio
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from core.scanner import Scanner
from core.utils import setup_logging, validate_targets

console = Console()

def print_banner():
    """Print the Sud0Hunt ASCII banner"""
    ascii_art = """
███████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔════╝██║   ██║██╔══██╗██╔═████╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████╗██║   ██║██║  ██║██║██╔██║███████║██║   ██║██╔██╗ ██║   ██║   
╚════██║██║   ██║██║  ██║████╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   
███████║╚██████╔╝██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
                                                                        """
    
    # Create styled text components
    banner_text = Text()
    banner_text.append(ascii_art + "\n\n", style="bright_red")
    banner_text.append("    Advanced Automated Bug Bounty Reconnaissance & Vulnerability Hunter\n", style="bold red")
    banner_text.append("    Author: sud0x.dev@proton.me | License: MIT", style="dim")
    
    console.print(Panel(
        banner_text,
        border_style="bright_red",
        padding=(1, 2)
    ))

def create_parser():
    """Create and configure argument parser with professional formatting"""
    
    # Custom formatter for better alignment
    class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action_invocation(self, action):
            if not action.option_strings:
                metavar, = self._metavar_formatter(action, action.dest)(1)
                return metavar
            else:
                parts = []
                if action.nargs == 0:
                    parts.extend(action.option_strings)
                else:
                    default = action.dest.upper()
                    args_string = self._format_args(action, default)
                    for option_string in action.option_strings:
                        parts.append('%s %s' % (option_string, args_string))
                return ', '.join(parts)
    
    parser = argparse.ArgumentParser(
        prog='Sud0Hunt',
        description='Sud0Hunt v1.0.0 - Advanced Bug Bounty Reconnaissance Tool',
        formatter_class=CustomHelpFormatter,
        add_help=False,  # Custom help handling
        epilog="""
Examples:
  python cli.py -t example.com --full-scan
  python cli.py -t example.com,test.com --subdomain-enum --port-scan
  python cli.py -t example.com --vuln-scan -o json,html --threads 50
  python cli.py -t target.com --quick --fast -o json
  python cli.py -t example.com --security-checks --timeout 10

More info: github.com/Sud0-x/Sud0Hunt • Contact: sud0x.dev@proton.me
        """
    )
    
    # Global options (shown first in help)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                       help='Show this help message and exit')
    parser.add_argument('--version', action='store_true',
                       help='Show program version and exit')
    
    # Required target specification
    parser.add_argument('-t', '--targets', required=True, metavar='TARGETS',
                       help='Comma-separated list of target domains')
    
    # Scan Options Group
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--full-scan', action='store_true',
                           help='Run all scan modules (comprehensive)')
    scan_group.add_argument('--subdomain-enum', action='store_true',
                           help='Enumerate subdomains only')
    scan_group.add_argument('--port-scan', action='store_true',
                           help='Scan ports and services only')
    scan_group.add_argument('--vuln-scan', action='store_true',
                           help='Detect vulnerabilities only')
    scan_group.add_argument('--tech-detect', action='store_true',
                           help='Identify technologies only')
    scan_group.add_argument('--security-checks', action='store_true',
                           help='Perform security checks only')
    
    # Output Options Group
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default='json', metavar='FORMAT',
                             help='Output format: json,html (default: json)')
    output_group.add_argument('--no-terminal', action='store_true',
                             help='Disable terminal output, save to file only')
    
    # Performance Options Group
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--threads', type=int, default=50, metavar='N',
                           help='Number of concurrent threads (default: 50)')
    perf_group.add_argument('--timeout', type=int, default=5, metavar='SEC',
                           help='Request timeout in seconds (default: 5)')
    perf_group.add_argument('--fast', action='store_true',
                           help='Fast mode with reduced accuracy')
    perf_group.add_argument('--quick', action='store_true',
                           help='Quick scan of common targets only')
    
    return parser

def print_summary_table(results):
    """Print summary results table"""
    table = Table(title="🎯 Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", justify="right", style="green")
    table.add_column("Details", style="yellow")
    
    # Subdomains
    subdomains = results.get('subdomains', [])
    table.add_row("Subdomains", str(len(subdomains)), f"{len([s for s in subdomains if s.get('alive')])} alive")
    
    # Ports
    ports = results.get('ports', [])
    open_ports = [p for p in ports if p.get('status') == 'open']
    table.add_row("Open Ports", str(len(open_ports)), f"Across {len(set(p.get('host') for p in open_ports))} hosts")
    
    # Vulnerabilities
    vulns = results.get('vulnerabilities', [])
    critical = len([v for v in vulns if v.get('severity') == 'critical'])
    high = len([v for v in vulns if v.get('severity') == 'high'])
    table.add_row("Vulnerabilities", str(len(vulns)), f"{critical} critical, {high} high")
    
    # Technologies
    tech = results.get('technologies', [])
    table.add_row("Technologies", str(len(tech)), f"{len(set(t.get('name') for t in tech))} unique")
    
    console.print(table)

def print_detailed_results(results):
    """Print detailed scan results"""
    # Subdomains section
    if results.get('subdomains'):
        console.print("\n[bold blue]🌐 Discovered Subdomains[/bold blue]")
        subdomain_table = Table(show_header=True, header_style="bold blue")
        subdomain_table.add_column("Subdomain", style="cyan")
        subdomain_table.add_column("Status", style="green")
        subdomain_table.add_column("IP Address", style="yellow")
        
        for subdomain in results['subdomains'][:20]:  # Show top 20
            status = "✅ Alive" if subdomain.get('alive') else "❌ Dead"
            subdomain_table.add_row(
                subdomain.get('domain', ''),
                status,
                subdomain.get('ip', 'N/A')
            )
        
        console.print(subdomain_table)
        if len(results['subdomains']) > 20:
            console.print(f"[dim]... and {len(results['subdomains']) - 20} more subdomains[/dim]")
    
    # Open Ports section
    if results.get('ports'):
        console.print("\n[bold green]🔌 Open Ports & Services[/bold green]")
        port_table = Table(show_header=True, header_style="bold green")
        port_table.add_column("Host", style="cyan")
        port_table.add_column("Port", style="yellow")
        port_table.add_column("Service", style="green")
        port_table.add_column("Banner/Version", style="white")
        
        for port_info in results['ports']:
            port_table.add_row(
                port_info.get('host', 'N/A'),
                str(port_info.get('port', 'N/A')),
                port_info.get('service', 'unknown'),
                port_info.get('banner', 'No banner')[:80] + "..." if len(port_info.get('banner', '')) > 80 else port_info.get('banner', 'No banner')
            )
        
        console.print(port_table)
    
    # Vulnerabilities section
    if results.get('vulnerabilities'):
        console.print("\n[bold red]🚨 Detected Vulnerabilities[/bold red]")
        vuln_table = Table(show_header=True, header_style="bold red")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Type", style="cyan")
        vuln_table.add_column("Target", style="yellow")
        vuln_table.add_column("Description", style="white")
        
        for vuln in results['vulnerabilities']:
            severity_color = {
                'critical': 'bright_red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green'
            }.get(vuln.get('severity', 'low'), 'white')
            
            vuln_table.add_row(
                f"[{severity_color}]{vuln.get('severity', '').upper()}[/{severity_color}]",
                vuln.get('type', ''),
                vuln.get('target', ''),
                vuln.get('description', '')[:60] + "..." if len(vuln.get('description', '')) > 60 else vuln.get('description', '')
            )
        
        console.print(vuln_table)
        
        # Show exploit suggestions for high severity vulnerabilities
        high_vulns = [v for v in results['vulnerabilities'] if v.get('severity') in ['critical', 'high'] and v.get('exploit_suggestions')]
        if high_vulns:
            console.print("\n[bold yellow]💥 Exploit Suggestions (High/Critical Vulnerabilities)[/bold yellow]")
            for i, vuln in enumerate(high_vulns[:3], 1):  # Show top 3
                exploit_data = vuln.get('exploit_suggestions', {})
                console.print(f"\n[bold red]{i}. {vuln.get('type')}[/bold red] - {vuln.get('target')}")
                
                if exploit_data.get('exploitation_steps'):
                    console.print("[bold cyan]🎯 Exploitation Steps:[/bold cyan]")
                    for step in exploit_data['exploitation_steps']:
                        console.print(f"   {step}")
                
                if exploit_data.get('tools'):
                    console.print(f"[bold green]🔧 Recommended Tools:[/bold green] {', '.join(exploit_data['tools'])}")
                
                if exploit_data.get('references'):
                    console.print(f"[bold blue]📚 References:[/bold blue] {', '.join(exploit_data['references'][:2])}")

async def main():
    """Main application entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle version request
    if args.version:
        print_version()
        sys.exit(0)
    
    # Print banner unless no-terminal is specified
    if not args.no_terminal:
        print_banner()
    
    # Validate targets
    targets = [t.strip() for t in args.targets.split(',')]
    valid_targets = validate_targets(targets)
    
    if not valid_targets:
        console.print("[red]❌ No valid targets provided![/red]")
        sys.exit(1)
    
    # Setup logging
    setup_logging()
    
    # Determine which scans to run
    scan_types = []
    if args.full_scan:
        scan_types = ['subdomain_enum', 'port_scan', 'vuln_scan', 'tech_detect', 'security_checks']
    else:
        if args.subdomain_enum:
            scan_types.append('subdomain_enum')
        if args.port_scan:
            scan_types.append('port_scan')
        if args.vuln_scan:
            scan_types.append('vuln_scan')
        if args.tech_detect:
            scan_types.append('tech_detect')
        if getattr(args, 'security_checks', False):
            scan_types.append('security_checks')
    
    if not scan_types:
        console.print("[yellow]⚠️  No scan types specified. Use --full-scan or specify individual scans.[/yellow]")
        sys.exit(1)
    
    # Initialize scanner
    scanner = Scanner(
        targets=valid_targets,
        threads=args.threads,
        timeout=args.timeout,
        output_formats=args.output.split(','),
        no_terminal=args.no_terminal
    )
    
    # Run scans
    if not args.no_terminal:
        console.print(f"\n[bold green]🎯 Starting scan on {len(valid_targets)} target(s)[/bold green]")
        console.print(f"[dim]Targets: {', '.join(valid_targets)}[/dim]")
        console.print(f"[dim]Scans: {', '.join(scan_types)}[/dim]\n")
    
    start_time = time.time()
    
    try:
        results = await scanner.run_scans(scan_types)
        
        if not args.no_terminal:
            console.print(f"\n[bold green]✅ Scan completed in {time.time() - start_time:.2f} seconds[/bold green]")
            
            # Print results
            print_summary_table(results)
            print_detailed_results(results)
            
            # Print report locations
            console.print(f"\n[bold blue]📄 Reports saved to:[/bold blue]")
            for fmt in args.output.split(','):
                console.print(f"  • {fmt.upper()}: reports/scan_results.{fmt}")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]❌ Error during scan: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
