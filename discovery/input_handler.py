import argparse
import sys
from typing import List
from discovery.ip_discovery import discover_ips, extract_ips_from_file

def parse_arguments():
    """Parse command line arguments for IP discovery"""
    parser = argparse.ArgumentParser(description="Advanced Threat Intelligence Tool")
    
    # Input methods
    parser.add_argument("--ips", nargs="+", help="Specific IPs to check")
    parser.add_argument("--file", help="File containing IPs (one per line)")
    parser.add_argument("--logs", nargs="+", help="Log files to extract IPs from")
    parser.add_argument("--network", help="Network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--feeds", action="store_true", help="Include threat feed IPs")
    
    return parser.parse_args()

def collect_ips(args) -> List[str]:
    """Collect IPs from all specified sources"""
    all_ips = []
    
    # Direct IP specification
    if args.ips:
        all_ips.extend(args.ips)
    
    # File input
    if args.file:
        file_ips = extract_ips_from_file(args.file)
        all_ips.extend(file_ips)
    
    # Log file extraction
    if args.logs:
        sources = {'files': args.logs}
        log_ips = discover_ips(sources)
        all_ips.extend(log_ips)
    
    # Network scanning
    if args.network:
        sources = {'network_ranges': [args.network]}
        network_ips = discover_ips(sources)
        all_ips.extend(network_ips)
    
    # Threat feeds
    if args.feeds:
        sources = {'threat_feeds': True}
        feed_ips = discover_ips(sources)
        all_ips.extend(feed_ips)
    
    # Remove duplicates and validate
    valid_ips = list(set(all_ips))
    return [ip for ip in valid_ips if is_valid_ip(ip)]

def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
