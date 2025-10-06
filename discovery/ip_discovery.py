import re
import subprocess
import requests
from pathlib import Path
from typing import List, Set

def extract_ips_from_file(file_path: str) -> List[str]:
    """Extract IPs from text files"""
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = []
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            ips = ip_pattern.findall(content)
    except FileNotFoundError:
        print(f"File {file_path} not found")
    
    return list(set(ips))

def extract_ips_from_logs(log_paths: List[str]) -> List[str]:
    """Extract IPs from log files"""
    return extract_ips_from_file(log_paths[0]) if log_paths else []

def fetch_threat_feed_ips() -> List[str]:
    """Get IPs from known threat feeds"""
    threat_ips = []
    
    feeds = [
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "https://urlhaus.abuse.ch/downloads/csv/"
    ]
    
    for feed_url in feeds:
        try:
            response = requests.get(feed_url, timeout=10)
            if response.status_code == 200:
                # Extract IPs from response
                ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                ips = ip_pattern.findall(response.text)
                threat_ips.extend(ips)
        except Exception as e:
            print(f"Error fetching {feed_url}: {e}")
    
    return list(set(threat_ips))

def scan_local_network(network_range: str) -> List[str]:
    """Basic network discovery (requires nmap)"""
    try:
        cmd = f"nmap -sn {network_range}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            return list(set(ip_pattern.findall(result.stdout)))
    except Exception as e:
        print(f"Network scan failed: {e}")
    
    return []

def discover_ips(sources: dict) -> List[str]:
    """Discover IPs from multiple sources"""
    all_ips = []
    
    if sources.get('files'):
        for file_path in sources['files']:
            all_ips.extend(extract_ips_from_logs([file_path]))
    
    if sources.get('network_ranges'):
        for network in sources['network_ranges']:
            all_ips.extend(scan_local_network(network))
    
    if sources.get('threat_feeds'):
        all_ips.extend(fetch_threat_feed_ips())
    
    return list(set(all_ips))
