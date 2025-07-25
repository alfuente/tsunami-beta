#!/usr/bin/env python3
"""
Test simple del fallback DNS sin neo4j
"""

import socket

def test_dns_fallback(domain):
    """Test simple DNS bruteforce."""
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "app", "cdn", "dev", "test", 
        "staging", "blog", "shop", "store", "support", "help", "docs"
    ]
    
    found_domains = []
    print(f"Testing {len(common_subs)} common subdomains for {domain}")
    
    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found_domains.append(subdomain)
            print(f"✓ {subdomain} -> {ip}")
        except socket.gaierror:
            pass  # Subdomain doesn't exist
    
    print(f"Found {len(found_domains)} subdomains for {domain}")
    return found_domains

if __name__ == "__main__":
    domains = ["bice.cl", "bci.cl", "example.com"]
    
    for domain in domains:
        print(f"\n=== Testing {domain} ===")
        results = test_dns_fallback(domain)
        if results:
            print(f"Success: {results}")
        else:
            print("No subdomains found")