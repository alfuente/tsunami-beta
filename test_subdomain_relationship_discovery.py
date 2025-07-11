#!/usr/bin/env python3
"""
Test script for subdomain relationship discovery improvements.
This script tests the enhanced subdomain relationship discovery functionality.
"""

import sys
import os
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')

def test_subdomain_relationship_discovery():
    """Test subdomain relationship discovery configuration and functions."""
    print("🧪 Testing Subdomain Relationship Discovery Improvements")
    print("=" * 70)
    
    # Test imports
    try:
        from subdomain_relationship_discovery import EnhancedSubdomainGraphIngester
        print("✅ Successfully imported EnhancedSubdomainGraphIngester")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return
    
    print("\n1. Testing configuration check without credentials:")
    try:
        # This should show warnings but not fail
        discovery = EnhancedSubdomainGraphIngester(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j", 
            neo4j_pass="test"
        )
        print("✅ Configuration check completed successfully")
    except Exception as e:
        print(f"❌ Configuration check failed: {e}")
        return
    
    print("\n2. Testing provider detection functions:")
    
    # Test provider detection with various IPs
    test_ips = [
        ("8.8.8.8", "Google DNS - should detect GCP"),
        ("1.1.1.1", "Cloudflare DNS - should detect Cloudflare"), 
        ("208.67.222.222", "OpenDNS - should detect unknown"),
        ("192.168.1.1", "Private IP - should detect unknown")
    ]
    
    for ip, description in test_ips:
        print(f"\n--- Testing {ip} ({description}) ---")
        
        try:
            # Test detection
            provider = discovery.detect_cloud_provider_by_ip(ip)
            print(f"Provider detected: {provider}")
            
            # Test detailed info
            cloud_info = discovery.get_cloud_provider_info(ip)
            if cloud_info:
                print(f"Detection method: {cloud_info.get('detection_method', 'unknown')}")
                if cloud_info.get('warnings'):
                    print(f"Warnings: {cloud_info['warnings']}")
                if cloud_info.get('organization'):
                    print(f"Organization: {cloud_info['organization']}")
            else:
                print("No detailed cloud info available")
                
        except Exception as e:
            print(f"Error: {e}")
    
    print("\n3. Testing EnhancedDomainInfo class:")
    try:
        from subdomain_relationship_discovery import EnhancedDomainInfo
        
        # Test domain classification
        test_domains = [
            "google.com",
            "mail.google.com",
            "api.subdomain.google.com",
            "cloudflare.com",
            "www.cloudflare.com"
        ]
        
        input_domains = {"google.com", "cloudflare.com"}
        
        for domain in test_domains:
            domain_info = EnhancedDomainInfo.from_fqdn(domain, input_domains)
            print(f"Domain: {domain}")
            print(f"  Is TLD domain: {domain_info.is_tld_domain}")
            print(f"  Base domain: {domain_info.base_domain}")
            print(f"  Subdomain: {domain_info.subdomain}")
            print(f"  Parent domain: {domain_info.parent_domain}")
            print()
        
    except Exception as e:
        print(f"Error testing EnhancedDomainInfo: {e}")
    
    # Test with token if available
    token = os.environ.get('IPINFO_TOKEN')
    if token:
        print(f"\n4. Testing with IPInfo token (first 10 chars: {token[:10]}...):")
        
        try:
            discovery_with_token = EnhancedSubdomainGraphIngester(
                neo4j_uri="bolt://localhost:7687",
                neo4j_user="neo4j", 
                neo4j_pass="test",
                ipinfo_token=token
            )
            
            test_ip = "8.8.8.8"
            provider = discovery_with_token.detect_cloud_provider_by_ip(test_ip)
            print(f"Provider for {test_ip} with token: {provider}")
            
            cloud_info = discovery_with_token.get_cloud_provider_info(test_ip)
            if cloud_info:
                print(f"Detection method: {cloud_info.get('detection_method', 'unknown')}")
                print(f"Organization: {cloud_info.get('organization', 'unknown')}")
                if cloud_info.get('warnings'):
                    print(f"Warnings: {cloud_info['warnings']}")
            
        except Exception as e:
            print(f"Error with token: {e}")
    else:
        print("\n❌ No IPInfo token found in IPINFO_TOKEN environment variable")
        print("Set IPINFO_TOKEN environment variable to test with token")
    
    print("\n✅ Subdomain relationship discovery test completed!")
    print("Check subdomain_relationship_discovery.log for detailed logs.")

if __name__ == "__main__":
    test_subdomain_relationship_discovery()