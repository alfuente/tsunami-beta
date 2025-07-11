#!/usr/bin/env python3
"""
Test script for provider detection improvements.
This script tests the enhanced provider detection functionality.
"""

import sys
import os
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')

from risk_loader_two_phase import TwoPhaseGraphIngester
import logging

# Test domains with known providers
TEST_DOMAINS = [
    "google.com",      # Should detect GCP
    "amazon.com",      # Should detect AWS
    "microsoft.com",   # Should detect Azure
    "cloudflare.com",  # Should detect Cloudflare
    "github.com",      # Should detect GitHub
    "akamai.com",      # Should detect Akamai
    "nonexistent-domain-12345.com"  # Should be unknown
]

def test_provider_detection():
    """Test provider detection with various domains."""
    print("🧪 Testing Provider Detection Improvements")
    print("=" * 60)
    
    # Create ingester without credentials (will show warnings)
    print("\n1. Testing without IPInfo token (should show warnings):")
    ingester = TwoPhaseGraphIngester(
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j", 
        neo4j_pass="test"
    )
    
    print("\n2. Testing DNS resolution and provider detection:")
    for domain in TEST_DOMAINS:
        print(f"\n--- Testing {domain} ---")
        try:
            # Test DNS resolution
            from risk_loader_two_phase import dns_query
            ips = dns_query(domain, "A")
            
            if ips:
                print(f"✓ Resolved {domain} to {len(ips)} IPs: {ips[:3]}...")
                
                # Test provider detection for first IP
                ip = ips[0]
                provider = ingester.detect_cloud_provider_by_ip(ip)
                cloud_info = ingester.get_cloud_provider_info(ip)
                
                print(f"🔍 Provider for {ip}: {provider}")
                if cloud_info:
                    print(f"📊 Detection method: {cloud_info.get('detection_method', 'unknown')}")
                    if cloud_info.get('warnings'):
                        print(f"⚠️  Warnings: {cloud_info['warnings']}")
                else:
                    print("❌ No cloud info available")
            else:
                print(f"❌ Could not resolve {domain}")
                
        except Exception as e:
            print(f"❌ Error testing {domain}: {e}")
    
    print("\n3. Testing with IPInfo token (if available):")
    token = os.environ.get('IPINFO_TOKEN')
    if token:
        print("✓ IPInfo token found in environment")
        ingester_with_token = TwoPhaseGraphIngester(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j", 
            neo4j_pass="test",
            ipinfo_token=token
        )
        
        # Test one domain with token
        test_ip = "8.8.8.8"  # Google DNS
        provider = ingester_with_token.detect_cloud_provider_by_ip(test_ip)
        cloud_info = ingester_with_token.get_cloud_provider_info(test_ip)
        
        print(f"🔍 Provider for {test_ip} with token: {provider}")
        if cloud_info:
            print(f"📊 Detection method: {cloud_info.get('detection_method', 'unknown')}")
            print(f"📍 Organization: {cloud_info.get('organization', 'unknown')}")
    else:
        print("❌ No IPInfo token found in IPINFO_TOKEN environment variable")
    
    print("\n✅ Provider detection test completed!")
    print("Check provider_detection.log for detailed logs.")

if __name__ == "__main__":
    test_provider_detection()