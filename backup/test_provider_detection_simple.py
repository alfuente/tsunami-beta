#!/usr/bin/env python3
"""
Simple test script for provider detection improvements (without Neo4j).
This script tests the enhanced provider detection functionality.
"""

import sys
import os
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')

def test_provider_detection_functions():
    """Test provider detection functions directly."""
    print("🧪 Testing Provider Detection Functions")
    print("=" * 60)
    
    # Test imports
    try:
        from risk_loader_advanced3 import detect_cloud_provider_by_ip, get_cloud_provider_info
        print("✅ Successfully imported detection functions")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return
    
    # Test IPs with known providers
    test_ips = [
        ("8.8.8.8", "Google DNS - should detect GCP"),
        ("1.1.1.1", "Cloudflare DNS - should detect Cloudflare"), 
        ("208.67.222.222", "OpenDNS - should detect unknown or OpenDNS"),
        ("192.168.1.1", "Private IP - should detect unknown")
    ]
    
    print("\n🔍 Testing provider detection without token:")
    for ip, description in test_ips:
        print(f"\n--- Testing {ip} ({description}) ---")
        
        try:
            # Test detection
            provider = detect_cloud_provider_by_ip(ip)
            print(f"Provider detected: {provider}")
            
            # Test detailed info
            cloud_info = get_cloud_provider_info(ip)
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
    
    # Test with token if available
    token = os.environ.get('IPINFO_TOKEN')
    if token:
        print(f"\n🔑 Testing with IPInfo token (first 10 chars: {token[:10]}...):")
        
        test_ip = "8.8.8.8"
        try:
            provider = detect_cloud_provider_by_ip(test_ip, token)
            print(f"Provider for {test_ip} with token: {provider}")
            
            cloud_info = get_cloud_provider_info(test_ip, token)
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
    
    print("\n✅ Provider detection function test completed!")

if __name__ == "__main__":
    test_provider_detection_functions()