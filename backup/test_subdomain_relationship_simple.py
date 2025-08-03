#!/usr/bin/env python3
"""
Simple test for subdomain relationship discovery improvements (without Neo4j).
This script tests the enhanced provider detection functionality.
"""

import sys
import os
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')

def test_enhanced_domain_info():
    """Test EnhancedDomainInfo functionality."""
    print("🧪 Testing EnhancedDomainInfo Class")
    print("=" * 50)
    
    try:
        from subdomain_relationship_discovery import EnhancedDomainInfo
        print("✅ Successfully imported EnhancedDomainInfo")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return
    
    # Test domain classification
    test_domains = [
        "google.com",
        "mail.google.com", 
        "api.subdomain.google.com",
        "cloudflare.com",
        "www.cloudflare.com",
        "deep.nested.subdomain.example.com"
    ]
    
    input_domains = {"google.com", "cloudflare.com", "example.com"}
    
    print("\n📋 Testing domain classification:")
    for domain in test_domains:
        try:
            domain_info = EnhancedDomainInfo.from_fqdn(domain, input_domains)
            print(f"\n--- {domain} ---")
            print(f"  FQDN: {domain_info.fqdn}")
            print(f"  Domain: {domain_info.domain}")
            print(f"  TLD: {domain_info.tld}")
            print(f"  Subdomain: {domain_info.subdomain}")
            print(f"  Is TLD domain: {domain_info.is_tld_domain}")
            print(f"  Base domain: {domain_info.base_domain}")
            print(f"  Parent domain: {domain_info.parent_domain}")
            print(f"  Is input domain: {domain_info.is_input_domain}")
        except Exception as e:
            print(f"❌ Error processing {domain}: {e}")
    
    print("\n✅ EnhancedDomainInfo test completed!")

def test_provider_detection_functions():
    """Test provider detection functions directly."""
    print("\n🔍 Testing Provider Detection Functions")
    print("=" * 50)
    
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
        ("208.67.222.222", "OpenDNS - should detect unknown"),
        ("192.168.1.1", "Private IP - should detect unknown")
    ]
    
    print("\n🔍 Testing provider detection:")
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
    
    print("\n✅ Provider detection function test completed!")

def test_relationship_info():
    """Test RelationshipInfo functionality."""
    print("\n🔗 Testing RelationshipInfo Class")
    print("=" * 50)
    
    try:
        from subdomain_relationship_discovery import RelationshipInfo
        print("✅ Successfully imported RelationshipInfo")
        
        # Test relationship creation
        rel_info = RelationshipInfo(
            source_fqdn="api.example.com",
            target_fqdn="example.com",
            relationship_type="SUBDOMAIN_OF",
            metadata={"discovered_at": "2025-07-10", "confidence": "high"}
        )
        
        print(f"✅ Created relationship: {rel_info.source_fqdn} --{rel_info.relationship_type}--> {rel_info.target_fqdn}")
        print(f"   Metadata: {rel_info.metadata}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error creating relationship: {e}")
    
    print("\n✅ RelationshipInfo test completed!")

if __name__ == "__main__":
    test_enhanced_domain_info()
    test_provider_detection_functions()
    test_relationship_info()
    
    print("\n🎉 All tests completed!")
    print("Check subdomain_relationship_discovery.log for detailed logs.")