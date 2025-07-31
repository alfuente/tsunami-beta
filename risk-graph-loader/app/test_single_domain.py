#!/usr/bin/env python3
"""
Test script para analizar un solo dominio y ver qué está pasando con services/providers
"""

import logging
import sys
from subdomain_relationship_discovery_v4 import EnhancedSubdomainGraphIngester

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_single_domain():
    print("🧪 TESTING SINGLE DOMAIN ANALYSIS")
    print("=" * 50)
    
    # Initialize ingester
    ingester = EnhancedSubdomainGraphIngester(
        'bolt://localhost:7687',
        'neo4j', 
        'test.password',
        '0bf607ce2c13ac',
        enable_tls_analysis=True,
        enable_service_detection=True,
        enable_provider_detection=True,
        enable_industry_classification=True,
        max_analysis_workers=1
    )
    
    try:
        # Test specific domain
        test_fqdn = 'www.bci.cl'
        print(f"\n🔍 Analyzing: {test_fqdn}")
        
        # Test DNS resolution
        print("\n1. DNS RESOLUTION:")
        dns_info = ingester.analyze_subdomain_dns(test_fqdn)
        print(f"   Full DNS info: {dns_info}")
        print(f"   A records: {dns_info.get('a_records', [])}")
        print(f"   IP addresses field: {dns_info.get('ip_addresses', [])}")
        
        # Test TLS analysis
        print("\n2. TLS ANALYSIS:")
        tls_info = ingester.analyze_subdomain_tls(test_fqdn)
        if tls_info:
            print(f"   TLS found: {tls_info.get('subject', 'No subject')}")
        else:
            print("   No TLS info")
        
        # Test service/provider detection
        print("\n3. SERVICE/PROVIDER DETECTION:")
        ip_addresses = dns_info.get('a_records', [])  # Use a_records instead of ip_addresses
        print(f"   Using IPs: {ip_addresses}")
        services, providers = ingester.detect_enhanced_services_and_providers(test_fqdn, ip_addresses)
        
        print(f"   Services found: {len(services)}")
        for service in services:
            print(f"     - {service}")
        
        print(f"   Providers found: {len(providers)}")
        for provider in providers:
            print(f"     - {provider}")
        
        # Test industry classification
        print("\n4. INDUSTRY CLASSIFICATION:")
        try:
            industry_info = ingester.analyze_domain_industry(test_fqdn)
            if industry_info:
                print(f"   Industry: {industry_info}")
            else:
                print("   No industry classification")
        except Exception as e:
            print(f"   Industry classification error: {e}")
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        ingester.close()

if __name__ == "__main__":
    test_single_domain()