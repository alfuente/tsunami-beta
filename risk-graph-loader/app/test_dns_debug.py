#!/usr/bin/env python3
"""
Test DNS resolution debug
"""

import dns.resolver
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def test_dns_direct():
    print("🧪 TESTING DNS RESOLUTION DIRECTLY")
    print("=" * 50)
    
    test_domain = 'www.bci.cl'
    
    # Test with dns.resolver directly
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 30
        
        print(f"\n1. DIRECT DNS RESOLUTION FOR {test_domain}:")
        answers = resolver.resolve(test_domain, 'A')
        a_records = [str(answer) for answer in answers]
        print(f"   A records: {a_records}")
        
    except Exception as e:
        print(f"   ❌ Direct DNS failed: {e}")
    
    # Test using the actual function from the script
    print(f"\n2. SCRIPT DNS FUNCTION TEST:")
    try:
        # Import the specific function
        from subdomain_relationship_discovery_v4 import EnhancedSubdomainGraphIngester
        
        # Just create a minimal instance to test DNS
        class TestDNS:
            def analyze_subdomain_dns(self, fqdn: str):
                dns_info = {
                    'a_records': [],
                    'aaaa_records': [],
                    'cname_records': [],
                    'mx_records': [],
                    'txt_records': [],
                    'ns_records': []
                }
                
                record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                resolver.lifetime = 30
                
                for record_type in record_types:
                    try:
                        answers = resolver.resolve(fqdn, record_type)
                        records = [str(answer) for answer in answers]
                        
                        if record_type == 'A':
                            dns_info['a_records'] = records
                        elif record_type == 'AAAA':
                            dns_info['aaaa_records'] = records
                        elif record_type == 'CNAME':
                            dns_info['cname_records'] = records
                        elif record_type == 'MX':
                            dns_info['mx_records'] = records
                        elif record_type == 'TXT':
                            dns_info['txt_records'] = records
                        elif record_type == 'NS':
                            dns_info['ns_records'] = records
                            
                    except dns.exception.DNSException:
                        pass  # Record type doesn't exist
                    except Exception as e:
                        print(f"DNS lookup failed for {fqdn} {record_type}: {e}")
                
                return dns_info
        
        test_dns = TestDNS()
        result = test_dns.analyze_subdomain_dns(test_domain)
        print(f"   DNS function result: {result}")
        print(f"   A records specifically: {result.get('a_records', [])}")
        
    except Exception as e:
        print(f"   ❌ Script DNS function failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_dns_direct()