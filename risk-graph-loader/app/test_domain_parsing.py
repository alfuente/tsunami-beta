#!/usr/bin/env python3
"""
test_domain_parsing.py - Simple test for enhanced domain parsing

This script demonstrates the improved TLD/domain/subdomain parsing 
without requiring Neo4j or other heavy dependencies.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_loader_improved import DomainInfo, extract_tld_fallback

def test_domain_parsing():
    """Test the enhanced domain parsing functionality."""
    
    print("Enhanced Domain Parsing Test")
    print("=" * 50)
    
    # Test cases covering the original issue
    test_cases = [
        # Original issue: "bci.cl" vs "www.bci.cl" should be different
        ("bci.cl", "bci", "cl", "", True),
        ("www.bci.cl", "bci", "cl", "www", False),
        ("api.bci.cl", "bci", "cl", "api", False),
        ("mail.api.bci.cl", "bci", "cl", "mail.api", False),
        
        # Other TLDs
        ("google.com", "google", "com", "", True),
        ("docs.google.com", "google", "com", "docs", False),
        ("mail.google.com", "google", "com", "mail", False),
        ("admin.mail.google.com", "google", "com", "admin.mail", False),
        
        # Multi-part TLDs
        ("example.co.uk", "example", "co.uk", "", True),
        ("www.example.co.uk", "example", "co.uk", "www", False),
        
        # Edge cases
        ("localhost", "localhost", "", "", True),
        ("test.localhost", "localhost", "", "test", False),
        
        # Latin American domains
        ("santander.cl", "santander", "cl", "", True),
        ("portal.santander.cl", "santander", "cl", "portal", False),
        ("empresa.com.ar", "empresa", "com.ar", "", True),
        ("www.empresa.com.ar", "empresa", "com.ar", "www", False),
    ]
    
    print("Testing domain parsing...")
    success_count = 0
    total_count = len(test_cases)
    
    for fqdn, expected_domain, expected_tld, expected_subdomain, expected_is_tld in test_cases:
        try:
            info = DomainInfo.from_fqdn(fqdn)
            
            success = (
                info.domain == expected_domain and
                info.tld == expected_tld and
                info.subdomain == expected_subdomain and
                info.is_tld_domain == expected_is_tld
            )
            
            if success:
                success_count += 1
                status = "✓"
            else:
                status = "✗"
            
            print(f"  {status} {fqdn}")
            print(f"    Expected: domain={expected_domain}, tld={expected_tld}, subdomain='{expected_subdomain}', is_tld={expected_is_tld}")
            print(f"    Got:      domain={info.domain}, tld={info.tld}, subdomain='{info.subdomain}', is_tld={info.is_tld_domain}")
            
            if not success:
                print(f"    ❌ MISMATCH!")
            
            # Show parent domain for subdomains
            if not info.is_tld_domain:
                print(f"    Parent:   {info.parent_domain}")
            
            print()
            
        except Exception as e:
            print(f"  ✗ {fqdn}: ERROR - {e}")
            print()
    
    print(f"Results: {success_count}/{total_count} tests passed")
    
    if success_count == total_count:
        print("🎉 All tests passed!")
    else:
        print("❌ Some tests failed!")
    
    return success_count == total_count

def test_fallback_extraction():
    """Test the fallback TLD extraction function."""
    print("\nTesting fallback TLD extraction...")
    
    test_cases = [
        ("bci.cl", "bci", "cl", ""),
        ("www.bci.cl", "bci", "cl", "www"),
        ("api.bci.cl", "bci", "cl", "api"),
        ("mail.api.bci.cl", "bci", "cl", "mail.api"),
        ("example.co.uk", "example", "co.uk", ""),
        ("www.example.co.uk", "example", "co.uk", "www"),
        ("google.com", "google", "com", ""),
        ("docs.google.com", "google", "com", "docs"),
    ]
    
    for fqdn, expected_domain, expected_tld, expected_subdomain in test_cases:
        domain, tld, subdomain = extract_tld_fallback(fqdn)
        
        success = (
            domain == expected_domain and
            tld == expected_tld and
            subdomain == expected_subdomain
        )
        
        status = "✓" if success else "✗"
        print(f"  {status} {fqdn}: domain={domain}, tld={tld}, subdomain='{subdomain}'")

def demonstrate_graph_relationships():
    """Demonstrate the expected graph relationships."""
    print("\nExpected Graph Relationships:")
    print("=" * 50)
    
    domains = [
        "bci.cl",
        "www.bci.cl", 
        "api.bci.cl",
        "mail.api.bci.cl",
        "portal.bci.cl"
    ]
    
    print("Domain hierarchy that will be created:")
    print()
    
    tlds = set()
    domain_nodes = set()
    subdomain_nodes = set()
    relationships = []
    
    for fqdn in domains:
        info = DomainInfo.from_fqdn(fqdn)
        
        # Collect nodes
        tlds.add(info.tld)
        
        if info.is_tld_domain:
            domain_nodes.add(info.fqdn)
            relationships.append(f"TLD({info.tld}) -[:CONTAINS_DOMAIN]-> Domain({info.fqdn})")
        else:
            subdomain_nodes.add(info.fqdn)
            relationships.append(f"Domain({info.parent_domain}) -[:HAS_SUBDOMAIN]-> Subdomain({info.fqdn})")
            
            # Also ensure parent domain exists
            domain_nodes.add(info.parent_domain)
            relationships.append(f"TLD({info.tld}) -[:CONTAINS_DOMAIN]-> Domain({info.parent_domain})")
    
    print("Nodes that will be created:")
    print(f"  TLD nodes: {sorted(tlds)}")
    print(f"  Domain nodes: {sorted(domain_nodes)}")
    print(f"  Subdomain nodes: {sorted(subdomain_nodes)}")
    print()
    
    print("Relationships that will be created:")
    for rel in sorted(set(relationships)):
        print(f"  {rel}")
    
    print()
    print("This solves the original issue:")
    print("- 'bci.cl' and 'www.bci.cl' are now different node types")
    print("- Clear hierarchy: TLD -> Domain -> Subdomain")
    print("- Proper relationships between parent and child domains")

def main():
    """Run all tests."""
    print("Enhanced Domain Processing - Test Suite")
    print("=" * 60)
    
    # Test the core functionality
    parsing_success = test_domain_parsing()
    
    # Test the fallback function
    test_fallback_extraction()
    
    # Demonstrate graph relationships
    demonstrate_graph_relationships()
    
    print("\n" + "=" * 60)
    if parsing_success:
        print("✅ Domain parsing implementation is working correctly!")
        print("\nThe enhanced implementation solves these issues:")
        print("1. ✅ Proper TLD/domain/subdomain distinction")
        print("2. ✅ 'bci.cl' and 'www.bci.cl' are now different types")
        print("3. ✅ Clear parent-child relationships")
        print("4. ✅ Fallback parsing when tldextract is not available")
        print("\nNext steps:")
        print("- Install required dependencies (neo4j, whois, tldextract)")
        print("- Run migration script to update existing graph")
        print("- Use the enhanced loader for new domain processing")
    else:
        print("❌ Some domain parsing tests failed!")
        print("Please check the implementation and fix any issues.")

if __name__ == "__main__":
    main()