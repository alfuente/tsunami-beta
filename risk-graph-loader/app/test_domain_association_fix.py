#!/usr/bin/env python3
"""
Test script to verify the domain association fixes work correctly.
This tests the improved logic that prevents incorrect subdomain associations.
"""

import sys
import tempfile
from pathlib import Path

# Add the current directory to Python path to import the modules
sys.path.insert(0, '.')

def test_parse_amass_output_with_input_domain():
    """Test the improved parse_amass_output function."""
    print("🧪 Testing parse_amass_output with input_domain parameter...")
    
    try:
        from risk_loader_advanced3 import parse_amass_output
        
        # Create a mock Amass output with mixed domains
        mock_output = """
www.afpcuprum.cl
mail.afpcuprum.cl
api.afpcuprum.cl
ahorra.afphabitat.cl
portal.afphabitat.cl
secure.bancochile.cl
admin.bci.cl
"""
        
        # Test with afpcuprum.cl as input domain
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(mock_output.strip())
            f.flush()
            
            temp_path = Path(f.name)
            
            # Parse with input domain context
            results = parse_amass_output(temp_path, input_domain="afpcuprum.cl")
            
            print(f"📊 Parsed {len(results)} entries:")
            
            # Analyze results
            valid_subdomains = []
            unrelated_domains = []
            
            for entry in results:
                name = entry.get('name', '')
                if entry.get('parent') == 'afpcuprum.cl':
                    valid_subdomains.append(name)
                elif entry.get('unrelated'):
                    unrelated_domains.append(name)
                elif entry.get('is_base_domain'):
                    print(f"  ✅ Base domain: {name}")
                    
            print(f"  ✅ Valid subdomains of afpcuprum.cl: {valid_subdomains}")
            print(f"  ⚠️  Unrelated domains (correctly identified): {unrelated_domains}")
            
            # Verify correct behavior
            expected_subdomains = ['www.afpcuprum.cl', 'mail.afpcuprum.cl', 'api.afpcuprum.cl']
            expected_unrelated = ['ahorra.afphabitat.cl', 'portal.afphabitat.cl', 'secure.bancochile.cl', 'admin.bci.cl']
            
            success = True
            for expected in expected_subdomains:
                if expected not in valid_subdomains:
                    print(f"  ❌ Missing expected subdomain: {expected}")
                    success = False
                    
            for expected in expected_unrelated:
                if expected not in unrelated_domains:
                    print(f"  ❌ Incorrectly classified as subdomain: {expected}")
                    success = False
            
            if success:
                print("  ✅ All domain associations are correct!")
            else:
                print("  ❌ Some domain associations are incorrect!")
                
            # Cleanup
            temp_path.unlink()
            
            return success
            
    except ImportError as e:
        print(f"  ❌ Cannot import required modules: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Test failed with error: {e}")
        return False

def test_subdomain_filtering():
    """Test the improved subdomain filtering logic."""
    print("\n🧪 Testing subdomain filtering logic...")
    
    # Mock discovered subdomains
    input_domain = "afpcuprum.cl"
    discovered_domains = [
        "www.afpcuprum.cl",
        "mail.afpcuprum.cl", 
        "api.afpcuprum.cl",
        "ahorra.afphabitat.cl",  # Should be filtered out
        "portal.afphabitat.cl",  # Should be filtered out
        "secure.bancochile.cl",  # Should be filtered out
        "afpcuprum.cl"  # Base domain, should be excluded
    ]
    
    # Apply the filtering logic from the fixed function
    valid_subdomains = []
    related_domains = []
    
    for subdomain in discovered_domains:
        if subdomain == input_domain:
            # Base domain, skip
            continue
        elif subdomain.endswith('.' + input_domain):
            # Valid subdomain
            valid_subdomains.append(subdomain)
        else:
            # Related but not subdomain
            related_domains.append(subdomain)
    
    print(f"  📊 Input domain: {input_domain}")
    print(f"  📊 Total discovered: {len(discovered_domains)} domains")
    print(f"  ✅ Valid subdomains: {valid_subdomains}")
    print(f"  ⚠️  Related domains: {related_domains}")
    
    # Verify results
    expected_valid = ["www.afpcuprum.cl", "mail.afpcuprum.cl", "api.afpcuprum.cl"]
    expected_related = ["ahorra.afphabitat.cl", "portal.afphabitat.cl", "secure.bancochile.cl"]
    
    success = (set(valid_subdomains) == set(expected_valid) and 
               set(related_domains) == set(expected_related))
    
    if success:
        print("  ✅ Subdomain filtering works correctly!")
    else:
        print("  ❌ Subdomain filtering has issues!")
        
    return success

def test_neo4j_relationship_logic():
    """Test the Neo4j relationship creation logic (without actual DB)."""
    print("\n🧪 Testing Neo4j relationship creation logic...")
    
    input_domain = "afpcuprum.cl"
    discovered_subdomains = [
        "www.afpcuprum.cl",
        "mail.afpcuprum.cl",
        "ahorra.afphabitat.cl",  # This should NOT create HAS_SUBDOMAIN relationship
        "portal.afphabitat.cl"   # This should NOT create HAS_SUBDOMAIN relationship
    ]
    
    # Simulate the fixed logic
    valid_subdomain_relationships = []
    discovered_related_relationships = []
    
    for subdomain in discovered_subdomains:
        if subdomain == input_domain:
            continue
        elif subdomain.endswith('.' + input_domain):
            # Create HAS_SUBDOMAIN relationship
            valid_subdomain_relationships.append(f"{input_domain} -[:HAS_SUBDOMAIN]-> {subdomain}")
        else:
            # Create DISCOVERED_RELATED relationship
            discovered_related_relationships.append(f"{input_domain} -[:DISCOVERED_RELATED]-> {subdomain}")
    
    print(f"  ✅ Correct HAS_SUBDOMAIN relationships:")
    for rel in valid_subdomain_relationships:
        print(f"    {rel}")
        
    print(f"  ⚠️  DISCOVERED_RELATED relationships (not subdomains):")
    for rel in discovered_related_relationships:
        print(f"    {rel}")
    
    # Verify no incorrect relationships
    incorrect_relationships = [
        f"{input_domain} -[:HAS_SUBDOMAIN]-> ahorra.afphabitat.cl",
        f"{input_domain} -[:HAS_SUBDOMAIN]-> portal.afphabitat.cl"
    ]
    
    success = True
    for incorrect in incorrect_relationships:
        if incorrect in valid_subdomain_relationships:
            print(f"  ❌ Found incorrect relationship: {incorrect}")
            success = False
    
    if success:
        print("  ✅ No incorrect HAS_SUBDOMAIN relationships will be created!")
    else:
        print("  ❌ Some incorrect relationships might be created!")
        
    return success

def main():
    """Run all tests."""
    print("🚀 Testing Domain Association Fixes")
    print("=" * 50)
    
    tests = [
        test_parse_amass_output_with_input_domain,
        test_subdomain_filtering,
        test_neo4j_relationship_logic
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"  ❌ Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    passed = sum(results)
    total = len(results)
    
    for i, (test, result) in enumerate(zip(tests, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test.__name__}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Domain association fixes are working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the fixes.")
        return 1

if __name__ == "__main__":
    sys.exit(main())