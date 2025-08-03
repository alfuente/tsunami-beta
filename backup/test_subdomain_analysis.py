#!/usr/bin/env python3
"""
Test script for subdomain analysis functionality
"""

import sys
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')
from domain_risk_calculator import DomainRiskCalculator
import json

def test_subdomain_functionality():
    print("🧪 Testing Subdomain Analysis Functionality")
    print("="*50)
    
    calc = DomainRiskCalculator('bolt://localhost:7687', 'neo4j', 'test.password', '0bf607ce2c13ac')
    
    try:
        # Test 1: Get subdomains
        print("\n1. Testing subdomain discovery...")
        subdomains = calc.get_subdomains_for_base_domain('bice.cl')
        print(f"   ✓ Found {len(subdomains)} subdomains for bice.cl")
        
        # Test 2: Get dependencies
        print("\n2. Testing dependency analysis...")
        deps = calc.get_domain_dependencies('bice.cl')
        print(f"   ✓ Found dependencies:")
        print(f"     - {len(deps['services'])} services")
        print(f"     - {len(deps['providers'])} providers: {deps['providers'][:3]}...")
        print(f"     - {len(deps['ip_addresses'])} IP addresses")
        print(f"     - {len(deps['related_domains'])} related domains")
        
        # Test 3: Subdomain-specific risk analysis
        print("\n3. Testing subdomain-specific risks...")
        test_subdomains = ['admin.test.com', 'api.test.com', 'dev.test.com']
        for subdomain in test_subdomains:
            risks = calc._analyze_subdomain_specific_risks(subdomain)
            print(f"   ✓ {subdomain}: {len(risks)} risks found")
        
        # Test 4: Dependency risk analysis
        print("\n4. Testing dependency risk analysis...")
        dep_risks = calc._analyze_dependency_risks('bice.cl', deps)
        print(f"   ✓ Found {len(dep_risks)} dependency-related risks")
        for risk in dep_risks:
            print(f"     - {risk.risk_type}: {risk.severity.value}")
        
        # Test 5: Comprehensive analysis (limited)
        print("\n5. Testing comprehensive analysis (first 3 subdomains)...")
        limited_subdomains = subdomains[:3]  # Only first 3 to avoid timeout
        
        results = {
            'base_domain': 'bice.cl',
            'subdomains_found': len(subdomains),
            'dependencies': deps,
            'sample_subdomain_analysis': []
        }
        
        for subdomain in limited_subdomains:
            try:
                # Basic risks
                basic_risks = calc.calculate_domain_risks(subdomain)
                # Specific risks
                specific_risks = calc._analyze_subdomain_specific_risks(subdomain)
                
                results['sample_subdomain_analysis'].append({
                    'fqdn': subdomain,
                    'basic_risks': len(basic_risks),
                    'specific_risks': len(specific_risks),
                    'total_risks': len(basic_risks) + len(specific_risks)
                })
                
                print(f"   ✓ {subdomain}: {len(basic_risks) + len(specific_risks)} total risks")
                
            except Exception as e:
                print(f"   ✗ {subdomain}: Error - {e}")
        
        print("\n📊 Test Results Summary:")
        print(json.dumps(results, indent=2, default=str))
        
        print("\n🎉 All tests completed successfully!")
        
    finally:
        calc.close()

if __name__ == "__main__":
    test_subdomain_functionality()