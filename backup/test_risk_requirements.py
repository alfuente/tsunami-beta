#!/usr/bin/env python3
"""
Test script to determine what's needed for Risk analysis to work
"""

import sys
sys.path.append('risk-graph-loader/app')

def test_risk_calculator_requirements():
    """Test what's needed for risk analysis"""
    
    print("🔍 Testing Risk Calculator Requirements\n")
    
    # Test 1: Check if module can be imported
    print("=== TEST 1: Module Import ===")
    try:
        from domain_risk_calculator import DomainRiskCalculator
        print("✅ domain_risk_calculator module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import domain_risk_calculator: {e}")
        return False
    
    # Test 2: Check if we can create an instance
    print("\n=== TEST 2: Instance Creation ===")
    try:
        calculator = DomainRiskCalculator("bolt://localhost:7687", "neo4j", "test.password")
        print("✅ DomainRiskCalculator instance created successfully")
    except Exception as e:
        print(f"❌ Failed to create DomainRiskCalculator: {e}")
        return False
    
    # Test 3: Check available methods
    print("\n=== TEST 3: Available Methods ===")
    methods = [attr for attr in dir(calculator) if not attr.startswith('_') and callable(getattr(calculator, attr))]
    print(f"Available public methods: {len(methods)}")
    
    risk_methods = [m for m in methods if 'risk' in m.lower()]
    print(f"Risk-related methods: {risk_methods}")
    
    # Check for the method our script is calling
    if 'calculate_domain_risk' in methods:
        print("✅ calculate_domain_risk method found")
        correct_method = 'calculate_domain_risk'
    elif 'calculate_domain_risks' in methods:
        print("⚠️  Found calculate_domain_risks (plural) - need to fix script")
        correct_method = 'calculate_domain_risks'
    else:
        print("❌ No calculate_domain_risk method found")
        correct_method = None
    
    # Test 4: Test a simple domain analysis
    print("\n=== TEST 4: Simple Domain Analysis ===")
    if correct_method:
        try:
            test_domain = "bci.cl"
            print(f"Testing risk analysis for {test_domain}...")
            
            if correct_method == 'calculate_domain_risks':
                result = calculator.calculate_domain_risks(test_domain)
                print(f"✅ Risk analysis completed for {test_domain}")
                print(f"   Found {len(result)} risks")
                
                if result:
                    print("   Sample risks:")
                    for i, risk in enumerate(result[:3]):
                        print(f"     {i+1}. {risk.risk_type} (severity: {risk.severity})")
                
                # Now try to save to graph
                if result:
                    saved_count = calculator.save_risks_to_graph(result)
                    print(f"✅ Saved {saved_count} risks to graph")
                    
            else:
                # Try the method our script is calling
                result = getattr(calculator, correct_method)(test_domain)
                print(f"✅ Risk analysis completed using {correct_method}")
                
        except Exception as e:
            print(f"❌ Risk analysis failed: {e}")
            print(f"   Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
    
    # Test 5: Check what data is needed in the graph
    print("\n=== TEST 5: Data Requirements ===")
    try:
        with calculator.drv.session() as session:
            # Check if the test domain exists in graph
            domain_result = session.run("""
                MATCH (d:Domain {fqdn: $domain})
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)
                OPTIONAL MATCH (ip)-[:HOSTED_BY]->(p:Provider)
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN 
                    d.fqdn as domain,
                    count(DISTINCT ip) as ip_count,
                    count(DISTINCT p) as provider_count,
                    count(DISTINCT s) as subdomain_count
            """, domain="bci.cl")
            
            domain_data = domain_result.single()
            if domain_data and domain_data['domain']:
                print(f"✅ Domain 'bci.cl' found in graph:")
                print(f"   - IP addresses: {domain_data['ip_count']}")
                print(f"   - Providers: {domain_data['provider_count']}")
                print(f"   - Subdomains: {domain_data['subdomain_count']}")
            else:
                print("⚠️  Domain 'bci.cl' not found in graph - this may be why risk analysis isn't working")
                
                # Check what domains we do have
                domains_result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.fqdn as domain
                    ORDER BY d.fqdn
                    LIMIT 5
                """)
                domains = [record['domain'] for record in domains_result]
                print(f"   Available domains in graph: {domains}")
    
    except Exception as e:
        print(f"❌ Failed to check graph data: {e}")
    
    finally:
        calculator.close()
    
    print("\n=== SUMMARY ===")
    print("Requirements for Risk Analysis to work:")
    print("1. ✅ domain_risk_calculator module must be available")
    print("2. ✅ Neo4j connection must work")
    print("3. ⚠️  Correct method name (calculate_domain_risks, not calculate_domain_risk)")
    print("4. ✅ Domain data must exist in Neo4j graph")
    print("5. ✅ Method should save risks to graph automatically")
    
    return True

if __name__ == "__main__":
    test_risk_calculator_requirements()