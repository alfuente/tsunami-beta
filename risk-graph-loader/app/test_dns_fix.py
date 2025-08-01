#!/usr/bin/env python3
"""
Test script to verify DNS record storage fix
"""

from neo4j import GraphDatabase
import sys

def test_dns_records(uri, user, password):
    """Test if DNS records are being stored properly"""
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    try:
        with driver.session() as session:
            # Test query that was failing
            print("Testing original query that was failing...")
            result = session.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                RETURN n.fqdn as fqdn, 
                       COALESCE(n.dns_cname_records, []) as cnames
                LIMIT 10
            """)
            
            records_found = 0
            cname_records_found = 0
            
            for record in result:
                records_found += 1
                fqdn = record["fqdn"]
                cnames = record["cnames"]
                
                print(f"Domain: {fqdn}")
                if cnames:
                    print(f"  CNAME records: {cnames}")
                    cname_records_found += 1
                else:
                    print(f"  No CNAME records")
                print()
            
            print(f"Summary:")
            print(f"- Total domains/subdomains checked: {records_found}")
            print(f"- Domains with CNAME records: {cname_records_found}")
            
            if records_found == 0:
                print("⚠️  No domains/subdomains found in database")
            else:
                print("✅ Query executed successfully - no property key warnings expected")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        driver.close()
    
    return True

def test_dns_properties(uri, user, password):
    """Check what DNS properties exist in the database"""
    
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    try:
        with driver.session() as session:
            print("\nChecking existing DNS properties...")
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.dns_a_records IS NOT NULL OR 
                      s.dns_cname_records IS NOT NULL OR
                      s.dns_mx_records IS NOT NULL
                RETURN s.fqdn as fqdn,
                       s.dns_a_records as a_records,
                       s.dns_cname_records as cname_records,
                       s.dns_mx_records as mx_records,
                       s.dns_analyzed_at as analyzed_at
                LIMIT 5
            """)
            
            dns_analyzed_count = 0
            for record in result:
                dns_analyzed_count += 1
                print(f"\nSubdomain: {record['fqdn']}")
                print(f"  A records: {record['a_records']}")
                print(f"  CNAME records: {record['cname_records']}")
                print(f"  MX records: {record['mx_records']}")
                print(f"  Analyzed at: {record['analyzed_at']}")
            
            if dns_analyzed_count == 0:
                print("⚠️  No subdomains with DNS analysis found")
                print("   This is expected if you haven't run the updated code yet")
            else:
                print(f"✅ Found {dns_analyzed_count} subdomains with DNS analysis")
                
    except Exception as e:
        print(f"❌ Error checking DNS properties: {e}")
        return False
    finally:
        driver.close()
    
    return True

if __name__ == "__main__":
    # Default Neo4j connection
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "test.password"
    
    if len(sys.argv) > 1:
        password = sys.argv[1]
    
    print("=== Testing DNS Records Fix ===")
    print(f"Connecting to: {uri}")
    print(f"User: {user}")
    print()
    
    success1 = test_dns_records(uri, user, password)
    success2 = test_dns_properties(uri, user, password)
    
    if success1 and success2:
        print("\n✅ All tests passed!")
        print("\nTo fix the original issue, re-run your subdomain discovery with the updated code.")
        print("The DNS records will be stored and the cross-domain relationship discovery will work.")
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)