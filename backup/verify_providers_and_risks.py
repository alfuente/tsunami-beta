#!/usr/bin/env python3
"""
Script to verify that Provider and Risk nodes were created in Neo4j
after running subdomain_relationship_discovery.py v2.0
"""

from neo4j import GraphDatabase
import json

def verify_database():
    """Connect to Neo4j and verify Provider and Risk nodes exist"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    try:
        with driver.session() as session:
            print("🔍 Verifying Neo4j database after subdomain_relationship_discovery.py v2.0 execution\n")
            
            # Check Provider nodes
            print("=== PROVIDER NODES ===")
            provider_result = session.run("""
                MATCH (p:Provider)
                RETURN p.name as provider_name, p.status as status, p.detection_method as detection_method
                ORDER BY p.name
                LIMIT 10
            """)
            
            providers = list(provider_result)
            print(f"Found {len(providers)} Provider nodes:")
            for provider in providers:
                print(f"  - {provider['provider_name']} (status: {provider['status']}, method: {provider['detection_method']})")
            
            # Count total providers
            total_providers = session.run("MATCH (p:Provider) RETURN count(p) as total").single()["total"]
            print(f"\nTotal Provider nodes: {total_providers}")
            
            # Check Risk nodes
            print("\n=== RISK NODES ===")
            risk_result = session.run("""
                MATCH (r:Risk)
                RETURN r.domain_fqdn as domain, r.severity as severity, r.score as score
                ORDER BY r.score DESC
                LIMIT 10
            """)
            
            risks = list(risk_result)
            print(f"Found {len(risks)} Risk nodes:")
            for risk in risks:
                print(f"  - {risk['domain']} (severity: {risk['severity']}, score: {risk['score']})")
            
            # Count total risks
            total_risks = session.run("MATCH (r:Risk) RETURN count(r) as total").single()["total"]
            print(f"\nTotal Risk nodes: {total_risks}")
            
            # Check Provider-Service relationships
            print("\n=== PROVIDER-SERVICE RELATIONSHIPS ===")
            provider_service_result = session.run("""
                MATCH (p:Provider)-[:PROVIDES]->(s:Service)
                RETURN p.name as provider, s.name as service, s.type as service_type
                LIMIT 5
            """)
            
            relationships = list(provider_service_result)
            print(f"Found {len(relationships)} Provider->Service relationships:")
            for rel in relationships:
                print(f"  - {rel['provider']} PROVIDES {rel['service']} ({rel['service_type']})")
            
            # Check IP-Provider relationships
            print("\n=== IP-PROVIDER RELATIONSHIPS ===")
            ip_provider_result = session.run("""
                MATCH (ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                RETURN ip.address as ip, p.name as provider
                LIMIT 5
            """)
            
            ip_relationships = list(ip_provider_result)
            print(f"Found {len(ip_relationships)} IP->Provider relationships:")
            for rel in ip_relationships:
                print(f"  - {rel['ip']} HOSTED_BY {rel['provider']}")
            
            # Check domain statistics
            print("\n=== DOMAIN STATISTICS ===")
            stats_result = session.run("""
                MATCH (d:Domain) 
                OPTIONAL MATCH (s:Subdomain)
                OPTIONAL MATCH (ip:IPAddress)
                OPTIONAL MATCH (p:Provider)
                OPTIONAL MATCH (r:Risk)
                RETURN 
                    count(DISTINCT d) as domains,
                    count(DISTINCT s) as subdomains,
                    count(DISTINCT ip) as ips,
                    count(DISTINCT p) as providers,
                    count(DISTINCT r) as risks
            """)
            
            stats = stats_result.single()
            print(f"Database contents:")
            print(f"  - Domains: {stats['domains']}")
            print(f"  - Subdomains: {stats['subdomains']}")
            print(f"  - IP Addresses: {stats['ips']}")
            print(f"  - Providers: {stats['providers']}")
            print(f"  - Risks: {stats['risks']}")
            
            # Verify v2.0 improvements
            print("\n=== v2.0 VERIFICATION ===")
            
            success_indicators = []
            
            # Check if Provider nodes exist (not just Service nodes)
            if total_providers > 0:
                success_indicators.append("✅ Provider nodes created successfully")
            else:
                success_indicators.append("❌ No Provider nodes found")
            
            # Check if Risk nodes exist
            if total_risks > 0:
                success_indicators.append("✅ Risk nodes created successfully")
            else:
                success_indicators.append("❌ No Risk nodes found")
            
            # Check if Provider-Service relationships exist
            if len(relationships) > 0:
                success_indicators.append("✅ Provider-Service relationships created")
            else:
                success_indicators.append("❌ No Provider-Service relationships found")
            
            # Check for multi-level subdomains (second level)
            second_level_result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.fqdn CONTAINS '.' AND size(split(s.fqdn, '.')) > 3
                RETURN count(s) as second_level_count
            """)
            second_level_count = second_level_result.single()["second_level_count"]
            
            if second_level_count > 0:
                success_indicators.append(f"✅ Multi-level subdomains found: {second_level_count}")
            else:
                success_indicators.append("⚠️  No multi-level subdomains detected")
            
            print("\nVerification Results:")
            for indicator in success_indicators:
                print(f"  {indicator}")
            
            # Overall assessment
            successful_checks = len([x for x in success_indicators if x.startswith("✅")])
            total_checks = len(success_indicators)
            
            print(f"\n📊 Overall: {successful_checks}/{total_checks} improvements verified")
            
            if successful_checks >= 2:
                print("🎉 v2.0 improvements are working correctly!")
                return True
            else:
                print("⚠️  Some v2.0 improvements may not be fully working")
                return False
                
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    verify_database()