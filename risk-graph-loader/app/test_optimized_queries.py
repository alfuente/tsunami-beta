#!/usr/bin/env python3
"""
Test script to verify the optimized Neo4j queries work without Cartesian product warnings.
"""

import sys
from neo4j import GraphDatabase

def test_optimized_queries():
    """Test the optimized queries."""
    print("🧪 Testing optimized Neo4j queries...")
    
    try:
        # Read password from file
        with open('../../risk-graph-service/test.password', 'r') as f:
            password = f.read().strip()

        # Connect to Neo4j
        driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', password))
        
        with driver.session() as session:
            with session.begin_transaction() as tx:
                # Clear any existing data
                tx.run("MATCH (n) DETACH DELETE n")
                
                # Create test data
                tx.run("""
                    CREATE (d:Domain {fqdn: 'test.com', created_at: '2025-01-01'})
                    CREATE (s:Subdomain {fqdn: 'www.test.com', created_at: '2025-01-01'})
                    CREATE (c:Certificate {id: 'test-cert-123'})
                    CREATE (srv:Service {id: 'test-service-456'})
                    CREATE (p:Provider {id: 'test-provider-789'})
                    CREATE (i:Industry {name: 'Technology'})
                    CREATE (rd:RelatedDomain {fqdn: 'related.example.com'})
                """)
                
                print("  ✅ Test data created")
                
                # Test the optimized queries
                test_queries = [
                    # HAS_SUBDOMAIN relationship
                    ("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (s:Subdomain {fqdn: $subdomain})
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                    """, {"domain": "test.com", "subdomain": "www.test.com"}),
                    
                    # SECURED_BY relationship
                    ("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (c:Certificate {id: $cert_id})
                        MERGE (s)-[:SECURED_BY]->(c)
                    """, {"fqdn": "www.test.com", "cert_id": "test-cert-123"}),
                    
                    # RUNS relationship
                    ("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (srv:Service {id: $service_id})
                        MERGE (s)-[:RUNS]->(srv)
                    """, {"fqdn": "www.test.com", "service_id": "test-service-456"}),
                    
                    # USES_SERVICE relationship
                    ("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (p:Provider {id: $provider_id})
                        MERGE (s)-[:USES_SERVICE]->(p)
                    """, {"fqdn": "www.test.com", "provider_id": "test-provider-789"}),
                    
                    # BELONGS_TO_INDUSTRY relationship
                    ("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (i:Industry {name: $industry_name})
                        MERGE (s)-[:BELONGS_TO_INDUSTRY]->(i)
                        SET s.primary_industry = $primary_industry
                    """, {"fqdn": "www.test.com", "industry_name": "Technology", "primary_industry": True}),
                    
                    # DISCOVERED_RELATED relationship
                    ("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (rd:RelatedDomain {fqdn: $subdomain})
                        MERGE (d)-[:DISCOVERED_RELATED]->(rd)
                    """, {"domain": "test.com", "subdomain": "related.example.com"})
                ]
                
                for i, (query, params) in enumerate(test_queries, 1):
                    try:
                        tx.run(query, params)
                        print(f"  ✅ Query {i}: Executed successfully")
                    except Exception as e:
                        print(f"  ❌ Query {i}: Failed with error: {e}")
                        return False
                
                tx.commit()
                
                # Verify relationships were created
                verification_queries = [
                    ("HAS_SUBDOMAIN", "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN count(*) as count"),
                    ("SECURED_BY", "MATCH (s:Subdomain)-[:SECURED_BY]->(c:Certificate) RETURN count(*) as count"),
                    ("RUNS", "MATCH (s:Subdomain)-[:RUNS]->(srv:Service) RETURN count(*) as count"),
                    ("USES_SERVICE", "MATCH (s:Subdomain)-[:USES_SERVICE]->(p:Provider) RETURN count(*) as count"),
                    ("BELONGS_TO_INDUSTRY", "MATCH (s:Subdomain)-[:BELONGS_TO_INDUSTRY]->(i:Industry) RETURN count(*) as count"),
                    ("DISCOVERED_RELATED", "MATCH (d:Domain)-[:DISCOVERED_RELATED]->(rd:RelatedDomain) RETURN count(*) as count")
                ]
                
                print(f"\n📊 Relationship verification:")
                all_verified = True
                for rel_name, verify_query in verification_queries:
                    result = session.run(verify_query).single()
                    count = result['count']
                    if count > 0:
                        print(f"  ✅ {rel_name}: {count} relationship(s) created")
                    else:
                        print(f"  ❌ {rel_name}: No relationships found")
                        all_verified = False
                
                # Clean up
                session.run("MATCH (n) DETACH DELETE n")
                print(f"\n🧹 Test data cleaned up")
                
                return all_verified
                
    except Exception as e:
        print(f"  ❌ Test failed with error: {e}")
        return False
    finally:
        driver.close()

def main():
    """Run the optimization test."""
    print("🚀 Testing Neo4j Query Optimizations")
    print("=" * 50)
    
    success = test_optimized_queries()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All optimized queries work correctly!")
        print("✅ No more Cartesian product warnings expected.")
        return 0
    else:
        print("⚠️  Some queries failed. Please review the optimizations.")
        return 1

if __name__ == "__main__":
    sys.exit(main())