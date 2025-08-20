#!/usr/bin/env python3
"""
Add www.ripley.cl subdomain to Neo4j
"""
import json
from neo4j import GraphDatabase

# Neo4j connection
neo4j_uri = "bolt://localhost:7687"
neo4j_user = "neo4j"
neo4j_password = "tsunami123"

def add_subdomain(tx, domain, subdomain):
    """Add subdomain to Neo4j"""
    
    # First create the subdomain node
    query1 = """
    MERGE (s:Subdomain {fqdn: $subdomain})
    SET s.base_domain = $domain,
        s.tld = 'cl',
        s.discovered_during_scan_of = $domain,
        s.relationship_type = 'subdomain',
        s.created_at = datetime(),
        s.last_updated = datetime()
    RETURN s.fqdn as fqdn
    """
    
    result1 = tx.run(query1, subdomain=subdomain, domain=domain)
    
    # Then create relationship with base domain
    query2 = """
    MATCH (d:Domain {fqdn: $domain})
    MATCH (s:Subdomain {fqdn: $subdomain})
    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
    RETURN d.fqdn as domain, s.fqdn as subdomain
    """
    
    result2 = tx.run(query2, domain=domain, subdomain=subdomain)
    
    return result1.single(), result2.single()

def main():
    # Connect to Neo4j
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    try:
        with driver.session() as session:
            result1, result2 = session.write_transaction(add_subdomain, "ripley.cl", "www.ripley.cl")
            if result1:
                print(f"✅ Added subdomain: {result1['fqdn']}")
            if result2:
                print(f"✅ Created relationship: {result2['domain']} -> {result2['subdomain']}")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()

if __name__ == "__main__":
    main()