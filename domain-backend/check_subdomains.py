#!/usr/bin/env python3
"""
Check subdomains in Neo4j for ripley.cl
"""
from neo4j import GraphDatabase

# Neo4j connection
neo4j_uri = "bolt://localhost:7687"
neo4j_user = "neo4j"
neo4j_password = "tsunami123"

def get_domain_subdomains(tx, domain):
    """Get domain and its subdomains from Neo4j"""
    query = """
    MATCH (d:Domain {fqdn: $domain})
    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
    RETURN d.fqdn as domain,
           collect(s.fqdn) as subdomains
    """
    
    result = tx.run(query, domain=domain)
    return result.single()

def main():
    # Connect to Neo4j
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    try:
        with driver.session() as session:
            result = session.read_transaction(get_domain_subdomains, "ripley.cl")
            if result:
                print("✅ Domain found in Neo4j:")
                print(f"  Domain: {result['domain']}")
                print(f"  Subdomains: {result['subdomains']}")
            else:
                print("❌ Domain not found in Neo4j")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()

if __name__ == "__main__":
    main()