#!/usr/bin/env python3
"""
Check Neo4j data for ripley.cl
"""
import json
from neo4j import GraphDatabase

# Neo4j connection
neo4j_uri = "bolt://localhost:7687"
neo4j_user = "neo4j"
neo4j_password = "tsunami123"

def get_domain_data(tx, domain):
    """Get domain data from Neo4j"""
    query = """
    MATCH (d:Domain {fqdn: $domain})
    RETURN d.fqdn as fqdn, 
           d.dns_records as dns_records,
           d.mx_records as mx_records,
           d.spf_record as spf_record,
           d.dmarc_record as dmarc_record,
           d.has_spf as has_spf,
           d.has_dmarc as has_dmarc,
           d.last_updated as last_updated
    """
    
    result = tx.run(query, domain=domain)
    return result.single()

def main():
    # Connect to Neo4j
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    try:
        with driver.session() as session:
            result = session.read_transaction(get_domain_data, "ripley.cl")
            if result:
                print("✅ Domain found in Neo4j:")
                print(f"  FQDN: {result['fqdn']}")
                print(f"  DNS Records: {result['dns_records'][:100] if result['dns_records'] else 'None'}...")
                print(f"  MX Records: {result['mx_records'][:100] if result['mx_records'] else 'None'}...")
                print(f"  SPF Record: {result['spf_record'][:50] if result['spf_record'] else 'None'}...")
                print(f"  DMARC Record: {result['dmarc_record'] if result['dmarc_record'] else 'None'}")
                print(f"  Has SPF: {result['has_spf']}")
                print(f"  Has DMARC: {result['has_dmarc']}")
                print(f"  Last Updated: {result['last_updated']}")
            else:
                print("❌ Domain not found in Neo4j")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()

if __name__ == "__main__":
    main()