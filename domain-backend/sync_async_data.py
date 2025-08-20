#!/usr/bin/env python3
"""
Script to sync async API data to main Neo4j database
"""
import json
import sys
from neo4j import GraphDatabase

# Neo4j connection
neo4j_uri = "bolt://localhost:7687"
neo4j_user = "neo4j"
neo4j_password = "tsunami123"

def update_domain_dns_data(tx, domain, dns_records, mx_data):
    """Update domain with DNS and MX records"""
    
    # Convert DNS records to JSON string
    dns_json = json.dumps(dns_records)
    mx_json = json.dumps(mx_data.get('mx_records', []))
    
    query = """
    MATCH (d:Domain {fqdn: $domain})
    SET d.dns_records = $dns_records,
        d.mx_records = $mx_records,
        d.spf_record = $spf_record,
        d.dmarc_record = $dmarc_record,
        d.has_spf = $has_spf,
        d.has_dmarc = $has_dmarc,
        d.last_updated = datetime()
    RETURN d.fqdn as fqdn
    """
    
    result = tx.run(query, 
                   domain=domain,
                   dns_records=dns_json,
                   mx_records=mx_json,
                   spf_record=mx_data.get('spf_record'),
                   dmarc_record=mx_data.get('dmarc_record'),
                   has_spf=mx_data.get('metadata', {}).get('has_spf', False),
                   has_dmarc=mx_data.get('metadata', {}).get('has_dmarc', False))
    
    return result.single()

def main():
    # Load data
    with open('/tmp/ripley_dns.json', 'r') as f:
        dns_data = json.load(f)
    
    with open('/tmp/ripley_mx.json', 'r') as f:
        mx_data = json.load(f)
    
    # Connect to Neo4j
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    try:
        with driver.session() as session:
            result = session.write_transaction(update_domain_dns_data, "ripley.cl", dns_data, mx_data)
            if result:
                print(f"✅ Updated domain: {result['fqdn']}")
            else:
                print("❌ Domain not found in database")
                
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()

if __name__ == "__main__":
    main()