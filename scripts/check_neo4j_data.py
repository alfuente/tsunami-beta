#!/usr/bin/env python3

import json
from neo4j import GraphDatabase

# Conectar a Neo4j
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def check_bancochile_data():
    with driver.session() as session:
        # Verificar subdominios de bancochile.cl
        print("🔍 Checking bancochile.cl subdomains in Neo4j...")
        
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl' 
            RETURN d.fqdn as fqdn, d.technologies as technologies, 
                   d.risk_score as risk_score, d.risk_tier as risk_tier,
                   d.last_calculated as last_calculated,
                   d.tech_analyzed_at as tech_analyzed_at
            ORDER BY d.fqdn
            LIMIT 10
        """)
        
        subdomains = []
        for record in result:
            subdomains.append({
                'fqdn': record['fqdn'],
                'has_technologies': record['technologies'] is not None,
                'risk_score': record['risk_score'],
                'risk_tier': record['risk_tier'],
                'last_calculated': record['last_calculated'],
                'tech_analyzed_at': record['tech_analyzed_at']
            })
        
        print(f"📊 Found {len(subdomains)} bancochile.cl domains:")
        for domain in subdomains:
            tech_status = "✅ HAS TECH" if domain['has_technologies'] else "❌ NO TECH"
            risk_status = f"Risk: {domain['risk_score'] or 0}" if domain['risk_score'] else "❌ NO RISK"
            calc_status = "✅ CALCULATED" if domain['last_calculated'] else "❌ NOT CALCULATED"
            
            print(f"  {domain['fqdn'][:40]:<40} {tech_status:<12} {risk_status:<12} {calc_status}")
        
        print("\n🔍 Checking services for www.bancochile.cl...")
        result = session.run("""
            MATCH (d:Domain {fqdn: 'www.bancochile.cl'})-[:HAS_SERVICE]->(s:Service)
            RETURN s.port as port, s.protocol as protocol, s.state as state
            ORDER BY s.port
        """)
        
        services = list(result)
        print(f"📦 Found {len(services)} services:")
        for service in services:
            print(f"  Port {service['port']}/{service['protocol']} - {service['state']}")
        
        print("\n🔍 Checking technology nodes for www.bancochile.cl...")
        result = session.run("""
            MATCH (d:Domain {fqdn: 'www.bancochile.cl'})-[:USES_TECHNOLOGY]->(t:Technology)
            RETURN t.name as name, t.category as category
            ORDER BY t.category, t.name
        """)
        
        technologies = list(result)
        print(f"💻 Found {len(technologies)} technology relationships:")
        for tech in technologies:
            print(f"  {tech['category']}: {tech['name']}")

if __name__ == "__main__":
    try:
        check_bancochile_data()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()