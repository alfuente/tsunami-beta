#!/usr/bin/env python3

import json
from neo4j import GraphDatabase
from datetime import datetime

# Conectar a Neo4j
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def create_subdomains():
    subdomains = [
        "www.bancochile.cl",
        "portal.bancochile.cl", 
        "portalpersonas.bancochile.cl",
        "portalempresas.bancochile.cl",
        "api.bancochile.cl",
        "mail.bancochile.cl",
        "login.bancochile.cl",
        "extranet.bancochile.cl",
        "servicios.bancochile.cl",
        "online.bancochile.cl"
    ]
    
    with driver.session() as session:
        for subdomain in subdomains:
            print(f"🔧 Creating subdomain: {subdomain}")
            
            # Crear el nodo de dominio
            session.run("""
                MERGE (d:Domain {fqdn: $subdomain})
                ON CREATE SET 
                    d.created_at = datetime(),
                    d.tld = 'cl',
                    d.tld_country_name = 'Chile',
                    d.business_criticality = 'Unknown',
                    d.monitoring_enabled = false,
                    d.risk_score = 0.0,
                    d.risk_tier = 'Unknown'
                ON MATCH SET
                    d.updated_at = datetime()
            """, subdomain=subdomain)
            
            # Crear relación con dominio base
            session.run("""
                MATCH (base:Domain {fqdn: 'bancochile.cl'})
                MATCH (sub:Domain {fqdn: $subdomain})
                MERGE (sub)-[:SUBDOMAIN_OF]->(base)
            """, subdomain=subdomain)
            
            # Agregar algunos datos tecnológicos de ejemplo
            if subdomain == "www.bancochile.cl":
                # Ya tiene datos, solo actualizar
                session.run("""
                    MATCH (d:Domain {fqdn: $subdomain})
                    SET d.technologies = $tech_data,
                        d.tech_analyzed_at = datetime()
                """, subdomain=subdomain, tech_data=json.dumps([
                    {"name": "TLS TLSv1.3", "category": "tls_configuration", "confidence": 0.9},
                    {"name": "Incapsula CDN", "category": "cdn", "confidence": 0.95},
                    {"name": "HTTPS", "category": "protocol", "confidence": 1.0}
                ]))
            
            elif "portal" in subdomain:
                # Portal subdomains - likely web applications
                session.run("""
                    MATCH (d:Domain {fqdn: $subdomain})
                    SET d.technologies = $tech_data,
                        d.tech_analyzed_at = datetime()
                """, subdomain=subdomain, tech_data=json.dumps([
                    {"name": "HTTPS", "category": "protocol", "confidence": 1.0},
                    {"name": "Web Application", "category": "application", "confidence": 0.8}
                ]))
            
            elif subdomain == "api.bancochile.cl":
                # API endpoint
                session.run("""
                    MATCH (d:Domain {fqdn: $subdomain})
                    SET d.technologies = $tech_data,
                        d.tech_analyzed_at = datetime()
                """, subdomain=subdomain, tech_data=json.dumps([
                    {"name": "REST API", "category": "api", "confidence": 0.9},
                    {"name": "HTTPS", "category": "protocol", "confidence": 1.0}
                ]))
                
                # Add some mock services for API
                session.run("""
                    MATCH (d:Domain {fqdn: $subdomain})
                    MERGE (s1:Service {port: 443, protocol: 'tcp', state: 'open', service: 'https'})
                    MERGE (s2:Service {port: 80, protocol: 'tcp', state: 'open', service: 'http'})
                    MERGE (d)-[:HAS_SERVICE]->(s1)
                    MERGE (d)-[:HAS_SERVICE]->(s2)
                """, subdomain=subdomain)
                
    print("✅ All subdomains created successfully!")

def verify_creation():
    with driver.session() as session:
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl' 
            RETURN d.fqdn as fqdn, d.technologies as technologies
            ORDER BY d.fqdn
        """)
        
        print("\n📊 Verification - Created domains:")
        for record in result:
            has_tech = "✅ HAS TECH" if record['technologies'] else "❌ NO TECH"
            print(f"  {record['fqdn']:<35} {has_tech}")

if __name__ == "__main__":
    try:
        create_subdomains()
        verify_creation()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()