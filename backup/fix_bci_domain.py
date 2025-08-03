#!/usr/bin/env python3
"""
Script para arreglar los problemas con el dominio BCI.cl
1. Crear relaciones SUBDOMAIN_OF faltantes
2. Crear relaciones con providers
3. Calcular risk scores
"""

from neo4j import GraphDatabase
import json

def fix_bci_domain():
    """Arreglar los problemas con BCI.cl"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    try:
        with driver.session() as session:
            print("🔧 Arreglando dominio BCI.cl...\n")
            
            # 1. Crear relaciones SUBDOMAIN_OF faltantes
            print("=== 1. CREANDO RELACIONES SUBDOMAIN_OF ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})
                MATCH (s:Subdomain)
                WHERE s.base_domain = 'bci.cl' AND NOT (s)-[:SUBDOMAIN_OF]->(d)
                CREATE (s)-[:SUBDOMAIN_OF]->(d)
                RETURN count(*) as created_relations
            """)
            
            created_relations = result.single()["created_relations"]
            print(f"✅ Creadas {created_relations} relaciones SUBDOMAIN_OF")
            
            # 2. Verificar subdominios conectados
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})<-[:SUBDOMAIN_OF]-(s:Subdomain)
                RETURN count(s) as connected_subdomains
            """)
            connected_subdomains = result.single()["connected_subdomains"]
            print(f"✅ Total subdominios conectados: {connected_subdomains}")
            
            # 3. Identificar providers a través de IPs
            print("\n=== 2. IDENTIFICANDO PROVIDERS A TRAVÉS DE IPs ===")
            result = session.run("""
                MATCH (s:Subdomain {base_domain: 'bci.cl'})-[:RESOLVES_TO]->(ip:IPAddress)
                MATCH (ip)-[:HOSTED_BY]->(p:Provider)
                WHERE NOT (s)-[:DEPENDS_ON]->(p)
                CREATE (s)-[:DEPENDS_ON]->(p)
                RETURN count(DISTINCT p) as connected_providers, collect(DISTINCT p.name) as provider_names
            """)
            
            record = result.single()
            connected_providers = record["connected_providers"]
            provider_names = record["provider_names"]
            print(f"✅ Conectados {connected_providers} providers: {provider_names}")
            
            # 4. Crear relaciones directas desde el dominio base a providers
            print("\n=== 3. CONECTANDO DOMINIO BASE A PROVIDERS ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})<-[:SUBDOMAIN_OF]-(s:Subdomain)-[:DEPENDS_ON]->(p:Provider)
                WHERE NOT (d)-[:DEPENDS_ON]->(p)
                CREATE (d)-[:DEPENDS_ON]->(p)
                RETURN count(DISTINCT p) as domain_providers
            """)
            
            domain_providers = result.single()["domain_providers"]
            print(f"✅ Dominio BCI.cl conectado a {domain_providers} providers")
            
            # 5. Conectar dominio base a services
            print("\n=== 4. CONECTANDO DOMINIO BASE A SERVICES ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})<-[:SUBDOMAIN_OF]-(s:Subdomain)-[:DEPENDS_ON]->(svc:Service)
                WHERE NOT (d)-[:DEPENDS_ON]->(svc)
                CREATE (d)-[:DEPENDS_ON]->(svc)
                RETURN count(DISTINCT svc) as domain_services
            """)
            
            domain_services = result.single()["domain_services"]
            print(f"✅ Dominio BCI.cl conectado a {domain_services} services")
            
            # 6. Calcular risk score básico
            print("\n=== 5. CALCULANDO RISK SCORE ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})
                OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                OPTIONAL MATCH (d)-[:DEPENDS_ON]->(svc:Service)
                
                WITH d, count(s) as subdomain_count, count(DISTINCT p) as provider_count, count(DISTINCT svc) as service_count
                
                // Calcular risk score básico
                WITH d, subdomain_count, provider_count, service_count,
                     (subdomain_count * 0.1 + provider_count * 0.3 + service_count * 0.2) as calculated_risk
                
                SET d.risk_score = CASE 
                    WHEN calculated_risk > 10 THEN 10.0
                    WHEN calculated_risk < 1 THEN 1.0
                    ELSE calculated_risk
                END,
                d.risk_tier = CASE
                    WHEN calculated_risk >= 8 THEN 'critical'
                    WHEN calculated_risk >= 6 THEN 'high'
                    WHEN calculated_risk >= 4 THEN 'medium'
                    ELSE 'low'
                END,
                d.last_calculated = datetime()
                
                RETURN d.risk_score as risk_score, d.risk_tier as risk_tier
            """)
            
            record = result.single()
            risk_score = record["risk_score"]
            risk_tier = record["risk_tier"]
            print(f"✅ Risk score calculado: {risk_score} ({risk_tier})")
            
            # 7. Verificación final
            print("\n=== 6. VERIFICACIÓN FINAL ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})
                OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                OPTIONAL MATCH (d)-[:DEPENDS_ON]->(svc:Service)
                
                RETURN 
                    d.fqdn as domain,
                    d.risk_score as risk_score,
                    d.risk_tier as risk_tier,
                    count(DISTINCT s) as subdomains,
                    count(DISTINCT p) as providers,
                    count(DISTINCT svc) as services
            """)
            
            record = result.single()
            print(f"Dominio: {record['domain']}")
            print(f"Risk Score: {record['risk_score']} ({record['risk_tier']})")
            print(f"Subdominios: {record['subdomains']}")
            print(f"Providers: {record['providers']}")
            print(f"Services: {record['services']}")
            
            print(f"\n🎉 Dominio BCI.cl arreglado exitosamente!")
            return True
                
    except Exception as e:
        print(f"Error arreglando BCI.cl: {e}")
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    fix_bci_domain()