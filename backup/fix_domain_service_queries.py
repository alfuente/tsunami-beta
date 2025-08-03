#!/usr/bin/env python3
"""
Script para arreglar las consultas del servicio backend creando las relaciones faltantes
que espera el DomainResource.java
"""

from neo4j import GraphDatabase

def fix_domain_service_queries():
    """Crear las relaciones que el backend espera"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    try:
        with driver.session() as session:
            print("🔧 Arreglando consultas del servicio backend...\n")
            
            # 1. Crear relaciones HAS_SUBDOMAIN (opuesto a SUBDOMAIN_OF)
            print("=== 1. CREANDO RELACIONES HAS_SUBDOMAIN ===")
            result = session.run("""
                MATCH (d:Domain)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                WHERE NOT (d)-[:HAS_SUBDOMAIN]->(s)
                CREATE (d)-[:HAS_SUBDOMAIN]->(s)
                RETURN count(*) as created_has_subdomain
            """)
            
            created_has_subdomain = result.single()["created_has_subdomain"]
            print(f"✅ Creadas {created_has_subdomain} relaciones HAS_SUBDOMAIN")
            
            # 2. Crear relaciones RUNS para services (desde DEPENDS_ON)
            print("\n=== 2. CREANDO RELACIONES RUNS PARA SERVICES ===")
            result = session.run("""
                MATCH (n)-[:DEPENDS_ON]->(s:Service)
                WHERE (n:Domain OR n:Subdomain) AND NOT (n)-[:RUNS]->(s)
                CREATE (n)-[:RUNS]->(s)
                RETURN count(*) as created_runs
            """)
            
            created_runs = result.single()["created_runs"]
            print(f"✅ Creadas {created_runs} relaciones RUNS")
            
            # 3. Crear relaciones HOSTED_BY para providers (desde DEPENDS_ON via IP)
            print("\n=== 3. VERIFICANDO RELACIONES HOSTED_BY ===")
            result = session.run("""
                MATCH (n)-[:DEPENDS_ON]->(p:Provider)
                MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress)
                WHERE (n:Domain OR n:Subdomain) AND NOT (ip)-[:HOSTED_BY]->(p)
                CREATE (ip)-[:HOSTED_BY]->(p)
                RETURN count(*) as created_hosted_by
            """)
            
            created_hosted_by = result.single()["created_hosted_by"]
            print(f"✅ Creadas {created_hosted_by} relaciones HOSTED_BY para IPs")
            
            # 4. Verificar BCI.cl específicamente
            print("\n=== 4. VERIFICACIÓN ESPECÍFICA DE BCI.CL ===")
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)
                OPTIONAL MATCH (d)-[:RUNS]->(s:Service)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                
                RETURN 
                    d.fqdn as domain,
                    count(DISTINCT sub) as has_subdomain_count,
                    count(DISTINCT s) as runs_service_count,
                    count(DISTINCT p) as provider_count
            """)
            
            record = result.single()
            print(f"Dominio: {record['domain']}")
            print(f"HAS_SUBDOMAIN relations: {record['has_subdomain_count']}")
            print(f"RUNS service relations: {record['runs_service_count']}")
            print(f"Provider relations via IP: {record['provider_count']}")
            
            # 5. Test the specific query structure used by DomainResource
            print("\n=== 5. PROBANDO CONSULTA DEL BACKEND ===")
            result = session.run("""
                MATCH (d:Domain)
                WITH d, 
                     CASE 
                         WHEN d.fqdn CONTAINS '.' THEN 
                             CASE 
                                 WHEN size(split(d.fqdn, '.')) >= 2 THEN 
                                     split(d.fqdn, '.')[-2] + '.' + split(d.fqdn, '.')[-1]
                                 ELSE d.fqdn
                             END
                         ELSE d.fqdn
                     END as base_domain
                WHERE base_domain = 'bci.cl'
                
                // Get both the domain and its subdomains
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)
                
                // Combine domain and subdomains into a single collection
                WITH d, collect({node: d, type: 'Domain'}) + collect({node: sub, type: 'Subdomain'}) as all_nodes
                
                // Unwind to process each node individually
                UNWIND all_nodes as node_info
                WITH node_info.node as n, node_info.type as node_type
                WHERE n IS NOT NULL
                
                // Get services and providers using the expected relationships
                OPTIONAL MATCH (n)-[:RUNS]->(s:Service)
                OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                
                RETURN 
                    n.fqdn as fqdn,
                    node_type,
                    collect(DISTINCT s.name) as services,
                    collect(DISTINCT p.name) as providers
                ORDER BY node_type, fqdn
                LIMIT 10
            """)
            
            print("Resultados de la consulta del backend:")
            for record in result:
                fqdn = record["fqdn"]
                node_type = record["node_type"]
                services = [s for s in record["services"] if s is not None]
                providers = [p for p in record["providers"] if p is not None]
                print(f"  {node_type}: {fqdn} - Services: {len(services)}, Providers: {len(providers)}")
            
            print(f"\n🎉 Consultas del servicio backend arregladas!")
            return True
                
    except Exception as e:
        print(f"Error arreglando consultas: {e}")
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    fix_domain_service_queries()