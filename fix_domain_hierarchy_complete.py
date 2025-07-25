#!/usr/bin/env python3
"""
Script integral para arreglar la jerarquía de dominios y evitar recursión
1. Eliminar dominios base que aparecen como subdominios de sí mismos
2. Agregar todos los services/providers de subdominios al dominio base
3. Calcular risk scores correctamente para dominios base
4. Aplicar a BCI.cl y BICE.cl, escalable para todos los dominios
"""

from neo4j import GraphDatabase
import json
from typing import List, Dict, Set

def fix_domain_hierarchy_complete():
    """Arreglar completamente la jerarquía de dominios"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    try:
        with driver.session() as session:
            print("🔧 Arreglando jerarquía completa de dominios...\n")
            
            # 1. Eliminar recursión: dominios base como subdominios de sí mismos
            print("=== 1. ELIMINANDO RECURSIÓN DE DOMINIOS BASE ===")
            result = session.run("""
                // Find domains that appear as subdomains of themselves
                MATCH (d:Domain), (s:Subdomain)
                WHERE d.fqdn = s.fqdn AND s.base_domain = d.fqdn
                
                // Delete the redundant subdomain node and its relationships
                DETACH DELETE s
                RETURN count(*) as deleted_recursive_subdomains
            """)
            
            deleted_recursive = result.single()["deleted_recursive_subdomains"]
            print(f"✅ Eliminados {deleted_recursive} subdominios recursivos")
            
            # 2. Identificar todos los dominios base en el sistema
            print("\n=== 2. IDENTIFICANDO DOMINIOS BASE ===")
            result = session.run("""
                MATCH (d:Domain)
                WHERE d.fqdn IS NOT NULL
                RETURN d.fqdn as base_domain
                ORDER BY d.fqdn
            """)
            
            base_domains = [record["base_domain"] for record in result]
            print(f"✅ Encontrados {len(base_domains)} dominios base")
            for domain in base_domains[:10]:  # Show first 10
                print(f"  - {domain}")
            if len(base_domains) > 10:
                print(f"  ... y {len(base_domains) - 10} más")
            
            # 3. Para cada dominio base, agregar todos services/providers de sus subdominios
            print(f"\n=== 3. AGREGANDO SERVICES/PROVIDERS DE SUBDOMINIOS A DOMINIOS BASE ===")
            
            processed_domains = []
            
            for base_domain in base_domains:
                print(f"\n🔍 Procesando {base_domain}...")
                
                # 3a. Agregar services de subdominios al dominio base
                result = session.run("""
                    MATCH (d:Domain {fqdn: $base_domain})
                    MATCH (s:Subdomain {base_domain: $base_domain})-[:DEPENDS_ON|RUNS]->(svc:Service)
                    WHERE NOT (d)-[:DEPENDS_ON]->(svc) AND NOT (d)-[:RUNS]->(svc)
                    
                    // Create both relationships for compatibility
                    CREATE (d)-[:DEPENDS_ON]->(svc)
                    CREATE (d)-[:RUNS]->(svc)
                    
                    RETURN count(DISTINCT svc) as added_services
                """, base_domain=base_domain)
                
                added_services = result.single()["added_services"]
                
                # 3b. Agregar providers de subdominios al dominio base
                result = session.run("""
                    MATCH (d:Domain {fqdn: $base_domain})
                    MATCH (s:Subdomain {base_domain: $base_domain})-[:DEPENDS_ON]->(p:Provider)
                    WHERE NOT (d)-[:DEPENDS_ON]->(p)
                    
                    CREATE (d)-[:DEPENDS_ON]->(p)
                    
                    RETURN count(DISTINCT p) as added_providers
                """, base_domain=base_domain)
                
                added_providers = result.single()["added_providers"]
                
                # 3c. Agregar providers via IP addresses de subdominios
                result = session.run("""
                    MATCH (d:Domain {fqdn: $base_domain})
                    MATCH (s:Subdomain {base_domain: $base_domain})-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                    WHERE NOT (d)-[:DEPENDS_ON]->(p)
                    
                    CREATE (d)-[:DEPENDS_ON]->(p)
                    
                    RETURN count(DISTINCT p) as added_ip_providers
                """, base_domain=base_domain)
                
                added_ip_providers = result.single()["added_ip_providers"]
                
                # 3d. Calcular risk score basado en subdominios, services y providers
                result = session.run("""
                    MATCH (d:Domain {fqdn: $base_domain})
                    OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                    OPTIONAL MATCH (d)-[:DEPENDS_ON|RUNS]->(svc:Service)
                    OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                    
                    WITH d, 
                         count(DISTINCT s) as subdomain_count,
                         count(DISTINCT svc) as service_count,
                         count(DISTINCT p) as provider_count,
                         avg(CASE WHEN s.risk_score IS NOT NULL THEN s.risk_score ELSE 0 END) as avg_subdomain_risk,
                         avg(CASE WHEN svc.risk_score IS NOT NULL THEN svc.risk_score ELSE 0 END) as avg_service_risk,
                         avg(CASE WHEN p.risk_score IS NOT NULL THEN p.risk_score ELSE 0 END) as avg_provider_risk
                    
                    // Calculate comprehensive risk score
                    WITH d, subdomain_count, service_count, provider_count,
                         (subdomain_count * 0.05 + 
                          service_count * 0.3 + 
                          provider_count * 0.25 + 
                          avg_subdomain_risk * 0.2 + 
                          avg_service_risk * 0.1 + 
                          avg_provider_risk * 0.1) as calculated_risk
                    
                    SET d.risk_score = CASE 
                        WHEN calculated_risk > 10 THEN 10.0
                        WHEN calculated_risk < 1 THEN CASE 
                            WHEN subdomain_count > 0 OR service_count > 0 OR provider_count > 0 THEN 2.0
                            ELSE 1.0
                        END
                        ELSE calculated_risk
                    END,
                    d.risk_tier = CASE
                        WHEN d.risk_score >= 8 THEN 'critical'
                        WHEN d.risk_score >= 6 THEN 'high'
                        WHEN d.risk_score >= 4 THEN 'medium'
                        ELSE 'low'
                    END,
                    d.last_calculated = datetime(),
                    d.subdomain_count = subdomain_count,
                    d.service_count = service_count,
                    d.provider_count = provider_count
                    
                    RETURN 
                        d.risk_score as risk_score, 
                        d.risk_tier as risk_tier,
                        subdomain_count,
                        service_count,
                        provider_count
                """, base_domain=base_domain)
                
                record = result.single()
                risk_score = record["risk_score"]
                risk_tier = record["risk_tier"]
                subdomain_count = record["subdomain_count"]
                service_count = record["service_count"]
                provider_count = record["provider_count"]
                
                processed_domains.append({
                    'domain': base_domain,
                    'added_services': added_services,
                    'added_providers': added_providers + added_ip_providers,
                    'risk_score': risk_score,
                    'risk_tier': risk_tier,
                    'subdomain_count': subdomain_count,
                    'service_count': service_count,
                    'provider_count': provider_count
                })
                
                if added_services > 0 or added_providers > 0 or added_ip_providers > 0:
                    print(f"  ✅ {base_domain}: +{added_services} services, +{added_providers + added_ip_providers} providers")
                    print(f"     Risk: {risk_score:.1f} ({risk_tier}) | Subs: {subdomain_count} | Svcs: {service_count} | Provs: {provider_count}")
            
            # 4. Mostrar resumen de los dominios más importantes
            print(f"\n=== 4. RESUMEN DE DOMINIOS PRINCIPALES ===")
            
            # Sort by risk score and show top domains
            top_domains = sorted(processed_domains, key=lambda x: x['risk_score'], reverse=True)[:10]
            
            print("Top 10 dominios por risk score:")
            for i, domain_info in enumerate(top_domains, 1):
                print(f"{i:2}. {domain_info['domain']:<20} | "
                      f"Risk: {domain_info['risk_score']:4.1f} ({domain_info['risk_tier']:<8}) | "
                      f"Subs: {domain_info['subdomain_count']:3} | "
                      f"Svcs: {domain_info['service_count']:3} | "
                      f"Provs: {domain_info['provider_count']:3}")
            
            # 5. Verificar específicamente BCI.cl y BICE.cl
            print(f"\n=== 5. VERIFICACIÓN ESPECÍFICA BCI.CL Y BICE.CL ===")
            
            for target_domain in ['bci.cl', 'bice.cl']:
                result = session.run("""
                    MATCH (d:Domain {fqdn: $domain})
                    OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                    OPTIONAL MATCH (d)-[:RUNS]->(svc:Service)
                    OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                    
                    // Check for any recursion
                    OPTIONAL MATCH (recursive:Subdomain {fqdn: $domain, base_domain: $domain})
                    
                    RETURN 
                        d.fqdn as domain,
                        d.risk_score as risk_score,
                        d.risk_tier as risk_tier,
                        count(DISTINCT s) as subdomains,
                        count(DISTINCT svc) as services,
                        count(DISTINCT p) as providers,
                        count(recursive) as recursive_entries
                """, domain=target_domain)
                
                if result.peek():  # Check if domain exists
                    record = result.single()
                    domain = record['domain']
                    risk_score = record['risk_score']
                    risk_tier = record['risk_tier']
                    subdomains = record['subdomains']
                    services = record['services']
                    providers = record['providers']
                    recursive_entries = record['recursive_entries']
                    
                    print(f"\n🎯 {domain.upper()}:")
                    print(f"   Risk Score: {risk_score:.1f} ({risk_tier})")
                    print(f"   Subdominios: {subdomains}")
                    print(f"   Services: {services}")
                    print(f"   Providers: {providers}")
                    print(f"   Recursión: {'❌ SÍ' if recursive_entries > 0 else '✅ NO'}")
                else:
                    print(f"\n⚠️  {target_domain.upper()}: No encontrado en la base de datos")
            
            print(f"\n🎉 Jerarquía de dominios arreglada completamente!")
            print(f"   - Procesados: {len(processed_domains)} dominios base")
            print(f"   - Sin recursión en dominios base")
            print(f"   - Services/Providers agregados correctamente")
            print(f"   - Risk scores calculados")
            
            return True
                
    except Exception as e:
        print(f"Error arreglando jerarquía de dominios: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    fix_domain_hierarchy_complete()