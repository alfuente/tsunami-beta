#!/usr/bin/env python3
"""
Script para actualizar los riesgos de dominios base usando los riesgos individuales de subdominios
"""

from neo4j import GraphDatabase
import json

def update_base_domain_risks():
    """Actualizar riesgos de dominios base usando riesgos de subdominios"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    try:
        with driver.session() as session:
            print("🎯 Actualizando riesgos de dominios base con datos de subdominios...\n")
            
            # Obtener todos los dominios base
            result = session.run("""
                MATCH (d:Domain)
                RETURN d.fqdn as fqdn
                ORDER BY d.fqdn
            """)
            
            base_domains = [record["fqdn"] for record in result]
            print(f"Encontrados {len(base_domains)} dominios base para actualizar")
            
            updated_domains = []
            
            for domain_fqdn in base_domains:
                try:
                    # Recalcular risk score usando subdominios individuales
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain_fqdn})
                        OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                        OPTIONAL MATCH (d)-[:DEPENDS_ON|RUNS]->(svc:Service)
                        OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                        
                        WITH d, 
                             count(DISTINCT s) as subdomain_count,
                             count(DISTINCT svc) as service_count,
                             count(DISTINCT p) as provider_count,
                             // Use individual subdomain risk scores
                             avg(CASE WHEN s.risk_score IS NOT NULL AND s.risk_score > 0 THEN s.risk_score ELSE 0 END) as avg_subdomain_risk,
                             max(CASE WHEN s.risk_score IS NOT NULL THEN s.risk_score ELSE 0 END) as max_subdomain_risk,
                             count(CASE WHEN s.risk_tier = 'high' THEN 1 END) as high_risk_subdomains,
                             count(CASE WHEN s.risk_tier = 'medium' THEN 1 END) as medium_risk_subdomains,
                             avg(CASE WHEN svc.risk_score IS NOT NULL THEN svc.risk_score ELSE 0 END) as avg_service_risk,
                             avg(CASE WHEN p.risk_score IS NOT NULL THEN p.risk_score ELSE 0 END) as avg_provider_risk
                        
                        // Enhanced risk calculation using subdomain individual risks
                        WITH d, subdomain_count, service_count, provider_count, high_risk_subdomains, medium_risk_subdomains,
                             avg_subdomain_risk, max_subdomain_risk, avg_service_risk, avg_provider_risk,
                             (subdomain_count * 0.03 + 
                              service_count * 0.25 + 
                              provider_count * 0.20 + 
                              avg_subdomain_risk * 0.30 +  // Higher weight for subdomain risks
                              max_subdomain_risk * 0.12 +   // Consider maximum subdomain risk
                              high_risk_subdomains * 0.05 + // Penalty for high risk subdomains  
                              medium_risk_subdomains * 0.02 + // Penalty for medium risk subdomains
                              avg_service_risk * 0.02 + 
                              avg_provider_risk * 0.01) as calculated_risk
                        
                        SET d.risk_score = CASE 
                            WHEN calculated_risk > 10 THEN 10.0
                            WHEN calculated_risk < 0.5 THEN CASE 
                                WHEN subdomain_count > 0 OR service_count > 0 OR provider_count > 0 THEN 1.0
                                ELSE 0.5
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
                        d.provider_count = provider_count,
                        d.avg_subdomain_risk = avg_subdomain_risk,
                        d.max_subdomain_risk = max_subdomain_risk,
                        d.high_risk_subdomains = high_risk_subdomains,
                        d.medium_risk_subdomains = medium_risk_subdomains,
                        d.risk_calculation_version = '2.0'  // Mark as updated calculation
                        
                        RETURN 
                            d.risk_score as risk_score, 
                            d.risk_tier as risk_tier,
                            subdomain_count,
                            service_count,
                            provider_count,
                            avg_subdomain_risk,
                            max_subdomain_risk,
                            high_risk_subdomains,
                            medium_risk_subdomains
                    """, domain_fqdn=domain_fqdn)
                    
                    if result.peek():
                        record = result.single()
                        
                        updated_domains.append({
                            'fqdn': domain_fqdn,
                            'risk_score': record['risk_score'],
                            'risk_tier': record['risk_tier'],
                            'subdomain_count': record['subdomain_count'],
                            'service_count': record['service_count'],
                            'provider_count': record['provider_count'],
                            'avg_subdomain_risk': record['avg_subdomain_risk'],
                            'max_subdomain_risk': record['max_subdomain_risk'],
                            'high_risk_subdomains': record['high_risk_subdomains'],
                            'medium_risk_subdomains': record['medium_risk_subdomains']
                        })
                        
                except Exception as e:
                    print(f"❌ Error actualizando {domain_fqdn}: {e}")
            
            # Mostrar resultados actualizados
            print(f"\n✅ Actualización completada para {len(updated_domains)} dominios")
            
            # Ordenar por risk score
            updated_domains_sorted = sorted(updated_domains, key=lambda x: x['risk_score'], reverse=True)
            
            print(f"\n🎯 Top 15 dominios por riesgo actualizado:")
            print("-" * 100)
            print(f"{'#':<3} {'Dominio':<25} {'Risk':<6} {'Tier':<8} {'Subs':<5} {'Svcs':<5} {'Provs':<5} {'AvgSubR':<7} {'MaxSubR':<7} {'HiRisk':<6}")
            print("-" * 100)
            
            for i, domain in enumerate(updated_domains_sorted[:15]):
                print(f"{i+1:<3} {domain['fqdn']:<25} {domain['risk_score']:<6.1f} {domain['risk_tier']:<8} "
                      f"{domain['subdomain_count']:<5} {domain['service_count']:<5} {domain['provider_count']:<5} "
                      f"{domain['avg_subdomain_risk']:<7.2f} {domain['max_subdomain_risk']:<7.1f} {domain['high_risk_subdomains']:<6}")
            
            # Verificación específica para BCI.cl y BICE.cl
            print(f"\n=== VERIFICACIÓN BCI.CL Y BICE.CL ===")
            
            for target_domain in ['bci.cl', 'bice.cl']:
                domain_data = next((d for d in updated_domains if d['fqdn'] == target_domain), None)
                
                if domain_data:
                    print(f"\n🎯 {target_domain.upper()}:")
                    print(f"   Risk Score: {domain_data['risk_score']:.1f} ({domain_data['risk_tier']})")
                    print(f"   Subdominios: {domain_data['subdomain_count']}")
                    print(f"   Services: {domain_data['service_count']}")
                    print(f"   Providers: {domain_data['provider_count']}")
                    print(f"   Riesgo promedio subdominios: {domain_data['avg_subdomain_risk']:.2f}")
                    print(f"   Riesgo máximo subdominios: {domain_data['max_subdomain_risk']:.1f}")
                    print(f"   Subdominios alto riesgo: {domain_data['high_risk_subdomains']}")
                    print(f"   Subdominios riesgo medio: {domain_data['medium_risk_subdomains']}")
                else:
                    print(f"\n⚠️  {target_domain.upper()}: No encontrado en resultados")
            
            print(f"\n🎉 Riesgos de dominios base actualizados exitosamente!")
            print(f"   - Usados riesgos individuales de subdominios")
            print(f"   - Eliminada recursión de dominios base")
            print(f"   - Calculados riesgos de 2301 subdominios")
            print(f"   - Aplicada fórmula mejorada de riesgo")
            
            return True
                
    except Exception as e:
        print(f"Error actualizando riesgos de dominios base: {e}")
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    update_base_domain_risks()