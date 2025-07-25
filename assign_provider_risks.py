#!/usr/bin/env python3
"""
Script para asignar risk scores a providers y services
"""

from neo4j import GraphDatabase
import random

def assign_provider_risks():
    """Asignar risk scores a providers y services"""
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))
    
    # Risk mappings based on provider type
    provider_risks = {
        'aws': {'score': 3.5, 'tier': 'medium'},
        'gcp': {'score': 3.2, 'tier': 'medium'},
        'azure': {'score': 3.0, 'tier': 'medium'},
        'cloudflare': {'score': 2.5, 'tier': 'low'},
        'Unknown Provider': {'score': 7.5, 'tier': 'high'}
    }
    
    service_risks = {
        'web-server': {'score': 4.0, 'tier': 'medium'},
        'email-server': {'score': 5.0, 'tier': 'medium'},
        'dns-server': {'score': 3.5, 'tier': 'medium'},
        'database': {'score': 6.0, 'tier': 'high'},
        'api': {'score': 4.5, 'tier': 'medium'}
    }
    
    try:
        with driver.session() as session:
            print("🎯 Asignando risk scores a providers y services...\n")
            
            # 1. Asignar risks a providers específicos
            print("=== 1. ASIGNANDO RISKS A PROVIDERS ===")
            for provider_name, risk_data in provider_risks.items():
                result = session.run("""
                    MATCH (p:Provider {name: $provider_name})
                    SET p.risk_score = $risk_score,
                        p.risk_tier = $risk_tier,
                        p.last_risk_assessment = datetime()
                    RETURN count(p) as updated_count
                """, provider_name=provider_name, risk_score=risk_data['score'], risk_tier=risk_data['tier'])
                
                updated_count = result.single()["updated_count"]
                if updated_count > 0:
                    print(f"✅ {provider_name}: score {risk_data['score']} ({risk_data['tier']})")
            
            # 2. Asignar risks a providers restantes (genérico)
            result = session.run("""
                MATCH (p:Provider)
                WHERE p.risk_score IS NULL
                SET p.risk_score = toFloat(round(rand() * 6 + 2, 1)),
                    p.risk_tier = CASE
                        WHEN p.risk_score >= 7 THEN 'high'
                        WHEN p.risk_score >= 4 THEN 'medium'
                        ELSE 'low'
                    END,
                    p.last_risk_assessment = datetime()
                RETURN count(p) as updated_generic
            """)
            
            updated_generic = result.single()["updated_generic"]
            print(f"✅ {updated_generic} providers adicionales con risk scores genéricos")
            
            # 3. Asignar risks a services
            print("\n=== 2. ASIGNANDO RISKS A SERVICES ===")
            result = session.run("""
                MATCH (s:Service)
                WHERE s.risk_score IS NULL
                SET s.risk_score = toFloat(round(rand() * 5 + 2.5, 1)),
                    s.risk_tier = CASE
                        WHEN s.risk_score >= 6.5 THEN 'high'
                        WHEN s.risk_score >= 4 THEN 'medium'
                        ELSE 'low'
                    END,
                    s.last_risk_assessment = datetime()
                RETURN count(s) as updated_services
            """)
            
            updated_services = result.single()["updated_services"]
            print(f"✅ {updated_services} services con risk scores asignados")
            
            # 4. Verificar resultados
            print("\n=== 3. VERIFICACIÓN ===")
            result = session.run("""
                MATCH (p:Provider)
                WHERE p.risk_score IS NOT NULL
                RETURN 
                    count(p) as total_providers,
                    avg(p.risk_score) as avg_provider_risk,
                    count(CASE WHEN p.risk_tier = 'high' THEN 1 END) as high_risk_providers
            """)
            
            record = result.single()
            print(f"Providers con risk: {record['total_providers']}")
            print(f"Risk promedio: {record['avg_provider_risk']:.2f}")
            print(f"High risk: {record['high_risk_providers']}")
            
            result = session.run("""
                MATCH (s:Service)
                WHERE s.risk_score IS NOT NULL
                RETURN 
                    count(s) as total_services,
                    avg(s.risk_score) as avg_service_risk,
                    count(CASE WHEN s.risk_tier = 'high' THEN 1 END) as high_risk_services
            """)
            
            record = result.single()
            print(f"Services con risk: {record['total_services']}")
            print(f"Risk promedio: {record['avg_service_risk']:.2f}")
            print(f"High risk: {record['high_risk_services']}")
            
            print(f"\n🎉 Risk scores asignados exitosamente!")
            return True
                
    except Exception as e:
        print(f"Error asignando risks: {e}")
        return False
    finally:
        driver.close()

if __name__ == "__main__":
    assign_provider_risks()