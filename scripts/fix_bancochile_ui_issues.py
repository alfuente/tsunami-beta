#!/usr/bin/env python3

from neo4j import GraphDatabase
import requests
import time

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def fix_ui_issues():
    print("🔧 Fixing bancochile.cl UI issues...")
    
    with driver.session() as session:
        # 1. Verificar duplicados de bancochile.cl
        print("\n📊 Step 1: Checking for bancochile.cl duplicates in UI...")
        
        result = session.run("""
            MATCH (d:Domain {fqdn: 'bancochile.cl'})
            RETURN count(d) as count
        """)
        
        count = result.single()['count']
        print(f"   Found {count} bancochile.cl base domain nodes")
        
        if count > 1:
            print("❌ Multiple bancochile.cl nodes found - need manual cleanup")
            # Deduplicar manteniendo el mejor
            session.run("""
                MATCH (d1:Domain {fqdn: 'bancochile.cl'}), (d2:Domain {fqdn: 'bancochile.cl'})
                WHERE id(d1) < id(d2) AND d1.risk_score IS NULL AND d2.risk_score IS NOT NULL
                DETACH DELETE d1
            """)
        
        # 2. Verificar subdominios y sus risk scores
        print("\n📈 Step 2: Checking subdomain risk scores...")
        
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl' AND d.fqdn <> 'bancochile.cl'
            RETURN d.fqdn as fqdn, d.risk_score as risk_score, d.risk_tier as risk_tier
            ORDER BY CASE WHEN d.risk_score IS NOT NULL THEN d.risk_score ELSE -1 END DESC
            LIMIT 20
        """)
        
        subdomains = list(result)
        print(f"   Found {len(subdomains)} subdomain records")
        
        scored_subdomains = [s for s in subdomains if s['risk_score'] and s['risk_score'] > 0]
        print(f"   {len(scored_subdomains)} have risk scores > 0")
        
        if scored_subdomains:
            print("   Top scored subdomains:")
            for sub in scored_subdomains[:5]:
                print(f"     {sub['fqdn']:<35} Score: {sub['risk_score']} Tier: {sub['risk_tier']}")
        
        # 3. Asegurar relaciones SUBDOMAIN_OF
        print("\n🔗 Step 3: Ensuring SUBDOMAIN_OF relationships...")
        
        session.run("""
            MATCH (base:Domain {fqdn: 'bancochile.cl'})
            MATCH (sub:Domain)
            WHERE sub.fqdn CONTAINS '.bancochile.cl' AND sub.fqdn <> 'bancochile.cl'
            MERGE (sub)-[:SUBDOMAIN_OF]->(base)
        """)
        
        # 4. Calcular risk scores usando la API
        print("\n⚖️ Step 4: Calculating risk scores via API...")
        
        # Solo calcular para subdominios que tengan datos de tecnología
        result = session.run("""
            MATCH (d:Domain)
            WHERE d.fqdn CONTAINS 'bancochile.cl' 
              AND d.fqdn <> 'bancochile.cl'
              AND (d.technologies IS NOT NULL OR d.risk_score IS NULL OR d.risk_score = 0.0)
            RETURN d.fqdn as fqdn
            ORDER BY d.fqdn
            LIMIT 10
        """)
        
        subdomains_to_calculate = [record['fqdn'] for record in result]
        print(f"   Calculating risk for {len(subdomains_to_calculate)} subdomains...")
        
        for subdomain in subdomains_to_calculate:
            try:
                print(f"   🔄 Calculating: {subdomain}")
                response = requests.post(
                    f"http://localhost:8081/api/v1/calculations/domain/{subdomain}", 
                    timeout=10
                )
                response.raise_for_status()
                result = response.json()
                print(f"     ✅ Status: {result.get('status')}")
                time.sleep(0.5)
            except Exception as e:
                print(f"     ❌ Error: {e}")
        
        # 5. Verificar resultados finales
        print("\n🎉 Step 5: Final verification...")
        
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl' AND d.risk_score > 0
            RETURN d.fqdn as fqdn, d.risk_score as risk_score, d.risk_tier as risk_tier
            ORDER BY d.risk_score DESC
            LIMIT 15
        """)
        
        final_results = list(result)
        print(f"   Final count: {len(final_results)} domains with risk scores > 0")
        
        if final_results:
            print("   📊 Updated risk scores:")
            for domain in final_results:
                print(f"     {domain['fqdn']:<40} Score: {domain['risk_score']:<6} Tier: {domain['risk_tier']}")
        
        print("\n✅ UI fix process completed!")

if __name__ == "__main__":
    try:
        fix_ui_issues()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()