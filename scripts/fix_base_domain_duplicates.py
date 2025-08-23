#!/usr/bin/env python3

from neo4j import GraphDatabase
import requests

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def fix_base_domain_duplicates():
    print("🔧 Fixing base domain duplicates in bancochile.cl...")
    
    with driver.session() as session:
        # 1. Verificar el problema actual
        print("\n📊 Step 1: Analyzing current bancochile.cl structure...")
        
        result = session.run("""
            MATCH (d:Domain) 
            WHERE d.fqdn CONTAINS 'bancochile.cl'
            RETURN d.fqdn as fqdn, d.risk_score as risk_score, 
                   d.risk_tier as risk_tier, d.last_calculated as last_calculated,
                   id(d) as node_id
            ORDER BY d.fqdn
        """)
        
        domains = list(result)
        print(f"   Found {len(domains)} bancochile.cl domain nodes:")
        
        base_domains = [d for d in domains if d['fqdn'] == 'bancochile.cl']
        subdomains = [d for d in domains if d['fqdn'] != 'bancochile.cl']
        
        print(f"   - Base domains: {len(base_domains)}")
        print(f"   - Subdomains: {len(subdomains)}")
        
        if len(base_domains) > 1:
            print(f"   ❌ PROBLEM: Multiple base domain nodes found!")
            for i, domain in enumerate(base_domains):
                calc_time = domain['last_calculated'].strftime('%H:%M:%S') if domain['last_calculated'] else 'Never'
                print(f"     Node {i+1} (ID: {domain['node_id']}): Score={domain['risk_score']}, Calc={calc_time}")
        
        # 2. Identificar el nodo base principal (el que tiene mejor score/datos)
        print("\n🎯 Step 2: Identifying primary base domain node...")
        
        if len(base_domains) > 1:
            # Mantener el nodo con mejor información
            primary_base = max(base_domains, key=lambda x: (
                x['risk_score'] or 0,
                x['last_calculated'] is not None,
                x['risk_tier'] != 'Unknown' if x['risk_tier'] else False
            ))
            
            print(f"   ✅ Primary base node: ID {primary_base['node_id']} (Score: {primary_base['risk_score']})")
            
            # Eliminar nodos base duplicados
            for domain in base_domains:
                if domain['node_id'] != primary_base['node_id']:
                    print(f"   🗑️ Deleting duplicate base node: ID {domain['node_id']}")
                    
                    # Mover relaciones al nodo principal antes de eliminar
                    session.run("""
                        MATCH (duplicate:Domain), (primary:Domain)
                        WHERE id(duplicate) = $duplicate_id AND id(primary) = $primary_id
                        
                        // Mover relaciones entrantes
                        OPTIONAL MATCH (other)-[r]->(duplicate)
                        WHERE type(r) <> 'SUBDOMAIN_OF'
                        WITH duplicate, primary, other, r
                        WHERE r IS NOT NULL
                        CREATE (other)-[r2:SUBDOMAIN_OF]->(primary)
                        DELETE r
                        
                        // Mover relaciones salientes  
                        OPTIONAL MATCH (duplicate)-[r2]->(other)
                        WHERE type(r2) <> 'SUBDOMAIN_OF'
                        WITH duplicate, primary, other, r2
                        WHERE r2 IS NOT NULL
                        CREATE (primary)-[r3:TYPE(r2)]->(other)
                        SET r3 = properties(r2)
                        DELETE r2
                        
                        // Eliminar nodo duplicado
                        DETACH DELETE duplicate
                    """, duplicate_id=domain['node_id'], primary_id=primary_base['node_id'])
        
        # 3. Asegurar que todos los subdominios apunten al nodo base correcto
        print("\n🔗 Step 3: Ensuring all subdomains point to primary base...")
        
        session.run("""
            MATCH (base:Domain {fqdn: 'bancochile.cl'})
            MATCH (sub:Domain)
            WHERE sub.fqdn CONTAINS '.bancochile.cl' AND sub.fqdn <> 'bancochile.cl'
            MERGE (sub)-[:SUBDOMAIN_OF]->(base)
        """)
        
        # 4. Verificar y corregir subdominios con scores que no están bien conectados
        print("\n📈 Step 4: Checking subdomain connections...")
        
        result = session.run("""
            MATCH (sub:Domain)
            WHERE sub.fqdn CONTAINS '.bancochile.cl' AND sub.fqdn <> 'bancochile.cl' AND sub.risk_score > 0
            OPTIONAL MATCH (sub)-[:SUBDOMAIN_OF]->(base:Domain {fqdn: 'bancochile.cl'})
            RETURN sub.fqdn as fqdn, sub.risk_score as score, base.fqdn as connected_base
        """)
        
        scored_subdomains = list(result)
        print(f"   Found {len(scored_subdomains)} subdomains with scores:")
        
        disconnected = [s for s in scored_subdomains if not s['connected_base']]
        if disconnected:
            print(f"   ❌ {len(disconnected)} subdomains not properly connected:")
            for sub in disconnected:
                print(f"     {sub['fqdn']} (Score: {sub['score']})")
        
        # 5. Forzar recálculo del base domain para agregación correcta
        print("\n⚖️ Step 5: Forcing base domain recalculation...")
        
        try:
            response = requests.post(
                "http://localhost:8081/api/v1/calculations/domain-tree/bancochile.cl?force_recalculation=true",
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            print(f"   ✅ Tree recalculation: {result.get('status')}")
        except Exception as e:
            print(f"   ❌ Error in tree recalculation: {e}")
        
        # 6. Verificación final
        print("\n🎉 Step 6: Final verification...")
        
        # Contar nodos base
        result = session.run("""
            MATCH (d:Domain {fqdn: 'bancochile.cl'})
            RETURN count(d) as base_count
        """)
        base_count = result.single()['base_count']
        
        # Contar subdominios conectados
        result = session.run("""
            MATCH (base:Domain {fqdn: 'bancochile.cl'})<-[:SUBDOMAIN_OF]-(sub:Domain)
            RETURN count(sub) as subdomain_count
        """)
        subdomain_count = result.single()['subdomain_count']
        
        # Contar subdominios con scores
        result = session.run("""
            MATCH (base:Domain {fqdn: 'bancochile.cl'})<-[:SUBDOMAIN_OF]-(sub:Domain)
            WHERE sub.risk_score > 0
            RETURN count(sub) as scored_count
        """)
        scored_count = result.single()['scored_count']
        
        print(f"   📊 Final structure:")
        print(f"     Base domain nodes: {base_count}")
        print(f"     Connected subdomains: {subdomain_count}")
        print(f"     Subdomains with scores: {scored_count}")
        
        if base_count == 1:
            print("   ✅ Base domain structure fixed!")
        else:
            print(f"   ❌ Still have {base_count} base domain nodes")

if __name__ == "__main__":
    try:
        fix_base_domain_duplicates()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        driver.close()