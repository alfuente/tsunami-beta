#!/usr/bin/env python3

from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test.password"))

def cleanup_duplicates():
    with driver.session() as session:
        print("🔍 Checking for bancochile.cl duplicates...")
        
        # Buscar nodos duplicados
        result = session.run("""
            MATCH (d:Domain {fqdn: 'bancochile.cl'})
            RETURN d.fqdn as fqdn, d.risk_score as risk_score, 
                   d.last_calculated as last_calculated, id(d) as node_id
        """)
        
        nodes = list(result)
        print(f"📊 Found {len(nodes)} bancochile.cl nodes:")
        
        for i, node in enumerate(nodes):
            calc_time = node['last_calculated'].strftime('%H:%M:%S') if node['last_calculated'] else 'Never'
            print(f"  Node {i+1} (ID: {node['node_id']}): Score={node['risk_score']}, Calc={calc_time}")
        
        if len(nodes) > 1:
            print("\n🧹 Cleaning up duplicates...")
            
            # Mantener el nodo con el mejor score/datos
            best_node = max(nodes, key=lambda x: (x['risk_score'] or 0, x['last_calculated'] is not None))
            best_id = best_node['node_id']
            
            print(f"✅ Keeping node {best_id} (Score: {best_node['risk_score']})")
            
            # Mover todas las relaciones al nodo principal
            for node in nodes:
                if node['node_id'] != best_id:
                    node_id = node['node_id']
                    print(f"🔄 Migrating relationships from node {node_id}...")
                    
                    # Mover relaciones entrantes
                    session.run("""
                        MATCH (other)-[r]->(duplicate:Domain)
                        WHERE id(duplicate) = $duplicate_id
                        MATCH (main:Domain)
                        WHERE id(main) = $main_id
                        CREATE (other)-[r2:TYPE(r)]->(main)
                        SET r2 = properties(r)
                        DELETE r
                    """, duplicate_id=node_id, main_id=best_id)
                    
                    # Mover relaciones salientes
                    session.run("""
                        MATCH (duplicate:Domain)-[r]->(other)
                        WHERE id(duplicate) = $duplicate_id
                        MATCH (main:Domain)
                        WHERE id(main) = $main_id
                        CREATE (main)-[r2:TYPE(r)]->(other)
                        SET r2 = properties(r)
                        DELETE r
                    """, duplicate_id=node_id, main_id=best_id)
                    
                    # Eliminar nodo duplicado
                    session.run("""
                        MATCH (d:Domain)
                        WHERE id(d) = $node_id
                        DELETE d
                    """, node_id=node_id)
                    
                    print(f"🗑️ Deleted duplicate node {node_id}")
        
        print("\n🎉 Cleanup completed!")
        
        # Verificar resultado
        result = session.run("""
            MATCH (d:Domain {fqdn: 'bancochile.cl'})
            RETURN count(d) as count
        """)
        
        count = result.single()['count']
        print(f"📈 Final result: {count} bancochile.cl node(s)")

if __name__ == "__main__":
    try:
        cleanup_duplicates()
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.close()