#!/usr/bin/env python3
"""
Script para verificar qué subdominios existen realmente en el grafo
y si tienen algún tipo de relación con servicios.
"""

from neo4j import GraphDatabase

class SubdomainChecker:
    def __init__(self):
        self.neo4j_driver = GraphDatabase.driver(
            "bolt://localhost:7687", 
            auth=("neo4j", "test.password")
        )
    
    def close(self):
        self.neo4j_driver.close()
    
    def search_specific_domains(self, patterns):
        """Busca dominios específicos que contengan ciertos patrones"""
        with self.neo4j_driver.session() as session:
            results = {}
            for pattern in patterns:
                result = session.run("""
                    MATCH (n)
                    WHERE (n:Domain OR n:Subdomain) 
                      AND (n.fqdn CONTAINS $pattern OR n.fqdn = $pattern)
                    OPTIONAL MATCH (n)-[r:HAS_SERVICE]->(s:Service)
                    RETURN n.fqdn as fqdn, 
                           labels(n) as labels,
                           n.hasSSL as hasSSL,
                           n.riskScore as riskScore,
                           collect(DISTINCT {
                               name: s.name,
                               port: s.port,
                               relation_type: type(r)
                           }) as services
                    ORDER BY n.fqdn
                """, pattern=pattern)
                
                results[pattern] = []
                for record in result:
                    results[pattern].append({
                        'fqdn': record['fqdn'],
                        'labels': record['labels'],
                        'hasSSL': record['hasSSL'],
                        'riskScore': record['riskScore'],
                        'services': [s for s in record['services'] if s['name'] is not None]
                    })
            return results
    
    def get_sample_subdomains(self, limit=20):
        """Obtiene una muestra de subdominios para ver su estructura"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                OPTIONAL MATCH (s)-[r:HAS_SERVICE]->(srv:Service)
                OPTIONAL MATCH (s)-[r2]->(n)
                RETURN s.fqdn as fqdn,
                       s.hasSSL as hasSSL,
                       s.riskScore as riskScore,
                       collect(DISTINCT {
                           name: srv.name,
                           port: srv.port
                       }) as services,
                       collect(DISTINCT type(r2)) as outgoing_relations
                ORDER BY s.fqdn
                LIMIT $limit
            """, limit=limit)
            
            return [{
                'fqdn': record['fqdn'],
                'hasSSL': record['hasSSL'],
                'riskScore': record['riskScore'],
                'services': [s for s in record['services'] if s['name'] is not None],
                'outgoing_relations': [r for r in record['outgoing_relations'] if r is not None]
            } for record in result]
    
    def check_service_relationships(self):
        """Verifica todos los tipos de relaciones con servicios"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (n)-[r]->(s:Service)
                RETURN labels(n) as node_labels,
                       type(r) as relation_type,
                       count(*) as count
                ORDER BY count DESC
            """)
            
            return [{
                'node_labels': record['node_labels'],
                'relation_type': record['relation_type'],
                'count': record['count']
            } for record in result]
    
    def check_all_relations_from_subdomains(self):
        """Verifica todas las relaciones salientes desde subdominios"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)-[r]->(n)
                RETURN type(r) as relation_type,
                       labels(n) as target_labels,
                       count(*) as count
                ORDER BY count DESC
            """)
            
            return [{
                'relation_type': record['relation_type'],
                'target_labels': record['target_labels'],
                'count': record['count']
            } for record in result]

def main():
    print("=== Verificación Detallada de Subdominios ===\n")
    
    checker = SubdomainChecker()
    
    try:
        # 1. Buscar dominios específicos
        print("1. BUSCANDO DOMINIOS ESPECÍFICOS")
        print("-" * 50)
        patterns = ['bci.cl', 'bice.cl', 'bancochile.cl', 'www.', 'api.', 'portal.']
        results = checker.search_specific_domains(patterns)
        
        for pattern, domains in results.items():
            print(f"\nPatrón '{pattern}':")
            if domains:
                for domain in domains:
                    print(f"  ✅ {domain['fqdn']} ({', '.join(domain['labels'])})")
                    print(f"     SSL: {domain['hasSSL']}, Risk: {domain['riskScore']}")
                    if domain['services']:
                        for service in domain['services']:
                            print(f"     - Servicio: {service['name']}:{service['port']}")
                    else:
                        print(f"     - Sin servicios")
            else:
                print(f"  ❌ No se encontraron dominios")
        
        # 2. Muestra de subdominios
        print(f"\n\n2. MUESTRA DE SUBDOMINIOS")
        print("-" * 50)
        sample = checker.get_sample_subdomains(10)
        for sub in sample:
            print(f"🌐 {sub['fqdn']}")
            print(f"   SSL: {sub['hasSSL']}, Risk: {sub['riskScore']}")
            if sub['services']:
                print(f"   Servicios: {len(sub['services'])}")
                for service in sub['services']:
                    print(f"   - {service['name']}:{service['port']}")
            else:
                print(f"   Sin servicios")
            
            if sub['outgoing_relations']:
                print(f"   Relaciones salientes: {', '.join(sub['outgoing_relations'])}")
        
        # 3. Verificar relaciones con servicios
        print(f"\n\n3. RELACIONES CON SERVICIOS")
        print("-" * 50)
        service_rels = checker.check_service_relationships()
        if service_rels:
            for rel in service_rels:
                node_type = ', '.join(rel['node_labels'])
                print(f"{node_type} --[{rel['relation_type']}]--> Service: {rel['count']} casos")
        else:
            print("❌ No se encontraron relaciones hacia servicios")
        
        # 4. Todas las relaciones desde subdominios
        print(f"\n\n4. TODAS LAS RELACIONES DESDE SUBDOMINIOS")
        print("-" * 50)
        all_rels = checker.check_all_relations_from_subdomains()
        if all_rels:
            for rel in all_rels:
                target_type = ', '.join(rel['target_labels'])
                print(f"Subdomain --[{rel['relation_type']}]--> {target_type}: {rel['count']} casos")
        else:
            print("❌ Los subdominios no tienen relaciones salientes")
    
    finally:
        checker.close()

if __name__ == "__main__":
    main()