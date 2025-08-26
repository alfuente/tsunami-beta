#!/usr/bin/env python3
"""
Script para analizar todos los subdominios con servicios web en Neo4j
y generar un reporte detallado.
"""

from neo4j import GraphDatabase
import json
from datetime import datetime

class WebSubdomainAnalyzer:
    def __init__(self):
        self.neo4j_driver = GraphDatabase.driver(
            "bolt://localhost:7687", 
            auth=("neo4j", "test.password")
        )
    
    def close(self):
        self.neo4j_driver.close()
    
    def get_all_subdomains_with_services(self):
        """Obtiene todos los subdominios con cualquier tipo de servicio"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)-[:HAS_SERVICE]->(srv:Service)
                RETURN s.fqdn as fqdn, 
                       collect(DISTINCT {
                           name: srv.name, 
                           port: srv.port, 
                           protocol: srv.protocol,
                           state: srv.state
                       }) as services
                ORDER BY s.fqdn
            """)
            return [{
                'fqdn': record['fqdn'],
                'services': record['services']
            } for record in result]
    
    def get_web_subdomains(self):
        """Obtiene subdominios con servicios web específicos"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)-[:HAS_SERVICE]->(srv:Service)
                WHERE srv.name IN ['http', 'https', 'HTTP', 'HTTPS', 'http-alt', 'https-alt']
                   OR srv.port IN [80, 443, 8080, 8443]
                RETURN s.fqdn as fqdn,
                       s.hasSSL as hasSSL,
                       s.tlsVersion as tlsVersion,
                       s.riskScore as riskScore,
                       collect(DISTINCT {
                           name: srv.name,
                           port: srv.port,
                           protocol: srv.protocol,
                           state: srv.state
                       }) as web_services
                ORDER BY s.fqdn
            """)
            return [{
                'fqdn': record['fqdn'],
                'hasSSL': record['hasSSL'],
                'tlsVersion': record['tlsVersion'],
                'riskScore': record['riskScore'],
                'web_services': record['web_services']
            } for record in result]
    
    def get_all_subdomains_stats(self):
        """Obtiene estadísticas generales de subdominios"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                OPTIONAL MATCH (s)-[:HAS_SERVICE]->(srv:Service)
                RETURN count(DISTINCT s) as total_subdomains,
                       count(DISTINCT CASE WHEN srv IS NOT NULL THEN s END) as subdomains_with_services,
                       count(DISTINCT srv) as total_services
            """)
            return dict(result.single())
    
    def get_service_distribution(self):
        """Obtiene distribución de servicios por puerto/nombre"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (:Subdomain)-[:HAS_SERVICE]->(srv:Service)
                RETURN srv.name as service_name, 
                       srv.port as port,
                       count(*) as count
                ORDER BY count DESC, srv.port
            """)
            return [{
                'service_name': record['service_name'],
                'port': record['port'], 
                'count': record['count']
            } for record in result]
    
    def get_domains_with_services(self):
        """También revisar si hay dominios base con servicios web"""
        with self.neo4j_driver.session() as session:
            result = session.run("""
                MATCH (d:Domain)-[:HAS_SERVICE]->(srv:Service)
                WHERE srv.name IN ['http', 'https', 'HTTP', 'HTTPS', 'http-alt', 'https-alt']
                   OR srv.port IN [80, 443, 8080, 8443]
                RETURN d.fqdn as fqdn,
                       d.hasSSL as hasSSL,
                       d.tlsVersion as tlsVersion, 
                       d.riskScore as riskScore,
                       collect(DISTINCT {
                           name: srv.name,
                           port: srv.port,
                           protocol: srv.protocol,
                           state: srv.state
                       }) as web_services
                ORDER BY d.fqdn
            """)
            return [{
                'fqdn': record['fqdn'],
                'hasSSL': record['hasSSL'],
                'tlsVersion': record['tlsVersion'],
                'riskScore': record['riskScore'],
                'web_services': record['web_services']
            } for record in result]

def main():
    print("=== Análisis de Subdominios con Servicios Web ===")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    analyzer = WebSubdomainAnalyzer()
    
    try:
        # Estadísticas generales
        print("1. ESTADÍSTICAS GENERALES")
        print("-" * 50)
        stats = analyzer.get_all_subdomains_stats()
        print(f"Total de subdominios en Neo4j: {stats['total_subdomains']}")
        print(f"Subdominios con servicios: {stats['subdomains_with_services']}")
        print(f"Total de servicios: {stats['total_services']}")
        print()
        
        # Distribución de servicios
        print("2. DISTRIBUCIÓN DE SERVICIOS")
        print("-" * 50)
        service_dist = analyzer.get_service_distribution()
        for service in service_dist[:20]:  # Top 20
            name = service['service_name'] or 'NULL'
            port = service['port'] or 'NULL'
            print(f"Servicio: {name:<15} Puerto: {port:<6} Cantidad: {service['count']}")
        print()
        
        # Dominios base con servicios web
        print("3. DOMINIOS BASE CON SERVICIOS WEB")
        print("-" * 50)
        domains_web = analyzer.get_domains_with_services()
        print(f"Encontrados: {len(domains_web)} dominios base con servicios web")
        for domain in domains_web:
            print(f"  {domain['fqdn']}")
            print(f"    SSL: {domain['hasSSL']}, TLS: {domain['tlsVersion']}, Risk: {domain['riskScore']}")
            for service in domain['web_services']:
                print(f"    - {service['name']}:{service['port']} ({service['state']})")
        print()
        
        # Subdominios con servicios web
        print("4. SUBDOMINIOS CON SERVICIOS WEB")
        print("-" * 50)
        web_subdomains = analyzer.get_web_subdomains()
        print(f"Encontrados: {len(web_subdomains)} subdominios con servicios web")
        
        # Guardar reporte detallado
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'stats': stats,
            'service_distribution': service_dist,
            'domains_with_web_services': domains_web,
            'subdomains_with_web_services': web_subdomains
        }
        
        with open('web_subdomains_report.json', 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 Reporte completo guardado en: web_subdomains_report.json")
        
        # Mostrar algunos ejemplos
        print("\n5. EJEMPLOS DE SUBDOMINIOS CON SERVICIOS WEB")
        print("-" * 50)
        for subdomain in web_subdomains[:10]:  # Primeros 10
            print(f"🌐 {subdomain['fqdn']}")
            print(f"   SSL: {subdomain['hasSSL']}, TLS: {subdomain['tlsVersion']}, Risk: {subdomain['riskScore']}")
            for service in subdomain['web_services']:
                print(f"   - {service['name']}:{service['port']} ({service['state']})")
        
        if len(web_subdomains) > 10:
            print(f"\n... y {len(web_subdomains) - 10} más (ver archivo JSON completo)")
        
        # Buscar específicamente los ejemplos que mencionaste
        print("\n6. VERIFICACIÓN DE EJEMPLOS ESPECÍFICOS")
        print("-" * 50)
        examples = ['www.bci.cl', 'www.bice.cl', 'api.bancochile.cl']
        
        all_with_services = analyzer.get_all_subdomains_with_services()
        
        for example in examples:
            found = False
            for sub in all_with_services:
                if example in sub['fqdn'] or sub['fqdn'] == example:
                    found = True
                    print(f"✅ {sub['fqdn']}")
                    for service in sub['services']:
                        print(f"   - {service['name']}:{service['port']}")
                    break
            
            if not found:
                print(f"❌ {example} - No encontrado en el grafo")
    
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()