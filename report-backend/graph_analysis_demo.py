#!/usr/bin/env python3
"""
Análisis detallado del grafo Neo4j para el sistema Tsunami
Genera información detallada sobre la estructura y datos del grafo
"""
import os
import sys
from datetime import datetime
from neo4j import GraphDatabase
import json

class GraphAnalyzer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.analysis_data = {}

    def close(self):
        self.driver.close()

    def get_node_statistics(self):
        """Obtiene estadísticas de nodos por tipo"""
        with self.driver.session() as session:
            # Estadísticas básicas de nodos
            result = session.run("""
                CALL apoc.meta.stats() YIELD labels
                RETURN labels
            """)
            
            node_stats = {}
            for record in result:
                labels = record["labels"]
                for label, count in labels.items():
                    node_stats[label] = count
            
            # Total de nodos
            total_result = session.run("MATCH (n) RETURN count(n) as total")
            total_nodes = total_result.single()["total"]
            
            return {
                "total_nodes": total_nodes,
                "node_types": node_stats
            }

    def get_relationship_statistics(self):
        """Obtiene estadísticas de relaciones por tipo"""
        with self.driver.session() as session:
            # Estadísticas de relaciones
            result = session.run("""
                CALL apoc.meta.stats() YIELD relTypes
                RETURN relTypes
            """)
            
            rel_stats = {}
            for record in result:
                rel_types = record["relTypes"]
                for rel_type, count in rel_types.items():
                    rel_stats[rel_type] = count
            
            # Total de relaciones
            total_result = session.run("MATCH ()-[r]->() RETURN count(r) as total")
            total_relationships = total_result.single()["total"]
            
            return {
                "total_relationships": total_relationships,
                "relationship_types": rel_stats
            }

    def get_domain_distribution(self):
        """Analiza la distribución de dominios"""
        with self.driver.session() as session:
            # Dominios base vs subdominios
            base_domains = session.run("""
                MATCH (d:Domain)
                WHERE NOT (d)<-[:HAS_SUBDOMAIN]-()
                RETURN count(d) as count
            """).single()["count"]
            
            subdomains = session.run("""
                MATCH (d:Domain)<-[:HAS_SUBDOMAIN]-()
                RETURN count(d) as count
            """).single()["count"]
            
            # Top level domains
            tld_result = session.run("""
                MATCH (d:Domain)
                WHERE NOT (d)<-[:HAS_SUBDOMAIN]-()
                WITH split(d.fqdn, '.') as parts
                WITH parts[size(parts)-1] as tld
                RETURN tld, count(*) as count
                ORDER BY count DESC
                LIMIT 10
            """)
            
            tlds = []
            for record in tld_result:
                tlds.append({
                    "tld": record["tld"],
                    "count": record["count"]
                })
            
            return {
                "base_domains": base_domains,
                "subdomains": subdomains,
                "top_level_domains": tlds
            }

    def get_technology_analysis(self):
        """Analiza las tecnologías detectadas"""
        with self.driver.session() as session:
            # Categorías de tecnologías
            tech_categories = session.run("""
                MATCH (t:Technology)
                RETURN t.category as category, count(*) as count
                ORDER BY count DESC
            """)
            
            categories = []
            for record in tech_categories:
                categories.append({
                    "category": record["category"] or "Unknown",
                    "count": record["count"]
                })
            
            # Tecnologías más detectadas
            most_detected = session.run("""
                MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)
                RETURN t.name as technology, count(d) as domains
                ORDER BY domains DESC
                LIMIT 15
            """)
            
            technologies = []
            for record in most_detected:
                technologies.append({
                    "technology": record["technology"],
                    "domains": record["domains"]
                })
            
            # Análisis de riesgo de versiones
            risk_levels = session.run("""
                MATCH (tv:TechnologyVersion)
                WHERE tv.risk_level IS NOT NULL
                RETURN tv.risk_level as risk_level, count(*) as count
                ORDER BY count DESC
            """)
            
            risks = []
            for record in risk_levels:
                risks.append({
                    "risk_level": record["risk_level"],
                    "count": record["count"]
                })
            
            return {
                "technology_categories": categories,
                "most_detected_technologies": technologies,
                "technology_risk_levels": risks
            }

    def get_risk_distribution(self):
        """Analiza la distribución de riesgos"""
        with self.driver.session() as session:
            # Distribución por buckets de riesgo
            risk_buckets = session.run("""
                MATCH (d:Domain)
                WHERE d.risk_score IS NOT NULL
                WITH 
                    CASE 
                        WHEN d.risk_score >= 80 THEN 'Critical (80-100)'
                        WHEN d.risk_score >= 60 THEN 'High (60-80)'
                        WHEN d.risk_score >= 40 THEN 'Medium-High (40-60)'
                        WHEN d.risk_score >= 20 THEN 'Medium (20-40)'
                        WHEN d.risk_score >= 10 THEN 'Low-Medium (10-20)'
                        ELSE 'Low (0-10)'
                    END as risk_bucket
                RETURN risk_bucket, count(*) as count
                ORDER BY 
                    CASE risk_bucket
                        WHEN 'Critical (80-100)' THEN 1
                        WHEN 'High (60-80)' THEN 2
                        WHEN 'Medium-High (40-60)' THEN 3
                        WHEN 'Medium (20-40)' THEN 4
                        WHEN 'Low-Medium (10-20)' THEN 5
                        ELSE 6
                    END
            """)
            
            risk_dist = []
            for record in risk_buckets:
                risk_dist.append({
                    "risk_bucket": record["risk_bucket"],
                    "count": record["count"]
                })
            
            # Promedio de riesgo
            avg_risk = session.run("""
                MATCH (d:Domain) 
                WHERE d.risk_score IS NOT NULL 
                RETURN avg(d.risk_score) as avg_risk
            """).single()["avg_risk"]
            
            return {
                "risk_distribution": risk_dist,
                "average_risk_score": avg_risk
            }

    def get_provider_analysis(self):
        """Analiza los proveedores detectados"""
        with self.driver.session() as session:
            # Tipos de proveedores
            provider_types = session.run("""
                MATCH (p:Provider)
                RETURN p.type as provider_type, count(*) as count
                ORDER BY count DESC
            """)
            
            types = []
            for record in provider_types:
                types.append({
                    "provider_type": record["provider_type"] or "Unknown",
                    "count": record["count"]
                })
            
            # Proveedores más usados
            most_used = session.run("""
                MATCH (d:Domain)-[:USES_PROVIDER]->(p:Provider)
                RETURN p.name as provider, count(d) as domains
                ORDER BY domains DESC
                LIMIT 15
            """)
            
            providers = []
            for record in most_used:
                providers.append({
                    "provider": record["provider"],
                    "domains": record["domains"]
                })
            
            return {
                "provider_types": types,
                "most_used_providers": providers
            }

    def get_connectivity_metrics(self):
        """Analiza métricas de conectividad del grafo"""
        with self.driver.session() as session:
            # Dominios con más subdominios
            most_subdomains = session.run("""
                MATCH (base:Domain)-[:HAS_SUBDOMAIN]->(sub:Domain)
                RETURN base.fqdn as domain, count(sub) as subdomain_count
                ORDER BY subdomain_count DESC
                LIMIT 10
            """)
            
            sub_leaders = []
            for record in most_subdomains:
                sub_leaders.append({
                    "domain": record["domain"],
                    "subdomain_count": record["subdomain_count"]
                })
            
            # Dominios con más tecnologías
            most_techs = session.run("""
                MATCH (d:Domain)-[:USES_TECHNOLOGY|USES_TECHNOLOGY_VERSION]->(t)
                RETURN d.fqdn as domain, count(t) as tech_count
                ORDER BY tech_count DESC
                LIMIT 10
            """)
            
            tech_leaders = []
            for record in most_techs:
                tech_leaders.append({
                    "domain": record["domain"],
                    "tech_count": record["tech_count"]
                })
            
            # Distribución de puertos de servicios
            port_dist = session.run("""
                MATCH (s:Service)
                WHERE s.port IS NOT NULL
                RETURN s.port as port, count(*) as count
                ORDER BY count DESC
                LIMIT 15
            """)
            
            ports = []
            for record in port_dist:
                ports.append({
                    "port": record["port"],
                    "count": record["count"]
                })
            
            return {
                "domains_with_most_subdomains": sub_leaders,
                "domains_with_most_technologies": tech_leaders,
                "service_port_distribution": ports
            }

    def run_full_analysis(self):
        """Ejecuta análisis completo del grafo"""
        print("🔍 Iniciando análisis del grafo Neo4j...")
        
        try:
            # Verifica conectividad
            with self.driver.session() as session:
                session.run("RETURN 1")
            print("✅ Conexión a Neo4j exitosa")
            
            # Ejecuta cada análisis
            print("\n📊 Obteniendo estadísticas de nodos...")
            self.analysis_data["node_statistics"] = self.get_node_statistics()
            
            print("🔗 Obteniendo estadísticas de relaciones...")
            self.analysis_data["relationship_statistics"] = self.get_relationship_statistics()
            
            print("🌐 Analizando distribución de dominios...")
            self.analysis_data["domain_distribution"] = self.get_domain_distribution()
            
            print("⚙️ Analizando tecnologías...")
            self.analysis_data["technology_analysis"] = self.get_technology_analysis()
            
            print("⚠️ Analizando distribución de riesgos...")
            self.analysis_data["risk_distribution"] = self.get_risk_distribution()
            
            print("🏢 Analizando proveedores...")
            self.analysis_data["provider_analysis"] = self.get_provider_analysis()
            
            print("🔄 Calculando métricas de conectividad...")
            self.analysis_data["connectivity_metrics"] = self.get_connectivity_metrics()
            
            # Metadatos del análisis
            self.analysis_data["analysis_metadata"] = {
                "timestamp": datetime.now().isoformat(),
                "database_health": "Connected",
                "analysis_version": "1.0.0"
            }
            
            print("✅ Análisis completado exitosamente\n")
            return self.analysis_data
            
        except Exception as e:
            print(f"❌ Error durante el análisis: {str(e)}")
            self.analysis_data["error"] = str(e)
            return self.analysis_data

    def generate_report(self):
        """Genera un reporte detallado en formato texto"""
        if not self.analysis_data:
            return "No hay datos de análisis disponibles"
        
        report = []
        report.append("=" * 80)
        report.append("REPORTE DE ANÁLISIS DEL GRAFO NEO4J - SISTEMA TSUNAMI")
        report.append("=" * 80)
        report.append(f"Fecha: {self.analysis_data.get('analysis_metadata', {}).get('timestamp', 'N/A')}")
        report.append("")
        
        # Estadísticas generales
        if "node_statistics" in self.analysis_data:
            ns = self.analysis_data["node_statistics"]
            report.append("📊 ESTADÍSTICAS DE NODOS")
            report.append("-" * 40)
            report.append(f"Total de nodos: {ns.get('total_nodes', 0):,}")
            report.append("\nDistribución por tipo:")
            for node_type, count in sorted(ns.get('node_types', {}).items(), key=lambda x: x[1], reverse=True):
                report.append(f"  • {node_type}: {count:,}")
            report.append("")
        
        if "relationship_statistics" in self.analysis_data:
            rs = self.analysis_data["relationship_statistics"]
            report.append("🔗 ESTADÍSTICAS DE RELACIONES")
            report.append("-" * 40)
            report.append(f"Total de relaciones: {rs.get('total_relationships', 0):,}")
            report.append("\nDistribución por tipo:")
            for rel_type, count in sorted(rs.get('relationship_types', {}).items(), key=lambda x: x[1], reverse=True):
                report.append(f"  • {rel_type}: {count:,}")
            report.append("")
        
        # Análisis de dominios
        if "domain_distribution" in self.analysis_data:
            dd = self.analysis_data["domain_distribution"]
            report.append("🌐 ANÁLISIS DE DOMINIOS")
            report.append("-" * 40)
            report.append(f"Dominios base: {dd.get('base_domains', 0):,}")
            report.append(f"Subdominios: {dd.get('subdomains', 0):,}")
            report.append("\nTLDs más comunes:")
            for tld in dd.get('top_level_domains', [])[:10]:
                report.append(f"  • .{tld['tld']}: {tld['count']} dominios")
            report.append("")
        
        # Análisis de tecnologías
        if "technology_analysis" in self.analysis_data:
            ta = self.analysis_data["technology_analysis"]
            report.append("⚙️ ANÁLISIS DE TECNOLOGÍAS")
            report.append("-" * 40)
            report.append("Tecnologías más detectadas:")
            for tech in ta.get('most_detected_technologies', [])[:10]:
                report.append(f"  • {tech['technology']}: {tech['domains']} dominios")
            report.append("\nCategorías de tecnologías:")
            for cat in ta.get('technology_categories', [])[:10]:
                report.append(f"  • {cat['category']}: {cat['count']} tecnologías")
            if ta.get('technology_risk_levels'):
                report.append("\nNiveles de riesgo de tecnologías:")
                for risk in ta.get('technology_risk_levels', []):
                    report.append(f"  • {risk['risk_level']}: {risk['count']} versiones")
            report.append("")
        
        # Análisis de riesgos
        if "risk_distribution" in self.analysis_data:
            rd = self.analysis_data["risk_distribution"]
            report.append("⚠️ ANÁLISIS DE RIESGOS")
            report.append("-" * 40)
            avg_risk = rd.get('average_risk_score', 0)
            report.append(f"Puntuación promedio de riesgo: {avg_risk:.2f}")
            report.append("\nDistribución por nivel de riesgo:")
            for risk in rd.get('risk_distribution', []):
                report.append(f"  • {risk['risk_bucket']}: {risk['count']} dominios")
            report.append("")
        
        # Análisis de proveedores
        if "provider_analysis" in self.analysis_data:
            pa = self.analysis_data["provider_analysis"]
            report.append("🏢 ANÁLISIS DE PROVEEDORES")
            report.append("-" * 40)
            report.append("Proveedores más utilizados:")
            for prov in pa.get('most_used_providers', [])[:10]:
                report.append(f"  • {prov['provider']}: {prov['domains']} dominios")
            report.append("\nTipos de proveedores:")
            for ptype in pa.get('provider_types', []):
                report.append(f"  • {ptype['provider_type']}: {ptype['count']} proveedores")
            report.append("")
        
        # Métricas de conectividad
        if "connectivity_metrics" in self.analysis_data:
            cm = self.analysis_data["connectivity_metrics"]
            report.append("🔄 MÉTRICAS DE CONECTIVIDAD")
            report.append("-" * 40)
            report.append("Dominios con más subdominios:")
            for dom in cm.get('domains_with_most_subdomains', [])[:5]:
                report.append(f"  • {dom['domain']}: {dom['subdomain_count']} subdominios")
            report.append("\nDominios con más tecnologías:")
            for dom in cm.get('domains_with_most_technologies', [])[:5]:
                report.append(f"  • {dom['domain']}: {dom['tech_count']} tecnologías")
            report.append("\nPuertos de servicios más comunes:")
            for port in cm.get('service_port_distribution', [])[:10]:
                report.append(f"  • Puerto {port['port']}: {port['count']} servicios")
            report.append("")
        
        report.append("=" * 80)
        report.append("Fin del reporte")
        report.append("=" * 80)
        
        return "\n".join(report)

def main():
    # Configuración de Neo4j desde docker-compose.yml
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "test.password"
    
    analyzer = None
    try:
        print("🚀 Iniciando análisis del grafo Neo4j para el sistema Tsunami")
        print(f"Conectando a: {NEO4J_URI}")
        
        analyzer = GraphAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Ejecuta análisis completo
        analysis_data = analyzer.run_full_analysis()
        
        # Genera reporte
        report = analyzer.generate_report()
        
        # Guarda reporte en archivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"/home/alf/dev/tsunami-beta/graph_analysis_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Guarda datos JSON
        json_file = f"/home/alf/dev/tsunami-beta/graph_analysis_data_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False, default=str)
        
        print("📄 REPORTE GENERADO")
        print("=" * 50)
        print(report)
        print("\n📁 Archivos guardados:")
        print(f"  • Reporte: {report_file}")
        print(f"  • Datos JSON: {json_file}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1
    finally:
        if analyzer:
            analyzer.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())