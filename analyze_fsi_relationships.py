#!/usr/bin/env python3
"""
FSI Domain Relationship Analysis - Análisis comprehensivo de relaciones entre dominios FSI

Este script analiza las relaciones entre dominios del sector financiero chileno,
incluyendo subdominios de nivel 3, servicios, proveedores y patrones de conectividad.
"""

import sys
import json
from typing import Dict, List, Any, Set
from collections import defaultdict, Counter
from neo4j import GraphDatabase
import time

class FSIRelationshipAnalyzer:
    """Analizador de relaciones para dominios del sector financiero."""
    
    def __init__(self, neo4j_uri: str = "bolt://localhost:7687", 
                 neo4j_user: str = "neo4j", neo4j_pass: str = "test.password"):
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        
        # Dominios FSI por categoría
        self.fsi_domains = {
            'bancos': [
                'bancochile.cl', 'santander.cl', 'bci.cl', 'itau.cl', 'scotiabank.cl',
                'bancoestado.cl', 'bancointernacional.cl', 'security.cl', 'bancoconsorcio.cl',
                'bancofalabella.cl', 'bancoripley.cl', 'bice.cl', 'btgpactual.cl', 'bb.cl'
            ],
            'cooperativas': [
                'coopeuch.cl', 'cajalosandes.cl', 'caja18.cl', 'laaraucana.cl', 'losheroes.cl'
            ],
            'procesadores_pagos': [
                'transbank.cl', 'redbanc.cl'
            ],
            'seguros': [
                'sura.cl', 'metlife.cl', 'zurich.cl', 'consorcio.cl', 'bicevida.cl', 'principal.cl'
            ],
            'afp': [
                'afphabitat.cl', 'afpcuprum.cl'
            ]
        }
    
    def analyze_subdomain_distribution(self) -> Dict[str, Any]:
        """Analiza la distribución de subdominios por categoría y dominio."""
        print("🔍 ANÁLISIS DE DISTRIBUCIÓN DE SUBDOMINIOS")
        print("="*60)
        
        results = {}
        
        with self.drv.session() as session:
            for categoria, dominios in self.fsi_domains.items():
                categoria_stats = {}
                total_subdominios = 0
                
                for dominio in dominios:
                    result = session.run("""
                        MATCH (s:Subdomain {base_domain: $dominio})
                        RETURN count(s) as subdomain_count
                    """, dominio=dominio)
                    
                    count = result.single()['subdomain_count'] if result.peek() else 0
                    categoria_stats[dominio] = count
                    total_subdominios += count
                
                results[categoria] = {
                    'dominios': categoria_stats,
                    'total_subdominios': total_subdominios,
                    'promedio_por_dominio': total_subdominios / len(dominios) if dominios else 0
                }
                
                print(f"\n{categoria.upper()}:")
                print(f"  Total subdominios: {total_subdominios}")
                print(f"  Promedio por dominio: {results[categoria]['promedio_por_dominio']:.1f}")
                
                # Top 5 dominios con más subdominios en esta categoría
                top_dominios = sorted(categoria_stats.items(), key=lambda x: x[1], reverse=True)[:5]
                for dominio, count in top_dominios:
                    print(f"    {dominio}: {count} subdominios")
        
        return results
    
    def analyze_subdomain_patterns(self) -> Dict[str, Any]:
        """Analiza patrones comunes en nombres de subdominios."""
        print("\n🎯 ANÁLISIS DE PATRONES DE SUBDOMINIOS")
        print("="*60)
        
        with self.drv.session() as session:
            # Obtener todos los subdominios FSI
            all_domains = [d for categoria in self.fsi_domains.values() for d in categoria]
            
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.base_domain IN $domains
                RETURN s.fqdn, s.base_domain
            """, domains=all_domains)
            
            subdomains = [(record['s.fqdn'], record['s.base_domain']) for record in result]
        
        # Análisis de prefijos
        prefixes = Counter()
        subdomain_levels = Counter()
        common_patterns = Counter()
        
        for fqdn, base_domain in subdomains:
            # Extraer prefijo del subdominio
            subdomain_part = fqdn.replace(f".{base_domain}", "")
            parts = subdomain_part.split('.')
            
            # Contar niveles de subdominio
            levels = len(parts)
            subdomain_levels[levels] += 1
            
            # Analizar prefijos
            if parts:
                prefix = parts[-1]  # Último componente (más cercano al dominio base)
                prefixes[prefix] += 1
                
                # Patrones comunes
                if any(pattern in prefix.lower() for pattern in ['www', 'api', 'mail', 'admin', 'test', 'dev']):
                    common_patterns[prefix.lower()] += 1
        
        print(f"Total subdominios analizados: {len(subdomains)}")
        
        print(f"\nDistribución por niveles:")
        for level, count in sorted(subdomain_levels.items()):
            print(f"  Nivel {level}: {count} subdominios")
        
        print(f"\nTop 20 prefijos más comunes:")
        for prefix, count in prefixes.most_common(20):
            print(f"  {prefix}: {count}")
        
        print(f"\nPatrones de servicios detectados:")
        for pattern, count in common_patterns.most_common(10):
            print(f"  {pattern}: {count}")
        
        return {
            'total_subdomains': len(subdomains),
            'level_distribution': dict(subdomain_levels),
            'top_prefixes': dict(prefixes.most_common(20)),
            'service_patterns': dict(common_patterns.most_common(10))
        }
    
    def analyze_shared_infrastructure(self) -> Dict[str, Any]:
        """Analiza infraestructura compartida entre instituciones FSI."""
        print("\n🌐 ANÁLISIS DE INFRAESTRUCTURA COMPARTIDA")
        print("="*60)
        
        with self.drv.session() as session:
            all_domains = [d for categoria in self.fsi_domains.values() for d in categoria]
            
            # Análisis de IPs compartidas
            result = session.run("""
                MATCH (d1)-[:RESOLVES_TO]->(ip:IPAddress)<-[:RESOLVES_TO]-(d2)
                WHERE (d1:Domain OR d1:Subdomain) AND (d2:Domain OR d2:Subdomain)
                AND d1.base_domain IN $domains AND d2.base_domain IN $domains
                AND d1.base_domain <> d2.base_domain
                RETURN ip.address as shared_ip, 
                       collect(DISTINCT d1.base_domain) + collect(DISTINCT d2.base_domain) as domains,
                       count(DISTINCT d1) + count(DISTINCT d2) as total_domains
                ORDER BY total_domains DESC
                LIMIT 20
            """, domains=all_domains)
            
            shared_ips = []
            for record in result:
                shared_ips.append({
                    'ip': record['shared_ip'],
                    'domains': list(set(record['domains'])),
                    'count': record['total_domains']
                })
            
            # Análisis de proveedores compartidos
            result = session.run("""
                MATCH (d1)-[:USES_SERVICE]->(p:Provider)<-[:USES_SERVICE]-(d2)
                WHERE (d1:Domain OR d1:Subdomain) AND (d2:Domain OR d2:Subdomain)
                AND d1.base_domain IN $domains AND d2.base_domain IN $domains
                AND d1.base_domain <> d2.base_domain
                RETURN p.name as provider_name,
                       collect(DISTINCT d1.base_domain) + collect(DISTINCT d2.base_domain) as domains,
                       count(DISTINCT d1) + count(DISTINCT d2) as usage_count
                ORDER BY usage_count DESC
                LIMIT 15
            """, domains=all_domains)
            
            shared_providers = []
            for record in result:
                shared_providers.append({
                    'provider': record['provider_name'],
                    'domains': list(set(record['domains'])),
                    'usage_count': record['usage_count']
                })
            
            print("IPs compartidas entre instituciones FSI:")
            for item in shared_ips[:10]:
                domains_str = ', '.join(item['domains'][:3])
                if len(item['domains']) > 3:
                    domains_str += f" (+{len(item['domains'])-3} más)"
                print(f"  {item['ip']}: {domains_str}")
            
            print("\nProveedores compartidos:")
            for item in shared_providers[:10]:
                domains_str = ', '.join(item['domains'][:3])
                if len(item['domains']) > 3:
                    domains_str += f" (+{len(item['domains'])-3} más)"
                print(f"  {item['provider']}: {domains_str}")
        
        return {
            'shared_ips': shared_ips,
            'shared_providers': shared_providers
        }
    
    def analyze_service_distribution(self) -> Dict[str, Any]:
        """Analiza la distribución de servicios detectados."""
        print("\n🔧 ANÁLISIS DE SERVICIOS DETECTADOS")
        print("="*60)
        
        with self.drv.session() as session:
            all_domains = [d for categoria in self.fsi_domains.values() for d in categoria]
            
            # Servicios por tipo
            result = session.run("""
                MATCH (s:Subdomain)-[:RUNS]->(srv:Service)
                WHERE s.base_domain IN $domains
                RETURN srv.type as service_type, count(srv) as count,
                       collect(DISTINCT s.base_domain) as domains
                ORDER BY count DESC
            """, domains=all_domains)
            
            services_by_type = {}
            for record in result:
                services_by_type[record['service_type']] = {
                    'count': record['count'],
                    'domains': record['domains']
                }
            
            # Servicios por dominio
            result = session.run("""
                MATCH (s:Subdomain)-[:RUNS]->(srv:Service)
                WHERE s.base_domain IN $domains
                RETURN s.base_domain as domain, 
                       collect(DISTINCT srv.type) as service_types,
                       count(srv) as total_services
                ORDER BY total_services DESC
            """, domains=all_domains)
            
            services_by_domain = {}
            for record in result:
                services_by_domain[record['domain']] = {
                    'service_types': record['service_types'],
                    'total_services': record['total_services']
                }
            
            print("Distribución de servicios por tipo:")
            for service_type, data in sorted(services_by_type.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
                print(f"  {service_type}: {data['count']} instancias en {len(data['domains'])} dominios")
            
            print("\nTop 10 dominios con más servicios:")
            for domain, data in sorted(services_by_domain.items(), key=lambda x: x[1]['total_services'], reverse=True)[:10]:
                types_str = ', '.join(data['service_types'][:3])
                if len(data['service_types']) > 3:
                    types_str += f" (+{len(data['service_types'])-3} más)"
                print(f"  {domain}: {data['total_services']} servicios ({types_str})")
        
        return {
            'services_by_type': services_by_type,
            'services_by_domain': services_by_domain
        }
    
    def analyze_cross_category_relationships(self) -> Dict[str, Any]:
        """Analiza relaciones entre diferentes categorías FSI."""
        print("\n🔗 ANÁLISIS DE RELACIONES ENTRE CATEGORÍAS")
        print("="*60)
        
        results = {}
        
        with self.drv.session() as session:
            for cat1, dominios1 in self.fsi_domains.items():
                for cat2, dominios2 in self.fsi_domains.items():
                    if cat1 >= cat2:  # Evitar duplicados
                        continue
                    
                    # Buscar relaciones entre categorías
                    result = session.run("""
                        MATCH (d1)-[:RESOLVES_TO]->(ip:IPAddress)<-[:RESOLVES_TO]-(d2)
                        WHERE (d1:Domain OR d1:Subdomain) AND (d2:Domain OR d2:Subdomain)
                        AND d1.base_domain IN $dominios1 AND d2.base_domain IN $dominios2
                        RETURN count(DISTINCT ip) as shared_ips,
                               collect(DISTINCT d1.base_domain)[0..3] as sample_domains1,
                               collect(DISTINCT d2.base_domain)[0..3] as sample_domains2
                    """, dominios1=dominios1, dominios2=dominios2)
                    
                    relationship_data = result.single()
                    if relationship_data and relationship_data['shared_ips'] > 0:
                        key = f"{cat1} <-> {cat2}"
                        results[key] = {
                            'shared_ips': relationship_data['shared_ips'],
                            'sample_domains1': relationship_data['sample_domains1'],
                            'sample_domains2': relationship_data['sample_domains2']
                        }
                        
                        print(f"{cat1.upper()} <-> {cat2.upper()}:")
                        print(f"  IPs compartidas: {relationship_data['shared_ips']}")
                        if relationship_data['sample_domains1'] and relationship_data['sample_domains2']:
                            print(f"  Ejemplo: {relationship_data['sample_domains1'][0]} <-> {relationship_data['sample_domains2'][0]}")
        
        return results
    
    def analyze_tls_security_posture(self) -> Dict[str, Any]:
        """Analiza la postura de seguridad TLS del sector FSI."""
        print("\n🔒 ANÁLISIS DE POSTURA DE SEGURIDAD TLS")
        print("="*60)
        
        with self.drv.session() as session:
            all_domains = [d for categoria in self.fsi_domains.values() for d in categoria]
            
            # Distribución de grados TLS
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.base_domain IN $domains
                AND s.tls_grade IS NOT NULL
                RETURN s.tls_grade as grade, count(s) as count,
                       collect(DISTINCT s.base_domain) as domains
                ORDER BY count DESC
            """, domains=all_domains)
            
            tls_grades = {}
            for record in result:
                tls_grades[record['grade']] = {
                    'count': record['count'],
                    'domains': record['domains']
                }
            
            # Subdominios sin TLS
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.base_domain IN $domains
                RETURN 
                    count(CASE WHEN s.has_tls = true THEN 1 END) as with_tls,
                    count(CASE WHEN s.has_tls = false THEN 1 END) as without_tls,
                    count(CASE WHEN s.tls_grade IS NULL THEN 1 END) as not_analyzed,
                    count(s) as total
            """, domains=all_domains)
            
            tls_coverage = dict(result.single())
            
            print("Distribución de grados TLS:")
            for grade, data in sorted(tls_grades.items(), key=lambda x: x[1]['count'], reverse=True):
                print(f"  Grado {grade}: {data['count']} subdominios")
            
            print(f"\nCobertura TLS:")
            print(f"  Con TLS: {tls_coverage['with_tls']}")
            print(f"  Sin TLS: {tls_coverage['without_tls']}")
            print(f"  No analizados: {tls_coverage['not_analyzed']}")
            print(f"  Total: {tls_coverage['total']}")
            
            if tls_coverage['total'] > 0:
                coverage_pct = (tls_coverage['with_tls'] / tls_coverage['total']) * 100
                print(f"  Cobertura TLS: {coverage_pct:.1f}%")
        
        return {
            'tls_grades': tls_grades,
            'tls_coverage': tls_coverage
        }
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Genera un reporte comprehensivo del análisis FSI."""
        print("\n📊 GENERANDO REPORTE COMPREHENSIVO FSI")
        print("="*80)
        
        start_time = time.time()
        
        report = {
            'metadata': {
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_institutions': sum(len(domains) for domains in self.fsi_domains.values()),
                'categories': list(self.fsi_domains.keys())
            }
        }
        
        # Ejecutar todos los análisis
        report['subdomain_distribution'] = self.analyze_subdomain_distribution()
        report['subdomain_patterns'] = self.analyze_subdomain_patterns()
        report['shared_infrastructure'] = self.analyze_shared_infrastructure()
        report['service_distribution'] = self.analyze_service_distribution()
        report['cross_category_relationships'] = self.analyze_cross_category_relationships()
        report['tls_security_posture'] = self.analyze_tls_security_posture()
        
        end_time = time.time()
        report['metadata']['analysis_duration'] = f"{end_time - start_time:.2f} seconds"
        
        print(f"\n✅ ANÁLISIS COMPLETADO EN {report['metadata']['analysis_duration']}")
        print("="*80)
        
        return report
    
    def close(self):
        """Cierra la conexión a Neo4j."""
        if self.drv:
            self.drv.close()

def main():
    """Función principal."""
    print("🏦 ANÁLISIS DE RELACIONES DEL SECTOR FINANCIERO CHILENO")
    print("="*80)
    print("Analizando subdominios, servicios, proveedores y relaciones")
    print("con descubrimiento de nivel 3 de profundidad")
    print("="*80)
    
    analyzer = FSIRelationshipAnalyzer()
    
    try:
        # Generar reporte comprehensivo
        report = analyzer.generate_comprehensive_report()
        
        # Guardar reporte en archivo JSON
        with open('fsi_analysis_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 Reporte guardado en: fsi_analysis_report.json")
        
        # Mostrar resumen ejecutivo
        print("\n📋 RESUMEN EJECUTIVO")
        print("="*40)
        
        total_subdomains = sum(cat['total_subdominios'] for cat in report['subdomain_distribution'].values())
        print(f"🎯 Total subdominios descubiertos: {total_subdomains}")
        print(f"🏢 Instituciones analizadas: {report['metadata']['total_institutions']}")
        print(f"🔧 Servicios únicos detectados: {len(report['service_distribution']['services_by_type'])}")
        print(f"🌐 Proveedores únicos identificados: {len(report['shared_infrastructure']['shared_providers'])}")
        
        # Top categorías por subdominios
        top_categories = sorted(report['subdomain_distribution'].items(), 
                              key=lambda x: x[1]['total_subdominios'], reverse=True)
        print(f"\n🥇 Top categorías por subdominios:")
        for i, (categoria, data) in enumerate(top_categories[:3], 1):
            print(f"  {i}. {categoria}: {data['total_subdominios']} subdominios")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error en el análisis: {e}")
        return 1
    finally:
        analyzer.close()

if __name__ == "__main__":
    sys.exit(main())