#!/usr/bin/env python3
"""
Script completo para procesar dominios evitando recursión y calculando riesgos correctamente.
Automatiza todo el proceso desde discovery hasta risk calculation.
"""

import sys
import os
import argparse
sys.path.append('/home/alf/dev/tsunami-beta/risk-graph-loader/app')

from subdomain_relationship_discovery import EnhancedSubdomainGraphIngester
from neo4j import GraphDatabase
import requests
import time
from typing import List, Dict, Set

class CompleteDomainProcessor:
    """Procesador completo de dominios con prevención de recursión."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        self.ipinfo_token = ipinfo_token
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        
    def process_domains(self, domains: List[str], skip_discovery: bool = False) -> Dict[str, any]:
        """Procesar dominios completamente desde discovery hasta risk calculation."""
        
        print(f"🚀 Procesando dominios: {', '.join(domains)}")
        
        results = {
            'processed_domains': [],
            'discovery_stats': {},
            'risk_calculation_stats': {},
            'api_verification': {},
            'errors': []
        }
        
        try:
            # 1. Subdomain Discovery (si no se omite)
            if not skip_discovery:
                print(f"\n=== 1. SUBDOMAIN DISCOVERY ===")
                discovery_stats = self._run_subdomain_discovery(domains)
                results['discovery_stats'] = discovery_stats
            else:
                print(f"\n=== 1. SKIPPING SUBDOMAIN DISCOVERY ===")
            
            # 2. Fix Domain Hierarchy (eliminar recursión y agregar relationships)
            print(f"\n=== 2. FIXING DOMAIN HIERARCHY ===")
            hierarchy_stats = self._fix_domain_hierarchy(domains)
            
            # 3. Calculate Risk Scores
            print(f"\n=== 3. CALCULATING RISK SCORES ===")
            risk_stats = self._calculate_risk_scores(domains)
            results['risk_calculation_stats'] = risk_stats
            
            # 4. Verify APIs
            print(f"\n=== 4. VERIFYING APIs ===")
            api_stats = self._verify_apis(domains)
            results['api_verification'] = api_stats
            
            # 5. Final Summary
            print(f"\n=== 5. FINAL SUMMARY ===")
            summary = self._generate_summary(domains)
            results['processed_domains'] = summary
            
            return results
            
        except Exception as e:
            error_msg = f"Error processing domains: {e}"
            print(f"❌ {error_msg}")
            results['errors'].append(error_msg)
            return results
    
    def _run_subdomain_discovery(self, domains: List[str]) -> Dict[str, any]:
        """Run subdomain discovery for domains."""
        
        # Initialize ingester with input domains to prevent recursion
        ingester = EnhancedSubdomainGraphIngester(
            neo4j_uri=self.neo4j_uri,
            neo4j_user=self.neo4j_user, 
            neo4j_pass=self.neo4j_pass,
            ipinfo_token=self.ipinfo_token
        )
        
        # Set input domains to prevent recursion
        ingester.set_input_domains(domains)
        
        stats = {}
        
        for domain in domains:
            print(f"🔍 Discovering subdomains for {domain}...")
            try:
                # Create domain hierarchy
                hierarchy_stats = ingester.create_enhanced_domain_hierarchy_batch([domain])
                
                # Discover cross-domain relationships
                relationship_stats = ingester.discover_cross_domain_relationships()
                
                stats[domain] = {
                    'hierarchy_created': True,
                    'relationships_discovered': True,
                    'hierarchy_stats': hierarchy_stats,
                    'relationship_stats': relationship_stats
                }
                
                print(f"✅ {domain}: Discovery completed")
                
            except Exception as e:
                error_msg = f"Discovery failed for {domain}: {e}"
                print(f"❌ {error_msg}")
                stats[domain] = {'error': error_msg}
        
        return stats
    
    def _fix_domain_hierarchy(self, domains: List[str]) -> Dict[str, any]:
        """Fix domain hierarchy to prevent recursion and aggregate services/providers."""
        
        stats = {}
        
        with self.driver.session() as session:
            for domain in domains:
                print(f"🔧 Fixing hierarchy for {domain}...")
                
                try:
                    # Remove any recursive subdomain entries
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain}), (s:Subdomain {fqdn: $domain})
                        DETACH DELETE s
                        RETURN count(*) as deleted_recursive
                    """, domain=domain)
                    
                    deleted_recursive = result.single()["deleted_recursive"]
                    
                    # Ensure SUBDOMAIN_OF relationships exist
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (s:Subdomain {base_domain: $domain})
                        WHERE NOT (s)-[:SUBDOMAIN_OF]->(d)
                        CREATE (s)-[:SUBDOMAIN_OF]->(d)
                        RETURN count(*) as created_relations
                    """, domain=domain)
                    
                    created_relations = result.single()["created_relations"]
                    
                    # Ensure HAS_SUBDOMAIN relationships exist (for Java backend compatibility)
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})<-[:SUBDOMAIN_OF]-(s:Subdomain)
                        WHERE NOT (d)-[:HAS_SUBDOMAIN]->(s)
                        CREATE (d)-[:HAS_SUBDOMAIN]->(s)
                        RETURN count(*) as created_has_relations
                    """, domain=domain)
                    
                    created_has_relations = result.single()["created_has_relations"]
                    
                    # Aggregate services from subdomains to domain
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (s:Subdomain {base_domain: $domain})-[:DEPENDS_ON]->(svc:Service)
                        WHERE NOT (d)-[:DEPENDS_ON]->(svc) AND NOT (d)-[:RUNS]->(svc)
                        CREATE (d)-[:DEPENDS_ON]->(svc)
                        CREATE (d)-[:RUNS]->(svc)
                        RETURN count(DISTINCT svc) as aggregated_services
                    """, domain=domain)
                    
                    aggregated_services = result.single()["aggregated_services"]
                    
                    # Aggregate providers from subdomains to domain
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (s:Subdomain {base_domain: $domain})-[:DEPENDS_ON]->(p:Provider)
                        WHERE NOT (d)-[:DEPENDS_ON]->(p)
                        CREATE (d)-[:DEPENDS_ON]->(p)
                        RETURN count(DISTINCT p) as aggregated_providers
                    """, domain=domain)
                    
                    aggregated_providers = result.single()["aggregated_providers"]
                    
                    stats[domain] = {
                        'deleted_recursive': deleted_recursive,
                        'created_relations': created_relations,
                        'created_has_relations': created_has_relations,
                        'aggregated_services': aggregated_services,
                        'aggregated_providers': aggregated_providers
                    }
                    
                    print(f"✅ {domain}: Hierarchy fixed")
                    
                except Exception as e:
                    error_msg = f"Hierarchy fix failed for {domain}: {e}"
                    print(f"❌ {error_msg}")
                    stats[domain] = {'error': error_msg}
        
        return stats
    
    def _calculate_risk_scores(self, domains: List[str]) -> Dict[str, any]:
        """Calculate risk scores for domains based on subdomains, services, and providers."""
        
        stats = {}
        
        with self.driver.session() as session:
            for domain in domains:
                print(f"🎯 Calculating risk for {domain}...")
                
                try:
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
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
                        
                        // Enhanced risk calculation
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
                    """, domain=domain)
                    
                    if result.peek():
                        record = result.single()
                        stats[domain] = {
                            'risk_score': record['risk_score'],
                            'risk_tier': record['risk_tier'],
                            'subdomain_count': record['subdomain_count'],
                            'service_count': record['service_count'],
                            'provider_count': record['provider_count']
                        }
                        
                        print(f"✅ {domain}: Risk {record['risk_score']:.1f} ({record['risk_tier']})")
                    else:
                        stats[domain] = {'error': 'Domain not found'}
                        print(f"❌ {domain}: Not found in database")
                        
                except Exception as e:
                    error_msg = f"Risk calculation failed for {domain}: {e}"
                    print(f"❌ {error_msg}")
                    stats[domain] = {'error': error_msg}
        
        return stats
    
    def _verify_apis(self, domains: List[str]) -> Dict[str, any]:
        """Verify that APIs are working correctly for the domains."""
        
        stats = {}
        
        for domain in domains:
            print(f"🌐 Verifying APIs for {domain}...")
            
            domain_stats = {}
            
            try:
                # Test domain API
                response = requests.get(f"http://localhost:8081/api/v1/domains/{domain}?includeIncidents=true", timeout=5)
                domain_stats['domain_api'] = {
                    'status_code': response.status_code,
                    'working': response.status_code == 200
                }
                
                if response.status_code == 200:
                    data = response.json()
                    domain_stats['domain_api']['data'] = {
                        'risk_score': data.get('risk_score', 0),
                        'risk_tier': data.get('risk_tier', 'Unknown')
                    }
                
                # Test dependencies API
                response = requests.get(f"http://localhost:8081/api/v1/dependencies/domain/{domain}/providers-services?includeRisk=true", timeout=5)
                domain_stats['dependencies_api'] = {
                    'status_code': response.status_code,
                    'working': response.status_code == 200
                }
                
                if response.status_code == 200:
                    data = response.json()
                    domain_stats['dependencies_api']['data'] = data.get('summary', {})
                
                # Test base domain details API
                response = requests.get(f"http://localhost:8081/api/v1/domains/base-domains/{domain}/details?includeRiskBreakdown=true", timeout=5)
                domain_stats['base_domain_api'] = {
                    'status_code': response.status_code,
                    'working': response.status_code == 200
                }
                
                if response.status_code == 200:
                    data = response.json()
                    domain_stats['base_domain_api']['data'] = {
                        'total_subdomains': data.get('total_count', 0),
                        'total_services': data.get('service_summary', {}).get('total_services', 0),
                        'total_providers': data.get('provider_summary', {}).get('total_providers', 0)
                    }
                
                all_working = all(api.get('working', False) for api in domain_stats.values())
                print(f"{'✅' if all_working else '❌'} {domain}: APIs {'working' if all_working else 'have issues'}")
                
            except Exception as e:
                error_msg = f"API verification failed for {domain}: {e}"
                print(f"❌ {error_msg}")
                domain_stats['error'] = error_msg
            
            stats[domain] = domain_stats
        
        return stats
    
    def _generate_summary(self, domains: List[str]) -> List[Dict[str, any]]:
        """Generate final summary of processed domains."""
        
        summary = []
        
        with self.driver.session() as session:
            for domain in domains:
                try:
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
                        OPTIONAL MATCH (d)<-[:SUBDOMAIN_OF]-(s:Subdomain)
                        OPTIONAL MATCH (d)-[:RUNS]->(svc:Service)
                        OPTIONAL MATCH (d)-[:DEPENDS_ON]->(p:Provider)
                        OPTIONAL MATCH (recursive:Subdomain {fqdn: $domain})
                        
                        RETURN 
                            d.fqdn as domain_fqdn,
                            d.risk_score as risk_score,
                            d.risk_tier as risk_tier,
                            d.last_calculated as last_calculated,
                            count(DISTINCT s) as subdomains,
                            count(DISTINCT svc) as services,
                            count(DISTINCT p) as providers,
                            count(recursive) as recursive_entries
                    """, domain=domain)
                    
                    if result.peek():
                        record = result.single()
                        summary.append({
                            'domain': record['domain_fqdn'],
                            'risk_score': record['risk_score'],
                            'risk_tier': record['risk_tier'],
                            'last_calculated': str(record['last_calculated']) if record['last_calculated'] else None,
                            'subdomains': record['subdomains'],
                            'services': record['services'],
                            'providers': record['providers'],
                            'no_recursion': record['recursive_entries'] == 0,
                            'status': 'success'
                        })
                        
                        print(f"✅ {domain}: Complete - Risk {record['risk_score']:.1f} ({record['risk_tier']}) | "
                              f"Subs: {record['subdomains']} | Svcs: {record['services']} | Provs: {record['providers']}")
                    else:
                        summary.append({
                            'domain': domain,
                            'status': 'not_found',
                            'error': 'Domain not found in database'
                        })
                        print(f"❌ {domain}: Not found")
                        
                except Exception as e:
                    summary.append({
                        'domain': domain,
                        'status': 'error',
                        'error': str(e)
                    })
                    print(f"❌ {domain}: Error - {e}")
        
        return summary
    
    def close(self):
        """Close database connection."""
        self.driver.close()

def main():
    parser = argparse.ArgumentParser(description='Complete domain processor with recursion prevention')
    parser.add_argument('domains', nargs='+', help='Domains to process')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-pass', default='test.password', help='Neo4j password')
    parser.add_argument('--ipinfo-token', help='IPInfo token for enhanced provider detection')
    parser.add_argument('--skip-discovery', action='store_true', help='Skip subdomain discovery phase')
    
    args = parser.parse_args()
    
    processor = CompleteDomainProcessor(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_pass=args.neo4j_pass,
        ipinfo_token=args.ipinfo_token
    )
    
    try:
        results = processor.process_domains(args.domains, skip_discovery=args.skip_discovery)
        
        print(f"\n🎉 PROCESSING COMPLETE!")
        print(f"   Processed: {len(results['processed_domains'])} domains")
        print(f"   Errors: {len(results['errors'])}")
        
        if results['errors']:
            print(f"\n❌ ERRORS:")
            for error in results['errors']:
                print(f"   - {error}")
        
        return 0 if not results['errors'] else 1
        
    finally:
        processor.close()

if __name__ == "__main__":
    sys.exit(main())