#!/usr/bin/env python3
"""
Script para probar el análisis detallado de un solo dominio
"""

import sys
import logging
import argparse
from subdomain_relationship_discovery_v4 import EnhancedSubdomainProcessor, EnhancedSubdomainGraphIngester

# Configurar logging detallado
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('single_domain_debug.log')
    ]
)

def test_single_domain(domain: str, password: str):
    """Test processing of a single domain with detailed logging"""
    
    print(f"\n🔬 ANÁLISIS DETALLADO DE: {domain}")
    print("=" * 60)
    
    # Initialize ingester first with improved TLS settings
    ingester = EnhancedSubdomainGraphIngester(
        neo4j_uri='bolt://localhost:7687',
        neo4j_user='neo4j', 
        neo4j_pass=password,
        ipinfo_token='0bf607ce2c13ac',
        enable_tls_analysis=True,
        enable_service_detection=True,
        enable_provider_detection=True,
        enable_industry_classification=True,
        max_analysis_workers=1,
        tls_timeout=60,  # Increased timeout for slow banking domains
        tls_retries=3    # More retries for reliability
    )
    
    # Initialize processor with ingester and enhanced discovery settings  
    processor = EnhancedSubdomainProcessor(
        ingester=ingester,
        neo4j_uri='bolt://localhost:7687',
        neo4j_user='neo4j', 
        neo4j_pass=password,
        discovery_workers=1,
        processing_workers=1,
        discovery_depth=3  # Deeper discovery, no limits on subdomains per level
    )
    
    try:
        print(f"\n📍 FASE 1: DISCOVERY")
        print("-" * 30)
        
        # Run discovery phase
        results = processor.enhanced_phase1_discovery([domain])
        
        print(f"✅ Discovery completed:")
        print(f"   • Domains processed: {results.get('domains_processed', 0)}")
        print(f"   • Subdomains found: {results.get('total_subdomains_discovered', 0)}")
        print(f"   • Processing time: {results.get('processing_time', 0):.2f}s")
        
        print(f"\n📍 FASE 2: ANALYSIS")
        print("-" * 30)
        
        # Run analysis phase
        analysis_results = processor.enhanced_phase2_processing(batch_size=10)
        
        print(f"✅ Analysis completed:")
        print(f"   • Subdomains processed: {analysis_results.get('subdomains_processed', 0)}")
        print(f"   • Processing time: {analysis_results.get('processing_time', 0):.2f}s")
        
        # Check database state
        print(f"\n📊 RESULTADOS EN NEO4J:")
        print("-" * 30)
        
        with ingester.driver.session() as session:
            # Count nodes by type
            for node_type in ['Domain', 'Subdomain', 'Provider', 'Service', 'Certificate', 'Industry']:
                result = session.run(f'MATCH (n:{node_type}) WHERE n.fqdn CONTAINS $domain OR n.domain CONTAINS $domain RETURN count(n) as count', domain=domain)
                count = result.single()['count']
                print(f"   • {node_type} nodes: {count}")
            
            # Show sample nodes
            result = session.run("""
                MATCH (n) 
                WHERE (n.fqdn CONTAINS $domain OR n.domain CONTAINS $domain)
                RETURN labels(n)[0] as type, n.fqdn as fqdn, n.domain as domain
                LIMIT 10
            """, domain=domain)
            
            print(f"\n📋 NODOS CREADOS:")
            for record in result:
                fqdn = record.get('fqdn', record.get('domain', 'N/A'))
                print(f"   • {record['type']}: {fqdn}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.exception("Detailed error:")
    
    finally:
        ingester.close()

def main():
    parser = argparse.ArgumentParser(description='Test single domain processing')
    parser.add_argument('domain', help='Domain to analyze (e.g., bci.cl)')
    parser.add_argument('--password', required=True, help='Neo4j password')
    
    args = parser.parse_args()
    
    test_single_domain(args.domain, args.password)

if __name__ == "__main__":
    main()