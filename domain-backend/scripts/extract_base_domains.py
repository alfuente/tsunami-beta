#!/usr/bin/env python3
"""
Script para extraer todos los dominios base que existen en el grafo Neo4j

Este script conecta a Neo4j y extrae todos los dominios base únicos que existen
en la base de datos, junto con información adicional como TLD, clasificación
industrial y estadísticas básicas.
"""

import sys
import json
import csv
from neo4j import GraphDatabase
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BaseDomainExtractor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="test.password"):
        """Initialize Neo4j connection"""
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info(f"Connected to Neo4j at {uri}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def extract_base_domains(self):
        """Extract all base domains from the graph"""
        # Primary query: get base domains from Domain nodes (these ARE the base domains)
        domain_query = """
        MATCH (d:Domain)
        RETURN d.fqdn as base_domain,
               d.tld as tld,
               d.primary_industry as industry,
               d.tld_country_code as country_code,
               0 as subdomain_count_from_subdomains
        """
        
        # Secondary query: get base domains from Subdomain nodes that have base_domain field
        subdomain_query = """
        MATCH (s:Subdomain)
        WHERE s.base_domain IS NOT NULL AND s.base_domain <> ""
        WITH s.base_domain as base_domain,
             SPLIT(s.base_domain, '.')[-1] as tld,
             s.primary_industry as industry,
             s.tld_country_code as country_code
        RETURN DISTINCT base_domain,
               tld,
               industry,
               country_code,
               count(*) as subdomain_count_from_subdomains
        ORDER BY base_domain
        """
        
        # Combined query to get all unique base domains
        combined_query = """
        // Get base domains from Domain nodes
        MATCH (d:Domain)
        WITH d.fqdn as base_domain,
             d.tld as tld,
             d.primary_industry as industry,
             d.tld_country_code as country_code
        
        // Count subdomains for each base domain
        OPTIONAL MATCH (s:Subdomain)
        WHERE s.base_domain = base_domain
        
        RETURN base_domain,
               tld,
               industry,
               country_code,
               count(s) as subdomain_count
        ORDER BY base_domain
        """
        
        base_domains = []
        
        try:
            with self.driver.session() as session:
                result = session.run(combined_query)
                
                for record in result:
                    base_domain_info = {
                        'base_domain': record['base_domain'],
                        'tld': record['tld'].lower() if record['tld'] else None,
                        'industry_classification': record['industry'],
                        'country_code': record['country_code'],
                        'subdomain_count': record['subdomain_count']
                    }
                    base_domains.append(base_domain_info)
                    
            logger.info(f"Extracted {len(base_domains)} base domains")
            return base_domains
            
        except Exception as e:
            logger.error(f"Error extracting base domains: {e}")
            return []
    
    def get_domain_statistics(self):
        """Get general statistics about domains in the graph"""
        queries = {
            'total_domains': "MATCH (d:Domain) RETURN count(d) as count",
            'total_base_domains': "MATCH (d:Domain) RETURN count(d) as count",  # Domain nodes ARE base domains
            'total_subdomains': "MATCH (s:Subdomain) RETURN count(s) as count",
            'domains_with_risk': "MATCH (d:Domain) WHERE d.risk_score IS NOT NULL RETURN count(d) as count",
            'subdomains_with_risk': "MATCH (s:Subdomain) WHERE s.risk_score IS NOT NULL RETURN count(s) as count",
            'tld_distribution': """
                MATCH (d:Domain)
                WHERE d.tld IS NOT NULL
                RETURN d.tld as tld, count(*) as count
                ORDER BY count DESC
                LIMIT 10
            """,
            'industry_distribution': """
                MATCH (d:Domain)
                WHERE d.primary_industry IS NOT NULL
                RETURN d.primary_industry as industry, count(*) as count
                ORDER BY count DESC
                LIMIT 10
            """,
            'subdomain_by_base_domain': """
                MATCH (s:Subdomain)
                WHERE s.base_domain IS NOT NULL
                RETURN s.base_domain as base_domain, count(*) as subdomain_count
                ORDER BY subdomain_count DESC
                LIMIT 10
            """
        }
        
        statistics = {}
        
        try:
            with self.driver.session() as session:
                for stat_name, query in queries.items():
                    result = session.run(query)
                    
                    if stat_name in ['tld_distribution', 'industry_distribution', 'subdomain_by_base_domain']:
                        statistics[stat_name] = [dict(record) for record in result]
                    else:
                        record = result.single()
                        statistics[stat_name] = record['count'] if record else 0
                        
            logger.info("Extracted domain statistics")
            return statistics
            
        except Exception as e:
            logger.error(f"Error extracting statistics: {e}")
            return {}
    
    def get_providers_and_services(self):
        """Extract providers and services information"""
        provider_query = """
        MATCH (p:Provider)
        RETURN p.name as name, 
               p.tld as tld, 
               p.country as country,
               p.provider_type as provider_type,
               p.confidence as confidence,
               p.source as source
        ORDER BY p.name
        """
        
        service_query = """
        MATCH (s:Service)
        RETURN s.name as name,
               s.service_type as service_type,
               s.detection_method as detection_method,
               s.confidence as confidence
        ORDER BY s.name
        """
        
        providers = []
        services = []
        
        try:
            with self.driver.session() as session:
                # Extract providers
                result = session.run(provider_query)
                for record in result:
                    providers.append(dict(record))
                
                # Extract services
                result = session.run(service_query)
                for record in result:
                    services.append(dict(record))
                    
            logger.info(f"Extracted {len(providers)} providers and {len(services)} services")
            return providers, services
            
        except Exception as e:
            logger.error(f"Error extracting providers/services: {e}")
            return [], []

def save_to_json(data, filename):
    """Save data to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Saved data to {filename}")
    except Exception as e:
        logger.error(f"Error saving JSON file {filename}: {e}")

def save_to_csv(data, filename, fieldnames=None):
    """Save data to CSV file"""
    if not data:
        logger.warning(f"No data to save to {filename}")
        return
        
    try:
        if fieldnames is None:
            fieldnames = data[0].keys() if data else []
            
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        logger.info(f"Saved {len(data)} records to {filename}")
    except Exception as e:
        logger.error(f"Error saving CSV file {filename}: {e}")

def main():
    """Main execution function"""
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"domain_extraction_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info(f"Starting domain extraction - Output directory: {output_dir}")
    
    # Initialize extractor
    extractor = BaseDomainExtractor()
    
    try:
        # Extract base domains
        logger.info("Extracting base domains...")
        base_domains = extractor.extract_base_domains()
        
        # Extract statistics
        logger.info("Extracting domain statistics...")
        statistics = extractor.get_domain_statistics()
        
        # Extract providers and services
        logger.info("Extracting providers and services...")
        providers, services = extractor.get_providers_and_services()
        
        # Prepare comprehensive export data
        export_data = {
            'extraction_info': {
                'timestamp': datetime.now().isoformat(),
                'total_base_domains': len(base_domains),
                'total_providers': len(providers),
                'total_services': len(services)
            },
            'statistics': statistics,
            'base_domains': base_domains,
            'providers': providers,
            'services': services
        }
        
        # Save comprehensive JSON export
        save_to_json(export_data, os.path.join(output_dir, 'complete_domain_export.json'))
        
        # Save individual CSV files
        save_to_csv(base_domains, os.path.join(output_dir, 'base_domains.csv'))
        
        if providers:
            save_to_csv(providers, os.path.join(output_dir, 'providers.csv'))
        
        if services:
            save_to_csv(services, os.path.join(output_dir, 'services.csv'))
        
        # Save base domains list for re-analysis (simple format)
        base_domain_list = [domain['base_domain'] for domain in base_domains]
        save_to_json(base_domain_list, os.path.join(output_dir, 'base_domains_list.json'))
        
        # Save text file with just domain names (one per line)
        with open(os.path.join(output_dir, 'base_domains_list.txt'), 'w') as f:
            for domain in base_domain_list:
                f.write(f"{domain}\\n")
        
        # Print summary
        print("\\n" + "="*60)
        print("DOMAIN EXTRACTION SUMMARY")
        print("="*60)
        print(f"📁 Output directory: {output_dir}")
        print(f"🏗️  Total base domains: {len(base_domains)}")
        print(f"🔧 Total providers: {len(providers)}")
        print(f"⚙️  Total services: {len(services)}")
        print(f"📊 Total domains in graph: {statistics.get('total_domains', 'N/A')}")
        print(f"🌐 Total subdomains in graph: {statistics.get('total_subdomains', 'N/A')}")
        print(f"⚠️  Domains with risk scores: {statistics.get('domains_with_risk', 'N/A')}")
        
        print("\\n📈 Top TLDs:")
        for tld_info in statistics.get('tld_distribution', [])[:5]:
            print(f"   .{tld_info['tld']}: {tld_info['count']} domains")
        
        print("\\n🏭 Top Industries:")
        for industry_info in statistics.get('industry_distribution', [])[:5]:
            print(f"   {industry_info['industry']}: {industry_info['count']} base domains")
        
        print("\\n📄 Files created:")
        print(f"   • complete_domain_export.json - Full export with all data")
        print(f"   • base_domains.csv - Base domains with metadata")
        print(f"   • base_domains_list.json - Simple list for scripts")
        print(f"   • base_domains_list.txt - Text file, one domain per line")
        if providers:
            print(f"   • providers.csv - Provider information")
        if services:
            print(f"   • services.csv - Service information")
        
        print("\\n✅ Extraction completed successfully!")
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)
    
    finally:
        extractor.close()

if __name__ == "__main__":
    main()