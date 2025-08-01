#!/usr/bin/env python3
"""
update_tld_data_v5.py - TLD Data Update Script

This script updates existing Domain and Subdomain nodes in the Neo4j database with comprehensive
TLD information and creates enhanced provider-domain associations.

Key operations:
1. Add TLD classification data to existing Domain and Subdomain nodes
2. Create enhanced HAS_PROVIDER relationships between domains and providers
3. Update subdomain count statistics on provider relationships
4. Add country and geographic information based on TLD analysis

Usage:
    python update_tld_data_v5.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password tsunami123
"""

import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional
import re

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'tld_update_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)

class TLDUpdater:
    """Updates existing graph nodes with comprehensive TLD information."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver required but not installed")
        
        # Initialize Neo4j driver
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            logging.info("✅ Neo4j connection established successfully")
        except Exception as e:
            logging.error(f"❌ Failed to connect to Neo4j: {e}")
            raise
        
        # TLD classification data
        self.country_tlds = {
            'cl': {'country_code': 'CL', 'country_name': 'Chile', 'tld_type': 'country'},
            'ar': {'country_code': 'AR', 'country_name': 'Argentina', 'tld_type': 'country'},
            'br': {'country_code': 'BR', 'country_name': 'Brazil', 'tld_type': 'country'},
            'mx': {'country_code': 'MX', 'country_name': 'Mexico', 'tld_type': 'country'},
            'co': {'country_code': 'CO', 'country_name': 'Colombia', 'tld_type': 'country'},
            'pe': {'country_code': 'PE', 'country_name': 'Peru', 'tld_type': 'country'},
            've': {'country_code': 'VE', 'country_name': 'Venezuela', 'tld_type': 'country'},
            'uy': {'country_code': 'UY', 'country_name': 'Uruguay', 'tld_type': 'country'},
            'py': {'country_code': 'PY', 'country_name': 'Paraguay', 'tld_type': 'country'},
            'ec': {'country_code': 'EC', 'country_name': 'Ecuador', 'tld_type': 'country'},
            'bo': {'country_code': 'BO', 'country_name': 'Bolivia', 'tld_type': 'country'},
            'us': {'country_code': 'US', 'country_name': 'United States', 'tld_type': 'country'},
            'ca': {'country_code': 'CA', 'country_name': 'Canada', 'tld_type': 'country'},
            'uk': {'country_code': 'GB', 'country_name': 'United Kingdom', 'tld_type': 'country'},
            'de': {'country_code': 'DE', 'country_name': 'Germany', 'tld_type': 'country'},
            'fr': {'country_code': 'FR', 'country_name': 'France', 'tld_type': 'country'},
            'es': {'country_code': 'ES', 'country_name': 'Spain', 'tld_type': 'country'},
            'it': {'country_code': 'IT', 'country_name': 'Italy', 'tld_type': 'country'},
            'jp': {'country_code': 'JP', 'country_name': 'Japan', 'tld_type': 'country'},
            'cn': {'country_code': 'CN', 'country_name': 'China', 'tld_type': 'country'},
            'in': {'country_code': 'IN', 'country_name': 'India', 'tld_type': 'country'},
            'au': {'country_code': 'AU', 'country_name': 'Australia', 'tld_type': 'country'},
            'nz': {'country_code': 'NZ', 'country_name': 'New Zealand', 'tld_type': 'country'},
            'ru': {'country_code': 'RU', 'country_name': 'Russia', 'tld_type': 'country'},
            'za': {'country_code': 'ZA', 'country_name': 'South Africa', 'tld_type': 'country'}
        }
        
        self.generic_tlds = {
            'com': {'tld_type': 'generic', 'purpose': 'commercial'},
            'org': {'tld_type': 'generic', 'purpose': 'organization'},
            'net': {'tld_type': 'generic', 'purpose': 'network'},
            'edu': {'tld_type': 'generic', 'purpose': 'education'},
            'gov': {'tld_type': 'generic', 'purpose': 'government'},
            'mil': {'tld_type': 'generic', 'purpose': 'military'},
            'int': {'tld_type': 'generic', 'purpose': 'international'},
            'info': {'tld_type': 'generic', 'purpose': 'information'},
            'biz': {'tld_type': 'generic', 'purpose': 'business'}
        }
    
    def close(self):
        """Close Neo4j connection."""
        if hasattr(self, 'driver'):
            self.driver.close()
    
    def extract_tld_info(self, fqdn: str) -> Dict[str, str]:
        """Extract comprehensive TLD information from FQDN."""
        try:
            if HAS_TLDEXTRACT:
                extracted = tldextract.extract(fqdn)
                tld = extracted.suffix
            else:
                # Fallback TLD extraction
                parts = fqdn.split('.')
                tld = parts[-1] if parts else ""
            
            tld_lower = tld.lower()
            
            # Classify TLD
            if tld_lower in self.country_tlds:
                tld_info = self.country_tlds[tld_lower].copy()
                tld_info['is_country_tld'] = True
            elif tld_lower in self.generic_tlds:
                tld_info = self.generic_tlds[tld_lower].copy()
                tld_info['is_country_tld'] = False
            else:
                tld_info = {
                    'tld_type': 'unknown',
                    'is_country_tld': False
                }
            
            return {
                'tld': tld,
                'country_code': tld_info.get('country_code'),
                'country_name': tld_info.get('country_name'),
                'tld_type': tld_info.get('tld_type', 'unknown'),
                'purpose': tld_info.get('purpose'),
                'is_country_tld': tld_info.get('is_country_tld', False)
            }
            
        except Exception as e:
            logging.debug(f"TLD extraction failed for {fqdn}: {e}")
            return {
                'tld': 'unknown',
                'country_code': None,
                'country_name': None,
                'tld_type': 'unknown',
                'purpose': None,
                'is_country_tld': False
            }
    
    def update_domain_tld_data(self, dry_run: bool = True) -> Dict:
        """Update Domain nodes with TLD information."""
        logging.info("🔍 Updating Domain nodes with TLD information...")
        
        with self.driver.session() as session:
            # Get all domains that need TLD updates
            result = session.run("""
                MATCH (d:Domain)
                WHERE d.tld IS NULL OR d.tld_type IS NULL
                RETURN d.fqdn
                ORDER BY d.fqdn
            """)
            
            domains_to_update = [record['d.fqdn'] for record in result]
            
        logging.info(f"📊 Found {len(domains_to_update)} domains needing TLD updates")
        
        if dry_run:
            logging.info("🔍 DRY RUN MODE - No changes will be made")
            # Show some examples
            for domain in domains_to_update[:10]:
                tld_info = self.extract_tld_info(domain)
                logging.info(f"  {domain}: TLD={tld_info['tld']}, Type={tld_info['tld_type']}, Country={tld_info['country_name']}")
            
            if len(domains_to_update) > 10:
                logging.info(f"  ... and {len(domains_to_update) - 10} more")
            
            return {
                'analyzed': len(domains_to_update),
                'would_update': len(domains_to_update),
                'dry_run': True
            }
        
        # Perform actual updates
        updated_count = 0
        failed_count = 0
        
        with self.driver.session() as session:
            for domain in domains_to_update:
                try:
                    tld_info = self.extract_tld_info(domain)
                    
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $fqdn})
                        SET d.tld = $tld,
                            d.tld_country_code = $country_code,
                            d.tld_country_name = $country_name,
                            d.tld_type = $tld_type,
                            d.tld_purpose = $purpose,
                            d.is_country_tld = $is_country_tld,
                            d.tld_updated_at = $timestamp
                        RETURN d.fqdn as updated_fqdn
                    """,
                    fqdn=domain,
                    tld=tld_info['tld'],
                    country_code=tld_info['country_code'],
                    country_name=tld_info['country_name'],
                    tld_type=tld_info['tld_type'],
                    purpose=tld_info['purpose'],
                    is_country_tld=tld_info['is_country_tld'],
                    timestamp=datetime.now().isoformat())
                    
                    if result.single():
                        updated_count += 1
                        if updated_count % 50 == 0:
                            logging.info(f"✅ Updated {updated_count} domains...")
                    else:
                        failed_count += 1
                        
                except Exception as e:
                    failed_count += 1
                    logging.error(f"❌ Error updating domain {domain}: {e}")
        
        logging.info(f"✅ Domain TLD update completed!")
        logging.info(f"  Updated: {updated_count}")
        logging.info(f"  Failed: {failed_count}")
        
        return {
            'analyzed': len(domains_to_update),
            'updated': updated_count,
            'failed': failed_count,
            'dry_run': False
        }
    
    def update_subdomain_tld_data(self, dry_run: bool = True) -> Dict:
        """Update Subdomain nodes with TLD information."""
        logging.info("🔍 Updating Subdomain nodes with TLD information...")
        
        with self.driver.session() as session:
            # Get all subdomains that need TLD updates
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.tld IS NULL OR s.tld_type IS NULL
                RETURN s.fqdn
                ORDER BY s.fqdn
            """)
            
            subdomains_to_update = [record['s.fqdn'] for record in result]
            
        logging.info(f"📊 Found {len(subdomains_to_update)} subdomains needing TLD updates")
        
        if dry_run:
            logging.info("🔍 DRY RUN MODE - No changes will be made")
            return {
                'analyzed': len(subdomains_to_update),
                'would_update': len(subdomains_to_update),
                'dry_run': True
            }
        
        # Perform actual updates
        updated_count = 0
        failed_count = 0
        
        with self.driver.session() as session:
            for subdomain in subdomains_to_update:
                try:
                    tld_info = self.extract_tld_info(subdomain)
                    
                    result = session.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        SET s.tld = $tld,
                            s.tld_country_code = $country_code,
                            s.tld_country_name = $country_name,
                            s.tld_type = $tld_type,
                            s.tld_purpose = $purpose,
                            s.is_country_tld = $is_country_tld,
                            s.tld_updated_at = $timestamp
                        RETURN s.fqdn as updated_fqdn
                    """,
                    fqdn=subdomain,
                    tld=tld_info['tld'],
                    country_code=tld_info['country_code'],
                    country_name=tld_info['country_name'],
                    tld_type=tld_info['tld_type'],
                    purpose=tld_info['purpose'],
                    is_country_tld=tld_info['is_country_tld'],
                    timestamp=datetime.now().isoformat())
                    
                    if result.single():
                        updated_count += 1
                        if updated_count % 100 == 0:
                            logging.info(f"✅ Updated {updated_count} subdomains...")
                    else:
                        failed_count += 1
                        
                except Exception as e:
                    failed_count += 1
                    logging.error(f"❌ Error updating subdomain {subdomain}: {e}")
        
        logging.info(f"✅ Subdomain TLD update completed!")
        logging.info(f"  Updated: {updated_count}")
        logging.info(f"  Failed: {failed_count}")
        
        return {
            'analyzed': len(subdomains_to_update),
            'updated': updated_count,
            'failed': failed_count,
            'dry_run': False
        }
    
    def create_provider_domain_associations(self, dry_run: bool = True) -> Dict:
        """Create enhanced HAS_PROVIDER relationships between domains and providers."""
        logging.info("🔍 Creating enhanced provider-domain associations...")
        
        with self.driver.session() as session:
            # Find domains that don't have HAS_PROVIDER relationships but should
            result = session.run("""
                MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:USES_SERVICE]->(p:Provider)
                WHERE NOT (d)-[:HAS_PROVIDER]->(p)
                RETURN DISTINCT d.fqdn as domain, p.id as provider_id, p.name as provider_name
                ORDER BY d.fqdn, p.name
            """)
            
            associations_to_create = [(record['domain'], record['provider_id'], record['provider_name']) 
                                    for record in result]
            
        logging.info(f"📊 Found {len(associations_to_create)} provider-domain associations to create")
        
        if dry_run:
            logging.info("🔍 DRY RUN MODE - No changes will be made")
            # Show some examples
            for domain, provider_id, provider_name in associations_to_create[:10]:
                logging.info(f"  {domain} -> {provider_name}")
            
            if len(associations_to_create) > 10:
                logging.info(f"  ... and {len(associations_to_create) - 10} more")
            
            return {
                'analyzed': len(associations_to_create),
                'would_create': len(associations_to_create),
                'dry_run': True
            }
        
        # Create associations
        created_count = 0
        failed_count = 0
        
        with self.driver.session() as session:
            for domain, provider_id, provider_name in associations_to_create:
                try:
                    result = session.run("""
                        MATCH (d:Domain {fqdn: $domain})
                        MATCH (p:Provider {id: $provider_id})
                        
                        // Count subdomains using this provider
                        MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:USES_SERVICE]->(p)
                        WITH d, p, count(s) as subdomain_count
                        
                        MERGE (d)-[r:HAS_PROVIDER]->(p)
                        SET r.subdomain_count = subdomain_count,
                            r.created_at = $timestamp,
                            r.last_seen = $timestamp
                        
                        RETURN r.subdomain_count as count
                    """,
                    domain=domain,
                    provider_id=provider_id,
                    timestamp=datetime.now().isoformat())
                    
                    record = result.single()
                    if record:
                        created_count += 1
                        if created_count % 50 == 0:
                            logging.info(f"✅ Created {created_count} associations...")
                    else:
                        failed_count += 1
                        
                except Exception as e:
                    failed_count += 1
                    logging.error(f"❌ Error creating association {domain} -> {provider_name}: {e}")
        
        logging.info(f"✅ Provider-domain association creation completed!")
        logging.info(f"  Created: {created_count}")
        logging.info(f"  Failed: {failed_count}")
        
        return {
            'analyzed': len(associations_to_create),
            'created': created_count,
            'failed': failed_count,
            'dry_run': False
        }
    
    def generate_tld_report(self) -> Dict:
        """Generate comprehensive TLD analysis report."""
        with self.driver.session() as session:
            # TLD distribution for domains
            domain_tld_stats = session.run("""
                MATCH (d:Domain)
                WHERE d.tld IS NOT NULL
                RETURN d.tld, d.tld_type, d.tld_country_name, count(*) as domain_count
                ORDER BY domain_count DESC
            """).data()
            
            # TLD distribution for subdomains
            subdomain_tld_stats = session.run("""
                MATCH (s:Subdomain)
                WHERE s.tld IS NOT NULL
                RETURN s.tld, s.tld_type, s.tld_country_name, count(*) as subdomain_count
                ORDER BY subdomain_count DESC
            """).data()
            
            # Provider-domain association stats
            provider_association_stats = session.run("""
                MATCH (d:Domain)-[r:HAS_PROVIDER]->(p:Provider)
                RETURN p.name, sum(r.subdomain_count) as total_subdomains, count(d) as domain_count
                ORDER BY total_subdomains DESC
                LIMIT 20
            """).data()
            
            # Country distribution
            country_stats = session.run("""
                MATCH (d:Domain)
                WHERE d.tld_country_name IS NOT NULL
                RETURN d.tld_country_name, count(*) as domain_count
                ORDER BY domain_count DESC
            """).data()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'domain_tld_distribution': domain_tld_stats,
                'subdomain_tld_distribution': subdomain_tld_stats[:10],  # Top 10
                'provider_associations': provider_association_stats,
                'country_distribution': country_stats
            }
            
            return report

def main():
    parser = argparse.ArgumentParser(description="TLD Data Update Script v5.0")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="tsunami123", help="Neo4j password")
    parser.add_argument("--dry-run", action="store_true", help="Analyze only, don't make changes")
    parser.add_argument("--report-only", action="store_true", help="Generate report only")
    parser.add_argument("--domains-only", action="store_true", help="Update only Domain nodes")
    parser.add_argument("--subdomains-only", action="store_true", help="Update only Subdomain nodes")
    parser.add_argument("--associations-only", action="store_true", help="Create only provider associations")
    
    args = parser.parse_args()
    
    try:
        updater = TLDUpdater(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        )
        
        if args.report_only:
            logging.info("📊 Generating TLD analysis report...")
            report = updater.generate_tld_report()
            
            print("\n" + "="*60)
            print("TLD ANALYSIS REPORT")
            print("="*60)
            print(f"Generated: {report['timestamp']}")
            
            print("\nTop Domain TLDs:")
            for tld_data in report['domain_tld_distribution'][:10]:
                country = f" ({tld_data['tld_country_name']})" if tld_data['tld_country_name'] else ""
                print(f"  .{tld_data['tld']}: {tld_data['domain_count']} domains{country}")
            
            print("\nTop Provider Associations:")
            for provider_data in report['provider_associations'][:10]:
                print(f"  {provider_data['p.name']}: {provider_data['total_subdomains']} subdomains across {provider_data['domain_count']} domains")
            
            print("\nTop Countries:")
            for country_data in report['country_distribution'][:10]:
                print(f"  {country_data['d.tld_country_name']}: {country_data['domain_count']} domains")
        
        else:
            # Perform updates
            results = {}
            
            if not args.subdomains_only and not args.associations_only:
                results['domains'] = updater.update_domain_tld_data(dry_run=args.dry_run)
            
            if not args.domains_only and not args.associations_only:
                results['subdomains'] = updater.update_subdomain_tld_data(dry_run=args.dry_run)
            
            if not args.domains_only and not args.subdomains_only:
                results['associations'] = updater.create_provider_domain_associations(dry_run=args.dry_run)
            
            print("\n" + "="*60)
            print("TLD UPDATE RESULTS")
            print("="*60)
            print(f"Mode: {'DRY RUN' if args.dry_run else 'ACTUAL UPDATE'}")
            
            for update_type, result in results.items():
                print(f"\n{update_type.upper()}:")
                if result['dry_run']:
                    print(f"  Would update: {result.get('would_update', result.get('would_create', 0))}")
                else:
                    print(f"  Updated/Created: {result.get('updated', result.get('created', 0))}")
                    print(f"  Failed: {result.get('failed', 0)}")
        
    except Exception as e:
        logging.error(f"❌ Fatal error: {e}")
        return 1
    finally:
        if 'updater' in locals():
            updater.close()
    
    return 0

if __name__ == "__main__":
    exit(main())