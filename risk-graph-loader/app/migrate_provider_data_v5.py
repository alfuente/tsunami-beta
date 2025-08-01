#!/usr/bin/env python3
"""
migrate_provider_data_v5.py - Provider Data Migration Script

This script fixes existing provider nodes in the Neo4j database by analyzing their metadata
and updating their names and TLD information while preserving all existing relationships.

Key operations:
1. Find all Provider nodes with name="unknown" but rich metadata
2. Re-process metadata to extract proper provider names and TLD information  
3. Update provider properties while preserving all relationships
4. Generate migration report showing changes made

Usage:
    python migrate_provider_data_v5.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password tsunami123
"""

import argparse
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import re

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# Enhanced provider patterns (copied from v5)
CLOUD_PROVIDER_PATTERNS = {
    'amazon': ['amazon', 'aws', 'amazonaws'],
    'microsoft': ['microsoft', 'azure', 'msft'],
    'google': ['google', 'gcp', 'googleapis', 'googleusercontent'],
    'cloudflare': ['cloudflare'],
    'fastly': ['fastly'],
    'akamai': ['akamai'],
    'imperva': ['imperva', 'incapsula'],  # Key addition for incapsula
    'maxcdn': ['maxcdn', 'stackpath'],
    'digitalocean': ['digitalocean'],
    'linode': ['linode'],
    'vultr': ['vultr'],
    'hetzner': ['hetzner'],
    'ovh': ['ovh'],
    'scaleway': ['scaleway']
}

# Country code to TLD mapping (copied from v5)
COUNTRY_TO_TLD = {
    'US': 'com',
    'CL': 'cl', 
    'BR': 'br',
    'AR': 'ar',
    'MX': 'mx',
    'CO': 'co',
    'PE': 'pe',
    'VE': 've',
    'UY': 'uy',
    'PY': 'py',
    'EC': 'ec',
    'BO': 'bo',
    'GT': 'gt',
    'CR': 'cr',
    'PA': 'pa',
    'CA': 'ca',
    'UK': 'uk',
    'GB': 'uk',
    'DE': 'de',
    'FR': 'fr',
    'ES': 'es',
    'IT': 'it',
    'JP': 'jp',
    'CN': 'cn',
    'IN': 'in',
    'AU': 'au',
    'NZ': 'nz',
    'RU': 'ru',
    'ZA': 'za'
}

# ASN to provider mapping (copied from v5)
ASN_TO_PROVIDER = {
    'AS16509': 'amazon',
    'AS8075': 'microsoft', 
    'AS15169': 'google',
    'AS13335': 'cloudflare',
    'AS54113': 'fastly',
    'AS20940': 'akamai',
    'AS19551': 'imperva',  # Incapsula
    'AS14061': 'digitalocean',
    'AS63949': 'linode',
    'AS20473': 'vultr',
    'AS24940': 'hetzner'
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'provider_migration_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)

class ProviderMigrator:
    """Migrates existing provider data using enhanced detection logic."""
    
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
    
    def close(self):
        """Close Neo4j connection."""
        if hasattr(self, 'driver'):
            self.driver.close()
    
    def extract_provider_from_metadata(self, metadata_str: str) -> Tuple[Optional[str], Optional[str], float, str]:
        """
        Extract provider name and TLD from metadata string.
        Returns: (provider_name, tld, confidence, source)
        """
        try:
            metadata = json.loads(metadata_str) if isinstance(metadata_str, str) else metadata_str
            
            # Look for resolution_attempts in metadata
            resolution_attempts = metadata.get('resolution_attempts', {})
            
            as_domain = resolution_attempts.get('as_domain', '')
            as_name = resolution_attempts.get('as_name', '')
            asn = resolution_attempts.get('asn', '')
            country_code = resolution_attempts.get('country_code', '')
            
            provider_name = None
            confidence = 0.0
            source = "unknown"
            tld = None
            
            # Extract provider from as_domain (highest priority)
            if as_domain:
                domain_parts = as_domain.lower().split('.')
                if len(domain_parts) >= 2:
                    potential_provider = domain_parts[0]
                    
                    # Check if it matches known provider patterns
                    for provider, patterns in CLOUD_PROVIDER_PATTERNS.items():
                        if potential_provider in patterns or any(pattern in potential_provider for pattern in patterns):
                            provider_name = provider
                            confidence = 0.9
                            source = "metadata_as_domain"
                            break
                    
                    # If not a known cloud provider, use the extracted name directly
                    if provider_name is None and len(potential_provider) > 2:
                        provider_name = potential_provider
                        confidence = 0.8
                        source = "metadata_as_domain_direct"
            
            # Fallback to as_name if as_domain didn't work
            if provider_name is None and as_name:
                extracted_from_name = self._extract_provider_from_org(as_name)
                if extracted_from_name != "unknown":
                    provider_name = extracted_from_name
                    confidence = 0.7
                    source = "metadata_as_name"
            
            # Fallback to ASN mapping
            if provider_name is None and asn:
                asn_provider = ASN_TO_PROVIDER.get(asn)
                if asn_provider:
                    provider_name = asn_provider
                    confidence = 0.8
                    source = "metadata_asn"
            
            # Determine TLD from country code
            if country_code:
                tld = COUNTRY_TO_TLD.get(country_code.upper())
            
            return provider_name, tld, confidence, source
            
        except Exception as e:
            logging.debug(f"Failed to extract provider from metadata: {e}")
            return None, None, 0.0, "extraction_failed"
    
    def _extract_provider_from_org(self, org: str) -> str:
        """Extract provider name from organization string."""
        if not org:
            return "unknown"
        
        org_lower = org.lower()
        
        # Check for cloud provider patterns
        for provider, patterns in CLOUD_PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern in org_lower:
                    return provider
        
        # Extract company name from ASN org format
        if ' ' in org:
            parts = org.split()
            # Look for meaningful company names
            for part in parts:
                if not part.startswith('AS') and len(part) > 2:
                    part_lower = part.lower()
                    # Skip common words
                    if part_lower not in ['inc', 'ltd', 'corp', 'company', 'limited', 'sa', 'ltda', 'banco', 'bank']:
                        return part_lower
        
        # If single word, return as-is (cleaned)
        clean_org = re.sub(r'[^a-zA-Z0-9]', '', org.lower())
        if len(clean_org) > 2:
            return clean_org
        
        return "unknown"
    
    def analyze_providers_needing_migration(self) -> List[Dict]:
        """Analyze providers that need migration and return migration plan."""
        
        with self.driver.session() as session:
            # Find all providers with unknown names but metadata
            result = session.run("""
                MATCH (p:Provider)
                WHERE p.name = 'unknown' AND p.metadata IS NOT NULL AND p.metadata <> '{}'
                RETURN p.id, p.name, p.metadata, p.country, p.tld
                ORDER BY p.id
            """)
            
            migration_candidates = []
            
            for record in result:
                provider_id = record['p.id']
                current_name = record['p.name']
                metadata = record['p.metadata']
                current_country = record['p.country']
                current_tld = record['p.tld']
                
                # Extract new provider info from metadata
                new_provider, new_tld, confidence, source = self.extract_provider_from_metadata(metadata)
                
                if new_provider and new_provider != "unknown":
                    migration_candidates.append({
                        'id': provider_id,
                        'current_name': current_name,
                        'new_name': new_provider,
                        'current_tld': current_tld,
                        'new_tld': new_tld,
                        'confidence': confidence,
                        'source': source,
                        'metadata': metadata
                    })
            
            return migration_candidates
    
    def migrate_provider_data(self, dry_run: bool = True) -> Dict:
        """
        Migrate provider data based on metadata analysis.
        
        Args:
            dry_run: If True, only analyze and report what would be changed
            
        Returns:
            Dict with migration statistics
        """
        
        logging.info(f"🔍 Starting provider data migration analysis...")
        
        migration_candidates = self.analyze_providers_needing_migration()
        
        logging.info(f"📊 Found {len(migration_candidates)} providers that can be improved")
        
        # Group by new provider name for summary
        provider_summary = {}
        for candidate in migration_candidates:
            new_name = candidate['new_name']
            if new_name not in provider_summary:
                provider_summary[new_name] = 0
            provider_summary[new_name] += 1
        
        logging.info("📈 Migration summary by provider:")
        for provider, count in sorted(provider_summary.items()):
            logging.info(f"  {provider}: {count} nodes")
        
        if dry_run:
            logging.info("🔍 DRY RUN MODE - No changes will be made")
            
            # Show some examples
            logging.info("\n📋 Example migrations that would be performed:")
            for candidate in migration_candidates[:10]:  # Show first 10
                logging.info(f"  {candidate['id']}: unknown -> {candidate['new_name']} (TLD: {candidate['new_tld']}, conf: {candidate['confidence']:.2f})")
            
            if len(migration_candidates) > 10:
                logging.info(f"  ... and {len(migration_candidates) - 10} more")
            
            return {
                'analyzed': len(migration_candidates),
                'would_migrate': len(migration_candidates),
                'dry_run': True,
                'provider_summary': provider_summary
            }
        
        # Perform actual migration
        logging.info("🚀 Performing actual migration...")
        
        migrated_count = 0
        failed_count = 0
        
        with self.driver.session() as session:
            for candidate in migration_candidates:
                try:
                    # Update provider properties while preserving relationships
                    result = session.run("""
                        MATCH (p:Provider {id: $provider_id})
                        SET p.name = $new_name,
                            p.tld = $new_tld,
                            p.migration_confidence = $confidence,
                            p.migration_source = $source,
                            p.migration_timestamp = $timestamp,
                            p.original_name = $original_name,
                            p.is_unknown = false
                        RETURN p.id as updated_id
                    """, 
                    provider_id=candidate['id'],
                    new_name=candidate['new_name'],
                    new_tld=candidate['new_tld'],
                    confidence=candidate['confidence'],
                    source=candidate['source'],
                    timestamp=datetime.now().isoformat(),
                    original_name=candidate['current_name']
                    )
                    
                    if result.single():
                        migrated_count += 1
                        if migrated_count % 100 == 0:
                            logging.info(f"✅ Migrated {migrated_count} providers...")
                    else:
                        failed_count += 1
                        logging.warning(f"⚠️ Failed to migrate provider {candidate['id']}")
                        
                except Exception as e:
                    failed_count += 1
                    logging.error(f"❌ Error migrating provider {candidate['id']}: {e}")
        
        logging.info(f"✅ Migration completed!")
        logging.info(f"  Migrated: {migrated_count}")
        logging.info(f"  Failed: {failed_count}")
        
        return {
            'analyzed': len(migration_candidates),
            'migrated': migrated_count,
            'failed': failed_count,
            'dry_run': False,
            'provider_summary': provider_summary
        }
    
    def generate_migration_report(self) -> Dict:
        """Generate a comprehensive migration report."""
        
        with self.driver.session() as session:
            # Count providers by status
            provider_stats = session.run("""
                MATCH (p:Provider)
                RETURN 
                    sum(CASE WHEN p.name = 'unknown' THEN 1 ELSE 0 END) as unknown_count,
                    sum(CASE WHEN p.name <> 'unknown' THEN 1 ELSE 0 END) as known_count,
                    sum(CASE WHEN p.migration_timestamp IS NOT NULL THEN 1 ELSE 0 END) as migrated_count,
                    count(p) as total_count
            """).single()
            
            # Get top providers
            top_providers = session.run("""
                MATCH (p:Provider)
                WHERE p.name <> 'unknown'
                RETURN p.name, count(*) as node_count
                ORDER BY node_count DESC
                LIMIT 10
            """).data()
            
            # Get migration details if any
            migration_details = session.run("""
                MATCH (p:Provider)
                WHERE p.migration_timestamp IS NOT NULL
                RETURN p.name, p.migration_source, count(*) as count
                ORDER BY count DESC
            """).data()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'provider_statistics': {
                    'total_providers': provider_stats['total_count'],
                    'unknown_providers': provider_stats['unknown_count'],
                    'known_providers': provider_stats['known_count'],
                    'migrated_providers': provider_stats['migrated_count']
                },
                'top_providers': top_providers,
                'migration_details': migration_details
            }
            
            return report

def main():
    parser = argparse.ArgumentParser(description="Provider Data Migration Script v5.0")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="tsunami123", help="Neo4j password")
    parser.add_argument("--dry-run", action="store_true", help="Analyze only, don't make changes")
    parser.add_argument("--report-only", action="store_true", help="Generate report only")
    
    args = parser.parse_args()
    
    try:
        migrator = ProviderMigrator(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        )
        
        if args.report_only:
            logging.info("📊 Generating migration report...")
            report = migrator.generate_migration_report()
            
            print("\n" + "="*60)
            print("PROVIDER MIGRATION REPORT")
            print("="*60)
            print(f"Generated: {report['timestamp']}")
            print(f"Total Providers: {report['provider_statistics']['total_providers']}")
            print(f"Unknown Providers: {report['provider_statistics']['unknown_providers']}")
            print(f"Known Providers: {report['provider_statistics']['known_providers']}")
            print(f"Migrated Providers: {report['provider_statistics']['migrated_providers']}")
            
            if report['top_providers']:
                print("\nTop Providers:")
                for provider in report['top_providers']:
                    print(f"  {provider['p.name']}: {provider['node_count']} nodes")
            
            if report['migration_details']:
                print("\nMigration Sources:")
                for detail in report['migration_details']:
                    print(f"  {detail['p.migration_source']}: {detail['count']} providers")
        
        else:
            # Perform migration
            result = migrator.migrate_provider_data(dry_run=args.dry_run)
            
            print("\n" + "="*60)
            print("MIGRATION RESULTS")
            print("="*60)
            print(f"Mode: {'DRY RUN' if result['dry_run'] else 'ACTUAL MIGRATION'}")
            print(f"Analyzed: {result['analyzed']} providers")
            
            if result['dry_run']:
                print(f"Would migrate: {result['would_migrate']} providers")
            else:
                print(f"Successfully migrated: {result['migrated']} providers")
                print(f"Failed: {result['failed']} providers")
            
            print("\nProvider distribution:")
            for provider, count in sorted(result['provider_summary'].items()):
                print(f"  {provider}: {count} nodes")
        
    except Exception as e:
        logging.error(f"❌ Fatal error: {e}")
        return 1
    finally:
        if 'migrator' in locals():
            migrator.close()
    
    return 0

if __name__ == "__main__":
    exit(main())