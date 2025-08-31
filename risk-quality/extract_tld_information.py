#!/usr/bin/env python3
"""
Extract TLD Information Script

This script analyzes all base domains in the Neo4j graph to determine their TLDs
and consolidates country information from:
1. Existing tld property in Domain nodes
2. tldextract library for proper TLD extraction
3. MMDB database for country mapping via IP geolocation
4. Hardcoded country-TLD mappings for accuracy

The output is a comprehensive JSON file with TLD information that includes:
- TLD code (.cl, .ar, etc.)
- Country name and code
- Whether it's a country-code TLD
- Statistics about domains using each TLD

Usage:
    python3 extract_tld_information.py [--output tld_information.json] [--mmdb-path ../risk-graph-loader/app/ipinfo_data/ipinfo.mmdb]

Requirements:
    pip install tldextract maxminddb
"""

import argparse
import logging
import json
import tldextract
from neo4j import GraphDatabase
from typing import Dict, List, Set, Optional
from collections import defaultdict
import socket

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Neo4j connection configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

# Default MMDB path
DEFAULT_MMDB_PATH = "../risk-graph-loader/app/ipinfo_data/ipinfo.mmdb"

class TLDInformationExtractor:
    def __init__(self, mmdb_path: str = None):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.mmdb_path = mmdb_path
        self.mmdb_reader = None
        
        # Initialize MMDB reader if available
        if mmdb_path:
            try:
                import maxminddb
                self.mmdb_reader = maxminddb.open_database(mmdb_path)
                logger.info(f"✅ MMDB database loaded from {mmdb_path}")
            except ImportError:
                logger.warning("⚠️ maxminddb library not available, IP-based country detection disabled")
            except Exception as e:
                logger.warning(f"⚠️ Could not load MMDB database: {e}")
        
        # Comprehensive country-TLD mapping
        self.country_to_tld_mapping = {
            # Latin America
            'CL': {'tld': 'cl', 'country_name': 'Chile', 'region': 'Latin America'},
            'AR': {'tld': 'ar', 'country_name': 'Argentina', 'region': 'Latin America'},
            'BR': {'tld': 'br', 'country_name': 'Brazil', 'region': 'Latin America'},
            'PE': {'tld': 'pe', 'country_name': 'Peru', 'region': 'Latin America'},
            'CO': {'tld': 'co', 'country_name': 'Colombia', 'region': 'Latin America'},
            'MX': {'tld': 'mx', 'country_name': 'Mexico', 'region': 'Latin America'},
            'VE': {'tld': 've', 'country_name': 'Venezuela', 'region': 'Latin America'},
            'UY': {'tld': 'uy', 'country_name': 'Uruguay', 'region': 'Latin America'},
            'PY': {'tld': 'py', 'country_name': 'Paraguay', 'region': 'Latin America'},
            'BO': {'tld': 'bo', 'country_name': 'Bolivia', 'region': 'Latin America'},
            'EC': {'tld': 'ec', 'country_name': 'Ecuador', 'region': 'Latin America'},
            
            # North America
            'US': {'tld': 'us', 'country_name': 'United States', 'region': 'North America'},
            'CA': {'tld': 'ca', 'country_name': 'Canada', 'region': 'North America'},
            
            # Europe
            'GB': {'tld': 'uk', 'country_name': 'United Kingdom', 'region': 'Europe'},
            'DE': {'tld': 'de', 'country_name': 'Germany', 'region': 'Europe'},
            'FR': {'tld': 'fr', 'country_name': 'France', 'region': 'Europe'},
            'ES': {'tld': 'es', 'country_name': 'Spain', 'region': 'Europe'},
            'IT': {'tld': 'it', 'country_name': 'Italy', 'region': 'Europe'},
            'NL': {'tld': 'nl', 'country_name': 'Netherlands', 'region': 'Europe'},
            'SE': {'tld': 'se', 'country_name': 'Sweden', 'region': 'Europe'},
            'NO': {'tld': 'no', 'country_name': 'Norway', 'region': 'Europe'},
            'DK': {'tld': 'dk', 'country_name': 'Denmark', 'region': 'Europe'},
            'FI': {'tld': 'fi', 'country_name': 'Finland', 'region': 'Europe'},
            'CH': {'tld': 'ch', 'country_name': 'Switzerland', 'region': 'Europe'},
            'AT': {'tld': 'at', 'country_name': 'Austria', 'region': 'Europe'},
            
            # Asia-Pacific
            'JP': {'tld': 'jp', 'country_name': 'Japan', 'region': 'Asia-Pacific'},
            'CN': {'tld': 'cn', 'country_name': 'China', 'region': 'Asia-Pacific'},
            'AU': {'tld': 'au', 'country_name': 'Australia', 'region': 'Asia-Pacific'},
            'IN': {'tld': 'in', 'country_name': 'India', 'region': 'Asia-Pacific'},
            'KR': {'tld': 'kr', 'country_name': 'South Korea', 'region': 'Asia-Pacific'},
            'SG': {'tld': 'sg', 'country_name': 'Singapore', 'region': 'Asia-Pacific'},
            'HK': {'tld': 'hk', 'country_name': 'Hong Kong', 'region': 'Asia-Pacific'},
            'TW': {'tld': 'tw', 'country_name': 'Taiwan', 'region': 'Asia-Pacific'},
        }
        
        # Generic TLD mapping
        self.generic_tlds = {
            'com': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'org': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'net': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'edu': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'gov': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'mil': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'int': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'info': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'biz': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'name': {'country_name': 'Generic', 'region': 'Global', 'tld_type': 'generic'},
            'io': {'country_name': 'British Indian Ocean Territory', 'region': 'Global', 'tld_type': 'country_used_generically'},
            'tv': {'country_name': 'Tuvalu', 'region': 'Global', 'tld_type': 'country_used_generically'},
            'me': {'country_name': 'Montenegro', 'region': 'Global', 'tld_type': 'country_used_generically'},
        }

        logger.info("TLD Information Extractor initialized")
    
    def close(self):
        """Close connections"""
        if self.driver:
            self.driver.close()
        if self.mmdb_reader:
            self.mmdb_reader.close()
        logger.info("Connections closed")
    
    def get_all_base_domains(self) -> List[Dict]:
        """Get all base domains from Neo4j with their current TLD information"""
        query = """
        MATCH (d:Domain)
        WHERE d.fqdn IS NOT NULL AND d.fqdn <> ""
        OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)
        RETURN d.fqdn as fqdn,
               d.tld as current_tld,
               d.tld_country_code as current_country_code,
               collect(DISTINCT ip.address) as ip_addresses
        ORDER BY d.fqdn
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                domains = []
                for record in result:
                    domains.append({
                        'fqdn': record['fqdn'],
                        'current_tld': record['current_tld'],
                        'current_country_code': record['current_country_code'],
                        'ip_addresses': record['ip_addresses']
                    })
                logger.info(f"Retrieved {len(domains)} base domains from Neo4j")
                return domains
        except Exception as e:
            logger.error(f"Error retrieving domains: {e}")
            return []
    
    def extract_tld_from_domain(self, domain: str) -> Dict:
        """Extract TLD information using tldextract"""
        try:
            ext = tldextract.extract(domain)
            return {
                'tld': ext.suffix.lower() if ext.suffix else None,
                'domain_part': ext.domain,
                'subdomain_part': ext.subdomain,
                'registered_domain': ext.registered_domain
            }
        except Exception as e:
            logger.warning(f"Error extracting TLD from {domain}: {e}")
            return {'tld': None, 'domain_part': None, 'subdomain_part': None, 'registered_domain': None}
    
    def get_country_from_ip(self, ip_address: str) -> Optional[Dict]:
        """Get country information from IP address using MMDB"""
        if not self.mmdb_reader:
            return None
            
        try:
            response = self.mmdb_reader.get(ip_address)
            if response:
                country_code = response.get('country_code', response.get('country', ''))
                country_name = response.get('country_name', '')
                
                return {
                    'country_code': country_code,
                    'country_name': country_name,
                    'source': 'mmdb'
                }
        except Exception as e:
            logger.debug(f"Error getting country for IP {ip_address}: {e}")
        
        return None
    
    def resolve_domain_to_ip(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        try:
            result = socket.getaddrinfo(domain, None)
            for family, type, proto, canonname, sockaddr in result:
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
        except Exception as e:
            logger.debug(f"Could not resolve {domain}: {e}")
        
        return ips
    
    def classify_tld(self, tld: str, domain_info: Dict) -> Dict:
        """Classify TLD and determine country information"""
        if not tld:
            return {
                'tld': None,
                'tld_type': 'unknown',
                'country_code': None,
                'country_name': 'Unknown',
                'region': 'Unknown',
                'source': 'none'
            }
        
        tld = tld.lower()
        
        # Check if it's a generic TLD
        if tld in self.generic_tlds:
            generic_info = self.generic_tlds[tld]
            return {
                'tld': tld,
                'tld_type': generic_info.get('tld_type', 'generic'),
                'country_code': None,
                'country_name': generic_info['country_name'],
                'region': generic_info['region'],
                'source': 'hardcoded_generic'
            }
        
        # Look for country-code TLD
        for country_code, mapping in self.country_to_tld_mapping.items():
            if mapping['tld'] == tld:
                return {
                    'tld': tld,
                    'tld_type': 'country_code',
                    'country_code': country_code,
                    'country_name': mapping['country_name'],
                    'region': mapping['region'],
                    'source': 'hardcoded_country'
                }
        
        # Try to get country from IP addresses
        if domain_info.get('ip_addresses'):
            for ip in domain_info['ip_addresses']:
                if ip:
                    country_info = self.get_country_from_ip(ip)
                    if country_info and country_info.get('country_code'):
                        cc = country_info['country_code']
                        if cc in self.country_to_tld_mapping:
                            mapping = self.country_to_tld_mapping[cc]
                            return {
                                'tld': tld,
                                'tld_type': 'country_code_inferred',
                                'country_code': cc,
                                'country_name': mapping['country_name'],
                                'region': mapping['region'],
                                'source': 'ip_geolocation'
                            }
        
        # If no existing IP, try to resolve
        if not domain_info.get('ip_addresses'):
            ips = self.resolve_domain_to_ip(domain_info.get('fqdn', ''))
            for ip in ips:
                country_info = self.get_country_from_ip(ip)
                if country_info and country_info.get('country_code'):
                    cc = country_info['country_code']
                    if cc in self.country_to_tld_mapping:
                        mapping = self.country_to_tld_mapping[cc]
                        return {
                            'tld': tld,
                            'tld_type': 'country_code_resolved',
                            'country_code': cc,
                            'country_name': mapping['country_name'],
                            'region': mapping['region'],
                            'source': 'ip_resolution'
                        }
        
        # Unknown TLD
        return {
            'tld': tld,
            'tld_type': 'unknown',
            'country_code': None,
            'country_name': 'Unknown',
            'region': 'Unknown',
            'source': 'unknown'
        }
    
    def extract_tld_information(self) -> Dict:
        """Main extraction function"""
        logger.info("Starting TLD information extraction")
        
        # Get all base domains
        domains = self.get_all_base_domains()
        
        if not domains:
            logger.error("No domains found")
            return {}
        
        # Process each domain
        tld_data = defaultdict(lambda: {
            'domains': [],
            'count': 0,
            'tld_info': None
        })
        
        domain_details = []
        
        for domain_info in domains:
            fqdn = domain_info['fqdn']
            logger.debug(f"Processing {fqdn}")
            
            # Extract TLD using tldextract
            tld_extract_info = self.extract_tld_from_domain(fqdn)
            extracted_tld = tld_extract_info.get('tld')
            
            # Use extracted TLD, fallback to current_tld if needed
            final_tld = extracted_tld or domain_info.get('current_tld')
            
            # Classify TLD
            tld_classification = self.classify_tld(final_tld, domain_info)
            
            # Store domain details
            domain_detail = {
                'fqdn': fqdn,
                'extracted_tld': extracted_tld,
                'current_tld': domain_info.get('current_tld'),
                'current_country_code': domain_info.get('current_country_code'),
                'final_tld': final_tld,
                'tld_classification': tld_classification,
                'ip_addresses': domain_info.get('ip_addresses', []),
                'tld_extract_info': tld_extract_info
            }
            domain_details.append(domain_detail)
            
            # Aggregate by TLD
            if final_tld:
                tld_data[final_tld]['domains'].append(fqdn)
                tld_data[final_tld]['count'] += 1
                tld_data[final_tld]['tld_info'] = tld_classification
        
        # Generate statistics
        statistics = {
            'total_domains': len(domains),
            'domains_with_tld': len([d for d in domain_details if d['final_tld']]),
            'domains_without_tld': len([d for d in domain_details if not d['final_tld']]),
            'unique_tlds': len(tld_data),
            'tld_type_distribution': defaultdict(int),
            'region_distribution': defaultdict(int),
            'source_distribution': defaultdict(int)
        }
        
        for tld, data in tld_data.items():
            tld_info = data['tld_info']
            if tld_info:
                statistics['tld_type_distribution'][tld_info.get('tld_type', 'unknown')] += data['count']
                statistics['region_distribution'][tld_info.get('region', 'Unknown')] += data['count']
                statistics['source_distribution'][tld_info.get('source', 'unknown')] += data['count']
        
        # Final result
        result = {
            'metadata': {
                'extraction_timestamp': str(datetime.now()),
                'mmdb_path': self.mmdb_path,
                'total_domains_analyzed': len(domains)
            },
            'statistics': dict(statistics),
            'tld_data': dict(tld_data),
            'domain_details': domain_details
        }
        
        logger.info("TLD information extraction completed")
        return result

def main():
    parser = argparse.ArgumentParser(description='Extract TLD information from Neo4j domains')
    parser.add_argument('--output', '-o', default='tld_information.json',
                        help='Output JSON file (default: tld_information.json)')
    parser.add_argument('--mmdb-path', '-m', default=DEFAULT_MMDB_PATH,
                        help=f'Path to MMDB database (default: {DEFAULT_MMDB_PATH})')
    parser.add_argument('--stats-only', '-s', action='store_true',
                        help='Show statistics only, do not save file')
    
    args = parser.parse_args()
    
    # Check dependencies
    missing_deps = []
    try:
        import tldextract
    except ImportError:
        missing_deps.append('tldextract')
    
    try:
        import maxminddb
    except ImportError:
        missing_deps.append('maxminddb')
    
    if missing_deps:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print(f"💡 Install with: pip install {' '.join(missing_deps)}")
        return
    
    # Check MMDB file
    import os
    if not os.path.exists(args.mmdb_path):
        logger.warning(f"⚠️ MMDB file not found at {args.mmdb_path}")
        logger.warning("Country detection from IP will be disabled")
        args.mmdb_path = None
    
    extractor = TLDInformationExtractor(args.mmdb_path)
    
    try:
        # Extract TLD information
        result = extractor.extract_tld_information()
        
        if not result:
            print("❌ No data extracted")
            return
        
        # Print statistics
        stats = result.get('statistics', {})
        print("\n" + "="*80)
        print("TLD INFORMATION EXTRACTION SUMMARY")
        print("="*80)
        print(f"📊 Total domains analyzed: {stats.get('total_domains', 0)}")
        print(f"✅ Domains with TLD: {stats.get('domains_with_tld', 0)}")
        print(f"❌ Domains without TLD: {stats.get('domains_without_tld', 0)}")
        print(f"🌐 Unique TLDs found: {stats.get('unique_tlds', 0)}")
        
        print("\n📈 TLD Type Distribution:")
        for tld_type, count in stats.get('tld_type_distribution', {}).items():
            print(f"   • {tld_type}: {count} domains")
        
        print("\n🌍 Region Distribution:")
        for region, count in stats.get('region_distribution', {}).items():
            print(f"   • {region}: {count} domains")
        
        print("\n🔍 Source Distribution:")
        for source, count in stats.get('source_distribution', {}).items():
            print(f"   • {source}: {count} domains")
        
        print("\n🏆 Top 10 TLDs:")
        tld_data = result.get('tld_data', {})
        sorted_tlds = sorted(tld_data.items(), key=lambda x: x[1]['count'], reverse=True)
        for tld, data in sorted_tlds[:10]:
            tld_info = data['tld_info']
            country = tld_info.get('country_name', 'Unknown') if tld_info else 'Unknown'
            print(f"   • .{tld}: {data['count']} domains ({country})")
        
        if not args.stats_only:
            # Save to JSON file
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False, default=str)
                print(f"\n📄 TLD information saved to: {args.output}")
                print(f"💡 Use create_tld_nodes.py to create TLD nodes in Neo4j")
            except Exception as e:
                logger.error(f"Error saving results: {e}")
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
    
    finally:
        extractor.close()

if __name__ == "__main__":
    from datetime import datetime
    main()