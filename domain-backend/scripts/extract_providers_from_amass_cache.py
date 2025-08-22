#!/usr/bin/env python3
"""
Script para extraer información de proveedores desde el cache de amass

Este script:
1. Lee los archivos de cache de amass
2. Extrae información de ASN, organizaciones y CNAME records
3. Mapea esta información a los proveedores de Neo4j
4. Actualiza las conexiones en Neo4j
"""

import json
import gzip
import os
import logging
import re
from typing import Dict, List, Optional, Set
from neo4j import GraphDatabase
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AmassProviderExtractor:
    def __init__(self, cache_dir="../amass_cache", neo4j_uri="bolt://localhost:7687", 
                 neo4j_user="neo4j", neo4j_password="test.password"):
        self.cache_dir = cache_dir
        self.metadata_dir = os.path.join(cache_dir, "metadata")
        self.data_dir = os.path.join(cache_dir, "data")
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.session = None
        
        # Provider patterns based on amass data
        self.provider_patterns = {
            'amazon': {
                'asn_orgs': ['amazon.com', 'amazon-aes', 'aws'],
                'domains': ['amazonaws.com', 'aws.amazon.com'],
                'cname_patterns': ['amazonaws.com', 'aws.amazon.com']
            },
            'akamai': {
                'asn_orgs': ['akamai-asn', 'akamai technologies', 'akamai-la'],
                'domains': ['akamai.com', 'akamaiedge.net', 'akamaitechnologies.com'],
                'cname_patterns': ['akamaiedge.net', 'akamaitechnologies.com', 'edgekey.net']
            },
            'salesforce': {
                'asn_orgs': ['salesforce.com'],
                'domains': ['salesforce.com', 'force.com'],
                'cname_patterns': ['salesforce.com']
            },
            'fastly': {
                'asn_orgs': ['fastnet-as-id', 'linknet-fastnet'],
                'domains': ['fastly.com', 'fastlylb.net'],
                'cname_patterns': ['fastly.com', 'fastlylb.net']
            },
            'google': {
                'asn_orgs': ['google inc', 'google llc'],
                'domains': ['google.com', 'googleapis.com', 'googleusercontent.com'],
                'cname_patterns': ['google.com', 'googleapis.com', 'googleusercontent.com']
            },
            'microsoft': {
                'asn_orgs': ['microsoft'],
                'domains': ['azure.com', 'outlook.com', 'office.com', 'office365.com'],
                'cname_patterns': ['outlook.com', 'office365.com', 'azurewebsites.net']
            },
            'cloudflare': {
                'asn_orgs': ['cloudflare'],
                'domains': ['cloudflare.com'],
                'cname_patterns': ['cloudflare.com']
            },
            'github': {
                'asn_orgs': ['github'],
                'domains': ['github.com', 'githubusercontent.com'],
                'cname_patterns': ['github.com', 'githubusercontent.com']
            }
        }
    
    def __enter__(self):
        self.session = self.driver.session()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()
        self.driver.close()
    
    def get_cached_domains(self) -> List[str]:
        """Get list of domains with valid cache"""
        domains = []
        if not os.path.exists(self.metadata_dir):
            return domains
            
        for filename in os.listdir(self.metadata_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(self.metadata_dir, filename), 'r') as f:
                        metadata = json.load(f)
                    if 'domain' in metadata:
                        domains.append(metadata['domain'])
                except Exception as e:
                    logger.debug(f"Error reading metadata {filename}: {e}")
        
        return domains
    
    def parse_amass_output(self, domain: str) -> Dict:
        """Parse amass output from cache for a domain"""
        try:
            # Look for amass output files with any timestamp
            import glob
            amass_files = glob.glob(f"/tmp/amass_output_{domain}_*.txt")
            if amass_files:
                # Use the most recent file
                amass_file = max(amass_files, key=os.path.getmtime)
                logger.info(f"📄 Found amass file: {amass_file}")
                return self._parse_amass_file(amass_file)
            
            # Try exact match
            amass_file = f"/tmp/amass_output_{domain}.txt"
            if os.path.exists(amass_file):
                return self._parse_amass_file(amass_file)
            
            # Fallback to cached data
            domain_hash = self._generate_hash(domain)
            data_file = os.path.join(self.data_dir, f"{domain_hash}.json.gz")
            if os.path.exists(data_file):
                with gzip.open(data_file, 'rt', encoding='utf-8') as f:
                    return json.load(f)
            
        except Exception as e:
            logger.error(f"Error parsing amass output for {domain}: {e}")
        
        return {}
    
    def _parse_amass_file(self, file_path: str) -> Dict:
        """Parse raw amass output file to extract provider relationships"""
        results = {
            'asn_relationships': [],
            'cname_relationships': [],
            'organizations': set(),
            'subdomains': [],
            'raw_lines': []
        }
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    results['raw_lines'].append(line)
                    
                    # Parse ASN relationships
                    if ' (ASN) --> managed_by --> ' in line:
                        parts = line.split(' --> ')
                        if len(parts) >= 3:
                            asn = parts[0].split(' ')[0]
                            org = parts[2].split(' (')[0]
                            results['asn_relationships'].append({'asn': asn, 'org': org})
                            results['organizations'].add(org.lower())
                    
                    # Parse CNAME relationships
                    elif ' --> cname_record --> ' in line:
                        parts = line.split(' --> ')
                        if len(parts) >= 3:
                            source = parts[0].split(' ')[0]
                            target = parts[2].split(' ')[0]
                            results['cname_relationships'].append({'source': source, 'target': target})
                    
                    # Parse subdomains (FQDNs)
                    elif '(FQDN)' in line and '-->' not in line:
                        subdomain = line.split(' ')[0]
                        if subdomain and '.' in subdomain:
                            results['subdomains'].append(subdomain)
        
        except Exception as e:
            logger.error(f"Error parsing amass file {file_path}: {e}")
        
        results['organizations'] = list(results['organizations'])
        return results
    
    def _generate_hash(self, domain: str) -> str:
        """Generate hash for domain (same as standalone_amass_executor.sh)"""
        import hashlib
        return hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    def detect_providers_from_amass_data(self, amass_data: Dict) -> Dict[str, List[str]]:
        """Detect providers from amass data"""
        detected_providers = {}
        
        # Check ASN organizations
        for org in amass_data.get('organizations', []):
            org_lower = org.lower()
            for provider_id, patterns in self.provider_patterns.items():
                for pattern in patterns['asn_orgs']:
                    if pattern in org_lower:
                        if provider_id not in detected_providers:
                            detected_providers[provider_id] = []
                        detected_providers[provider_id].append(f"ASN org: {org}")
        
        # Check CNAME relationships
        for cname in amass_data.get('cname_relationships', []):
            target = cname['target'].lower()
            source = cname['source'].lower()
            
            for provider_id, patterns in self.provider_patterns.items():
                for pattern in patterns['cname_patterns']:
                    if pattern in target:
                        if provider_id not in detected_providers:
                            detected_providers[provider_id] = []
                        detected_providers[provider_id].append(f"CNAME: {cname['source']} -> {cname['target']}")
        
        # Check MX records for email providers
        mx_records = []
        for line_data in amass_data.get('raw_lines', []):
            if 'mx_record' in line_data:
                mx_records.append(line_data)
        
        for mx in mx_records:
            mx_lower = mx.lower()
            
            # Google Workspace detection
            if 'google.com' in mx_lower:
                if 'google' not in detected_providers:
                    detected_providers['google'] = []
                detected_providers['google'].append(f"MX: {mx}")
            
            # Microsoft detection
            if 'outlook.com' in mx_lower or 'office365.com' in mx_lower:
                if 'microsoft' not in detected_providers:
                    detected_providers['microsoft'] = []
                detected_providers['microsoft'].append(f"MX: {mx}")
        
        # Check NS records for DNS providers
        ns_records = []
        for line_data in amass_data.get('raw_lines', []):
            if 'ns_record' in line_data:
                ns_records.append(line_data)
        
        for ns in ns_records:
            ns_lower = ns.lower()
            
            # AWS Route53 detection
            if 'awsdns' in ns_lower:
                if 'amazon' not in detected_providers:
                    detected_providers['amazon'] = []
                detected_providers['amazon'].append(f"NS: {ns}")
        
        return detected_providers
    
    def update_neo4j_provider_connections(self, domain: str, providers: Dict[str, List[str]]):
        """Update Neo4j with provider connections"""
        current_time = datetime.now().isoformat()
        
        for provider_id, evidence in providers.items():
            # Check if provider exists in our curated list
            query = """
            MATCH (p:Provider {id: $provider_id})
            MATCH (d:Domain {fqdn: $domain})
            MERGE (d)-[r:USES_PROVIDER]->(p)
            SET r.detection_method = 'amass_cache',
                r.evidence = $evidence,
                r.confidence = 0.9,
                r.created_at = $current_time,
                r.updated_at = $current_time
            RETURN d.fqdn, p.name
            """
            
            try:
                result = self.session.run(query, 
                                        provider_id=provider_id, 
                                        domain=domain, 
                                        evidence=evidence,
                                        current_time=current_time)
                
                record = result.single()
                if record:
                    logger.info(f"✅ Connected {domain} -> {record['p.name']} (evidence: {len(evidence)} items)")
                else:
                    logger.warning(f"⚠️ Provider {provider_id} not found in Neo4j for domain {domain}")
                    
            except Exception as e:
                logger.error(f"❌ Error updating Neo4j for {domain} -> {provider_id}: {e}")
    
    def process_domain_cache(self, domain: str):
        """Process cache for a single domain"""
        logger.info(f"🔍 Processing cache for {domain}")
        
        amass_data = self.parse_amass_output(domain)
        if not amass_data:
            logger.warning(f"No amass data found for {domain}")
            return
        
        providers = self.detect_providers_from_amass_data(amass_data)
        if providers:
            logger.info(f"📊 Found {len(providers)} providers for {domain}: {list(providers.keys())}")
            self.update_neo4j_provider_connections(domain, providers)
        else:
            logger.info(f"❌ No providers detected for {domain}")
    
    def process_all_cached_domains(self):
        """Process all domains with cache"""
        domains = self.get_cached_domains()
        logger.info(f"🚀 Processing {len(domains)} cached domains")
        
        processed = 0
        for domain in domains:
            try:
                self.process_domain_cache(domain)
                processed += 1
            except Exception as e:
                logger.error(f"Error processing {domain}: {e}")
        
        logger.info(f"✅ Processed {processed}/{len(domains)} domains")
        return processed

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Extract providers from amass cache')
    parser.add_argument('--cache-dir', default='../amass_cache', help='Amass cache directory')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='test.password', help='Neo4j password')
    parser.add_argument('--domain', help='Process specific domain only')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("AMASS CACHE PROVIDER EXTRACTION")
    print("=" * 60)
    print(f"Cache directory: {args.cache_dir}")
    print(f"Neo4j URI: {args.neo4j_uri}")
    print("=" * 60)
    
    try:
        with AmassProviderExtractor(args.cache_dir, args.neo4j_uri, 
                                  args.neo4j_user, args.neo4j_password) as extractor:
            
            if args.domain:
                extractor.process_domain_cache(args.domain)
            else:
                processed = extractor.process_all_cached_domains()
                
                print("\n" + "=" * 60)
                print("EXTRACTION COMPLETED")
                print("=" * 60)
                print(f"✅ Processed domains: {processed}")
                print("=" * 60)
            
    except Exception as e:
        logger.error(f"❌ Extraction failed: {e}")
        raise

if __name__ == "__main__":
    main()