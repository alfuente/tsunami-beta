#!/usr/bin/env python3
"""
extract_web_subdomains.py - Extract subdomains with web services

Extracts all subdomains from Neo4j that have web services running on ports:
- 80 (HTTP)
- 443 (HTTPS) 
- 8080 (HTTP alternate)
- 8443 (HTTPS alternate)

Outputs a CSV file with subdomain, base domain, and detected web ports.

Usage:
    python3 extract_web_subdomains.py --output web_subdomains.csv
    python3 extract_web_subdomains.py --output web_subdomains.csv --neo4j-uri bolt://localhost:7687
"""

import json
import logging
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import sys
import os
import argparse

try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Error: Neo4j driver not available. Run: pip install neo4j")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WebSubdomain:
    subdomain: str
    base_domain: str
    web_ports: List[int]
    services_count: int
    has_http: bool
    has_https: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'subdomain': self.subdomain,
            'base_domain': self.base_domain,
            'web_ports': ','.join(map(str, self.web_ports)),
            'services_count': self.services_count,
            'has_http': self.has_http,
            'has_https': self.has_https
        }

class WebSubdomainExtractor:
    """Extracts subdomains with web services from Neo4j graph"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", 
                 neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.web_ports = [80, 443, 8080, 8443]

    def close(self):
        if hasattr(self, 'driver'):
            self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Neo4j query and return results"""
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return list(result)
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def extract_base_domain(self, fqdn: str) -> str:
        """Extract base domain from FQDN"""
        if not fqdn:
            return ""
        
        parts = fqdn.split('.')
        if len(parts) >= 2:
            # Handle common TLDs
            if len(parts) >= 3 and parts[-2] in ['com', 'org', 'net', 'edu', 'gov', 'mil']:
                return '.'.join(parts[-3:])  # e.g., example.com.ar
            else:
                return '.'.join(parts[-2:])  # e.g., example.com
        return fqdn

    def extract_web_subdomains(self) -> List[WebSubdomain]:
        """Extract all subdomains with web services"""
        logger.info("Extracting subdomains with web services...")
        
        # Query to find subdomains with web services on specific ports
        query = """
        MATCH (s:Subdomain)-[:RUNS_SERVICE]->(svc:Service)
        WHERE svc.port IN $web_ports
        WITH s, collect(DISTINCT svc.port) as web_ports, count(svc) as service_count
        WHERE size(web_ports) > 0
        RETURN s.fqdn as subdomain,
               web_ports,
               service_count,
               s.services_count as total_services
        ORDER BY s.fqdn
        """
        
        results = self.run_query(query, {"web_ports": self.web_ports})
        
        web_subdomains = []
        for record in results:
            subdomain = record.get('subdomain', '')
            if not subdomain:
                continue
                
            web_ports = record.get('web_ports', [])
            service_count = record.get('service_count', 0)
            total_services = record.get('total_services', 0)
            
            # Extract base domain
            base_domain = self.extract_base_domain(subdomain)
            
            # Check for HTTP/HTTPS
            has_http = any(port in [80, 8080] for port in web_ports)
            has_https = any(port in [443, 8443] for port in web_ports)
            
            web_subdomains.append(WebSubdomain(
                subdomain=subdomain,
                base_domain=base_domain,
                web_ports=sorted(web_ports),
                services_count=service_count,
                has_http=has_http,
                has_https=has_https
            ))
        
        logger.info(f"Found {len(web_subdomains)} subdomains with web services")
        return web_subdomains

    def get_statistics(self, web_subdomains: List[WebSubdomain]) -> Dict[str, Any]:
        """Generate statistics about the extracted subdomains"""
        if not web_subdomains:
            return {}
        
        base_domains = set(ws.base_domain for ws in web_subdomains)
        total_subdomains = len(web_subdomains)
        
        # Port statistics
        port_counts = {}
        for ws in web_subdomains:
            for port in ws.web_ports:
                port_counts[port] = port_counts.get(port, 0) + 1
        
        # Protocol statistics
        http_count = sum(1 for ws in web_subdomains if ws.has_http)
        https_count = sum(1 for ws in web_subdomains if ws.has_https)
        both_count = sum(1 for ws in web_subdomains if ws.has_http and ws.has_https)
        
        # Base domain distribution
        domain_counts = {}
        for ws in web_subdomains:
            domain_counts[ws.base_domain] = domain_counts.get(ws.base_domain, 0) + 1
        
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_subdomains': total_subdomains,
            'unique_base_domains': len(base_domains),
            'port_distribution': port_counts,
            'protocol_stats': {
                'http_only': http_count - both_count,
                'https_only': https_count - both_count,
                'both_http_https': both_count,
                'total_http': http_count,
                'total_https': https_count
            },
            'top_base_domains': top_domains
        }

    def export_to_csv(self, web_subdomains: List[WebSubdomain], output_file: str) -> None:
        """Export results to CSV file"""
        logger.info(f"Exporting {len(web_subdomains)} records to {output_file}")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['subdomain', 'base_domain', 'web_ports', 'services_count', 'has_http', 'has_https']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for ws in web_subdomains:
                writer.writerow(ws.to_dict())
        
        logger.info(f"CSV export completed: {output_file}")

    def export_to_json(self, web_subdomains: List[WebSubdomain], output_file: str, 
                      include_stats: bool = True) -> None:
        """Export results to JSON file"""
        logger.info(f"Exporting {len(web_subdomains)} records to {output_file}")
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_records': len(web_subdomains),
            'subdomains': [ws.to_dict() for ws in web_subdomains]
        }
        
        if include_stats:
            data['statistics'] = self.get_statistics(web_subdomains)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON export completed: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Extract subdomains with web services from Neo4j")
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687',
                      help='Neo4j URI (default: bolt://localhost:7687)')
    parser.add_argument('--neo4j-user', default='neo4j',
                      help='Neo4j username (default: neo4j)')
    parser.add_argument('--neo4j-password', default='neo4j',
                      help='Neo4j password (default: neo4j)')
    parser.add_argument('--output', '-o', default='web_subdomains.csv',
                      help='Output CSV file (default: web_subdomains.csv)')
    parser.add_argument('--json-output',
                      help='Additional JSON output file')
    parser.add_argument('--format', choices=['csv', 'json', 'both'], default='csv',
                      help='Output format (default: csv)')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Verbose logging')
    parser.add_argument('--stats-only', action='store_true',
                      help='Show statistics only, do not export files')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        with WebSubdomainExtractor(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        ) as extractor:
            
            # Extract web subdomains
            web_subdomains = extractor.extract_web_subdomains()
            
            if not web_subdomains:
                logger.warning("No subdomains with web services found")
                sys.exit(0)
            
            # Generate and display statistics
            stats = extractor.get_statistics(web_subdomains)
            
            print(f"\n{'='*60}")
            print("WEB SUBDOMAINS EXTRACTION SUMMARY")
            print(f"{'='*60}")
            print(f"Total subdomains with web services: {stats['total_subdomains']}")
            print(f"Unique base domains: {stats['unique_base_domains']}")
            
            print(f"\nPort Distribution:")
            for port, count in sorted(stats['port_distribution'].items()):
                print(f"  Port {port}: {count} subdomains")
            
            print(f"\nProtocol Distribution:")
            proto_stats = stats['protocol_stats']
            print(f"  HTTP only: {proto_stats['http_only']}")
            print(f"  HTTPS only: {proto_stats['https_only']}")
            print(f"  Both HTTP & HTTPS: {proto_stats['both_http_https']}")
            
            print(f"\nTop Base Domains:")
            for domain, count in stats['top_base_domains']:
                print(f"  {domain}: {count} subdomains")
            
            if args.stats_only:
                print(f"\n{'='*60}")
                return
            
            # Export results
            if args.format in ['csv', 'both']:
                extractor.export_to_csv(web_subdomains, args.output)
            
            if args.format in ['json', 'both']:
                json_file = args.json_output or args.output.replace('.csv', '.json')
                extractor.export_to_json(web_subdomains, json_file)
            
            print(f"\n{'='*60}")
            print("EXPORT COMPLETED")
            if args.format in ['csv', 'both']:
                print(f"CSV file: {args.output}")
            if args.format in ['json', 'both']:
                json_file = args.json_output or args.output.replace('.csv', '.json')
                print(f"JSON file: {json_file}")
            print(f"{'='*60}")
    
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()