#!/usr/bin/env python3
"""
Identify Invalid Base Domains Script

This script analyzes all Domain nodes in the Neo4j graph and identifies which ones
are actually subdomains (not true base domains) using the tldextract library and
proper domain classification logic.

Usage:
    python3 identify_invalid_base_domains.py [--output invalid_base_domains.txt] [--stats-only]

Requirements:
    pip install tldextract
"""

import argparse
import logging
import json
from neo4j import GraphDatabase
from urllib.parse import urlsplit
import ipaddress
import tldextract

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Neo4j connection configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

def _normalize_host(s: str) -> str:
    """
    Acepta host o URL y devuelve solo el host normalizado (lowercase, sin puerto,
    sin corchetes IPv6, sin punto final).
    """
    s = s.strip()
    # Si viene como URL, extrae netloc; si no, trata 's' como host
    parts = urlsplit(s if "://" in s else f"//{s}", scheme="http")
    host = parts.hostname or ""
    host = host.rstrip(".").lower()
    return host

def classify_domain(s: str):
    """
    Retorna un dict con:
      - input: string original
      - host: host normalizado
      - type: 'ip', 'localhost', 'invalid', o 'domain'
      - base_domain: eTLD+1 cuando aplique
      - is_base_domain: True si host == eTLD+1 (registered/registrable domain)
      - subdomain_parts: lista de labels del subdominio
      - suffix: TLD/sufijo público
    """
    raw = s
    host = _normalize_host(s)
    if not host:
        return {"input": raw, "host": host, "type": "invalid", "reason": "empty host"}

    # IPs
    try:
        ipaddress.ip_address(host)
        return {"input": raw, "host": host, "type": "ip"}
    except ValueError:
        pass

    # 'localhost' y similares (sin sufijo público)
    if host == "localhost":
        return {"input": raw, "host": host, "type": "localhost"}

    ext = tldextract.extract(host)
    # ext.suffix vacío => no es FQDN válido con PSL
    if not ext.suffix:
        return {"input": raw, "host": host, "type": "invalid", "reason": "no public suffix"}

    registered = ext.registered_domain  # dominio registrable (eTLD+1)
    is_base = (host == registered)
    sub_parts = ext.subdomain.split(".") if ext.subdomain else []

    return {
        "input": raw,
        "host": host,
        "type": "domain",
        "base_domain": registered,
        "is_base_domain": is_base,
        "subdomain_parts": sub_parts,
        "suffix": ext.suffix,
    }

def is_base_domain(s: str) -> bool:
    info = classify_domain(s)
    return info.get("type") == "domain" and info.get("is_base_domain", False)

class InvalidBaseDomainIdentifier:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        logger.info(f"Connected to Neo4j at {NEO4J_URI}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def get_all_domain_nodes(self):
        """Get all Domain nodes from the graph"""
        query = """
        MATCH (d:Domain)
        WHERE d.fqdn IS NOT NULL AND d.fqdn <> ""
        RETURN d.fqdn as fqdn, id(d) as node_id
        ORDER BY d.fqdn
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                domains = [(record["fqdn"], record["node_id"]) for record in result]
                logger.info(f"Found {len(domains)} Domain nodes in the graph")
                return domains
        except Exception as e:
            logger.error(f"Error getting domain nodes: {e}")
            return []
    
    def analyze_domains(self, domains):
        """Analyze domains and classify them"""
        results = {
            "valid_base_domains": [],
            "invalid_base_domains": [],  # These are subdomains stored as Domain nodes
            "ip_addresses": [],
            "localhost_entries": [],
            "invalid_entries": [],
            "classification_details": []
        }
        
        logger.info("Starting domain classification analysis...")
        
        for fqdn, node_id in domains:
            classification = classify_domain(fqdn)
            classification["node_id"] = node_id
            
            results["classification_details"].append(classification)
            
            if classification["type"] == "domain":
                if classification["is_base_domain"]:
                    results["valid_base_domains"].append({
                        "fqdn": fqdn,
                        "node_id": node_id,
                        "base_domain": classification["base_domain"],
                        "suffix": classification["suffix"]
                    })
                else:
                    # This is a subdomain stored as a Domain node - INVALID!
                    results["invalid_base_domains"].append({
                        "fqdn": fqdn,
                        "node_id": node_id,
                        "base_domain": classification["base_domain"],
                        "subdomain_parts": classification["subdomain_parts"],
                        "suffix": classification["suffix"]
                    })
            elif classification["type"] == "ip":
                results["ip_addresses"].append({
                    "fqdn": fqdn,
                    "node_id": node_id,
                    "host": classification["host"]
                })
            elif classification["type"] == "localhost":
                results["localhost_entries"].append({
                    "fqdn": fqdn,
                    "node_id": node_id,
                    "host": classification["host"]
                })
            elif classification["type"] == "invalid":
                results["invalid_entries"].append({
                    "fqdn": fqdn,
                    "node_id": node_id,
                    "host": classification["host"],
                    "reason": classification.get("reason", "unknown")
                })
        
        logger.info("Domain classification completed")
        return results
    
    def print_analysis_summary(self, results):
        """Print summary of the analysis"""
        total = len(results["classification_details"])
        valid_base = len(results["valid_base_domains"])
        invalid_base = len(results["invalid_base_domains"])
        ips = len(results["ip_addresses"])
        localhost = len(results["localhost_entries"])
        invalid = len(results["invalid_entries"])
        
        print("\n" + "="*80)
        print("DOMAIN NODE CLASSIFICATION ANALYSIS")
        print("="*80)
        print(f"📊 Total Domain nodes analyzed: {total}")
        print(f"✅ Valid base domains: {valid_base}")
        print(f"❌ Invalid base domains (subdomains): {invalid_base}")
        print(f"🔢 IP addresses: {ips}")
        print(f"🏠 Localhost entries: {localhost}")
        print(f"⚠️  Invalid entries: {invalid}")
        
        if total > 0:
            invalid_percentage = (invalid_base / total) * 100
            print(f"🚨 Invalid base domains percentage: {invalid_percentage:.1f}%")
        
        print("\n" + "="*80)
        print("PROBLEMS FOUND:")
        print("="*80)
        
        if invalid_base > 0:
            print(f"🚨 {invalid_base} Domain nodes are actually subdomains:")
            for item in results["invalid_base_domains"][:10]:  # Show first 10
                subdomain_part = ".".join(item["subdomain_parts"])
                print(f"   • {item['fqdn']} -> subdomain of {item['base_domain']} (sub: {subdomain_part})")
            if invalid_base > 10:
                print(f"   ... and {invalid_base - 10} more")
        
        if ips > 0:
            print(f"\n🔢 {ips} Domain nodes contain IP addresses:")
            for item in results["ip_addresses"][:5]:
                print(f"   • {item['fqdn']}")
            if ips > 5:
                print(f"   ... and {ips - 5} more")
        
        if localhost > 0:
            print(f"\n🏠 {localhost} Domain nodes are localhost entries:")
            for item in results["localhost_entries"]:
                print(f"   • {item['fqdn']}")
        
        if invalid > 0:
            print(f"\n⚠️  {invalid} Domain nodes are invalid:")
            for item in results["invalid_entries"][:5]:
                print(f"   • {item['fqdn']} ({item['reason']})")
            if invalid > 5:
                print(f"   ... and {invalid - 5} more")
        
        return invalid_base > 0 or ips > 0 or localhost > 0 or invalid > 0
    
    def save_invalid_domains_list(self, results, output_file):
        """Save list of invalid base domains (subdomains) to txt file for deletion"""
        invalid_domains = []
        
        # Add all problematic entries
        for item in results["invalid_base_domains"]:
            invalid_domains.append(item["fqdn"])
        
        for item in results["ip_addresses"]:
            invalid_domains.append(item["fqdn"])
        
        for item in results["localhost_entries"]:
            invalid_domains.append(item["fqdn"])
        
        for item in results["invalid_entries"]:
            invalid_domains.append(item["fqdn"])
        
        if invalid_domains:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for domain in invalid_domains:
                        f.write(f"{domain}\n")
                logger.info(f"Saved {len(invalid_domains)} invalid domains to {output_file}")
                return len(invalid_domains)
            except Exception as e:
                logger.error(f"Error saving invalid domains list: {e}")
        
        return 0
    
    def save_detailed_results(self, results, output_file):
        """Save detailed analysis results to JSON"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Detailed results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving detailed results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Identify invalid base domains in Neo4j graph')
    parser.add_argument('--output', '-o', default='invalid_base_domains.txt',
                        help='Output TXT file with invalid domains for deletion (default: invalid_base_domains.txt)')
    parser.add_argument('--detailed-output', '-d', 
                        help='Output JSON file with detailed analysis (default: auto-generated)')
    parser.add_argument('--stats-only', '-s', action='store_true',
                        help='Show statistics only, do not save files')
    
    args = parser.parse_args()
    
    # Auto-generate detailed output filename
    if not args.detailed_output and not args.stats_only:
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        args.detailed_output = f"domain_analysis_detailed_{timestamp}.json"
    
    # Check tldextract dependency
    try:
        import tldextract
        logger.info("tldextract library available")
    except ImportError:
        print("❌ Error: tldextract library not found")
        print("💡 Install with: pip install tldextract")
        return
    
    identifier = InvalidBaseDomainIdentifier()
    
    try:
        # Get all domain nodes
        domains = identifier.get_all_domain_nodes()
        
        if not domains:
            print("❌ No Domain nodes found in the graph")
            return
        
        # Analyze domains
        results = identifier.analyze_domains(domains)
        
        # Print summary
        has_problems = identifier.print_analysis_summary(results)
        
        if not args.stats_only:
            # Save invalid domains list for deletion
            invalid_count = identifier.save_invalid_domains_list(results, args.output)
            
            # Save detailed results
            if args.detailed_output:
                identifier.save_detailed_results(results, args.detailed_output)
            
            if invalid_count > 0:
                print(f"\n📄 {invalid_count} invalid domains saved to: {args.output}")
                print(f"💡 Use delete_invalid_base_domains.py to remove them from the graph")
                if args.detailed_output:
                    print(f"📊 Detailed analysis saved to: {args.detailed_output}")
            else:
                print(f"\n✅ No invalid domains found - graph is clean!")
        
        if has_problems and not args.stats_only:
            print(f"\n🚨 ACTION REQUIRED: {len(results['invalid_base_domains'])} Domain nodes are actually subdomains")
            print(f"   These should be moved to Subdomain nodes or deleted.")
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
    
    finally:
        identifier.close()

if __name__ == "__main__":
    main()