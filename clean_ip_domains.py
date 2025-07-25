#!/usr/bin/env python3
"""
clean_ip_domains.py - Remove IP addresses that were incorrectly stored as domains/base domains

This script identifies and removes nodes in the Neo4j graph that are IP addresses
but were stored as Domain or Subdomain nodes.
"""

import argparse
import ipaddress
import logging
import re
from typing import List, Dict, Any
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

def is_ip_address(value: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False

def is_valid_domain_name(domain: str) -> bool:
    """Check if a string is a valid domain name (not an IP address)."""
    if not domain:
        return False
    
    # Check if it's an IP address
    if is_ip_address(domain):
        return False
    
    # Basic domain name validation
    if len(domain) > 255:
        return False
    
    # Domain must contain at least one dot for TLD
    if '.' not in domain:
        return False
    
    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False
    
    # Each part must be valid
    parts = domain.split('.')
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

class GraphCleaner:
    """Clean IP addresses from Neo4j graph."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        """Initialize the cleaner."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.test_connection()
    
    def test_connection(self):
        """Test Neo4j connection."""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            logging.info("Neo4j connection successful")
        except Exception as e:
            logging.error(f"Neo4j connection failed: {e}")
            raise
    
    def find_ip_domains(self) -> Dict[str, List[str]]:
        """Find all domains that are actually IP addresses."""
        ip_domains = {'domains': [], 'subdomains': []}
        
        with self.driver.session() as session:
            # Find IP addresses stored as Domain nodes
            result = session.run("""
                MATCH (d:Domain)
                RETURN d.fqdn as fqdn
            """)
            
            for record in result:
                fqdn = record.get('fqdn', '')
                if fqdn and is_ip_address(fqdn):
                    ip_domains['domains'].append(fqdn)
                    logging.warning(f"Found IP address stored as Domain: {fqdn}")
            
            # Find IP addresses stored as Subdomain nodes
            result = session.run("""
                MATCH (s:Subdomain)
                RETURN s.fqdn as fqdn
            """)
            
            for record in result:
                fqdn = record.get('fqdn', '')
                if fqdn and is_ip_address(fqdn):
                    ip_domains['subdomains'].append(fqdn)
                    logging.warning(f"Found IP address stored as Subdomain: {fqdn}")
        
        return ip_domains
    
    def find_invalid_base_domains(self) -> List[str]:
        """Find base domains that are IP addresses."""
        invalid_base_domains = []
        
        with self.driver.session() as session:
            # Check base_domain properties
            result = session.run("""
                MATCH (n)
                WHERE n.base_domain IS NOT NULL
                RETURN DISTINCT n.base_domain as base_domain
            """)
            
            for record in result:
                base_domain = record.get('base_domain', '')
                if base_domain and is_ip_address(base_domain):
                    invalid_base_domains.append(base_domain)
                    logging.warning(f"Found IP address stored as base_domain: {base_domain}")
        
        return invalid_base_domains
    
    def clean_ip_domains(self, dry_run: bool = True) -> Dict[str, Any]:
        """Remove IP addresses stored as domains."""
        ip_domains = self.find_ip_domains()
        invalid_base_domains = self.find_invalid_base_domains()
        
        total_domains = len(ip_domains['domains'])
        total_subdomains = len(ip_domains['subdomains'])
        total_base_domains = len(invalid_base_domains)
        
        logging.info(f"Found {total_domains} Domain nodes with IP addresses")
        logging.info(f"Found {total_subdomains} Subdomain nodes with IP addresses")
        logging.info(f"Found {total_base_domains} base_domain properties with IP addresses")
        
        if dry_run:
            logging.info("DRY RUN - No changes will be made")
            return {
                'dry_run': True,
                'ip_domains_found': total_domains,
                'ip_subdomains_found': total_subdomains,
                'ip_base_domains_found': total_base_domains,
                'ip_domains': ip_domains['domains'],
                'ip_subdomains': ip_domains['subdomains'], 
                'ip_base_domains': invalid_base_domains
            }
        
        removed_count = 0
        updated_count = 0
        
        with self.driver.session() as session:
            with session.begin_transaction() as tx:
                # Remove Domain nodes that are IP addresses
                for ip_domain in ip_domains['domains']:
                    try:
                        result = tx.run("""
                            MATCH (d:Domain {fqdn: $fqdn})
                            DETACH DELETE d
                            RETURN count(d) as deleted
                        """, fqdn=ip_domain)
                        
                        deleted = result.single()['deleted']
                        removed_count += deleted
                        logging.info(f"Removed Domain node: {ip_domain}")
                        
                    except Exception as e:
                        logging.error(f"Error removing Domain {ip_domain}: {e}")
                
                # Remove Subdomain nodes that are IP addresses
                for ip_subdomain in ip_domains['subdomains']:
                    try:
                        result = tx.run("""
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            DETACH DELETE s
                            RETURN count(s) as deleted
                        """, fqdn=ip_subdomain)
                        
                        deleted = result.single()['deleted']
                        removed_count += deleted
                        logging.info(f"Removed Subdomain node: {ip_subdomain}")
                        
                    except Exception as e:
                        logging.error(f"Error removing Subdomain {ip_subdomain}: {e}")
                
                # Update base_domain properties that are IP addresses
                for ip_base_domain in invalid_base_domains:
                    try:
                        result = tx.run("""
                            MATCH (n)
                            WHERE n.base_domain = $ip_base_domain
                            SET n.base_domain = null
                            RETURN count(n) as updated
                        """, ip_base_domain=ip_base_domain)
                        
                        updated = result.single()['updated']
                        updated_count += updated
                        logging.info(f"Cleared base_domain property for IP: {ip_base_domain}")
                        
                    except Exception as e:
                        logging.error(f"Error updating base_domain {ip_base_domain}: {e}")
                
                tx.commit()
        
        return {
            'dry_run': False,
            'nodes_removed': removed_count,
            'properties_updated': updated_count,
            'ip_domains_found': total_domains,
            'ip_subdomains_found': total_subdomains,
            'ip_base_domains_found': total_base_domains
        }
    
    def validate_remaining_domains(self) -> Dict[str, Any]:
        """Validate that all remaining domains are valid."""
        invalid_domains = []
        valid_count = 0
        
        with self.driver.session() as session:
            # Check Domain nodes
            result = session.run("MATCH (d:Domain) RETURN d.fqdn as fqdn")
            for record in result:
                fqdn = record.get('fqdn', '')
                if fqdn:
                    if is_valid_domain_name(fqdn):
                        valid_count += 1
                    else:
                        invalid_domains.append(('Domain', fqdn))
            
            # Check Subdomain nodes
            result = session.run("MATCH (s:Subdomain) RETURN s.fqdn as fqdn")
            for record in result:
                fqdn = record.get('fqdn', '')
                if fqdn:
                    if is_valid_domain_name(fqdn):
                        valid_count += 1
                    else:
                        invalid_domains.append(('Subdomain', fqdn))
        
        return {
            'valid_domains': valid_count,
            'invalid_domains': invalid_domains
        }
    
    def close(self):
        """Close the Neo4j driver."""
        if self.driver:
            self.driver.close()

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Clean IP addresses from Neo4j graph")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-pass", default="test.password", help="Neo4j password")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Perform dry run (default)")
    parser.add_argument("--execute", action="store_true", help="Actually perform the cleanup")
    parser.add_argument("--validate", action="store_true", help="Validate remaining domains after cleanup")
    
    args = parser.parse_args()
    
    # Determine if this is a dry run
    dry_run = not args.execute
    
    if dry_run:
        logging.info("Running in DRY RUN mode. Use --execute to actually perform cleanup.")
    else:
        logging.warning("EXECUTING cleanup - this will modify the database!")
    
    try:
        cleaner = GraphCleaner(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_pass=args.neo4j_pass
        )
        
        # Perform cleanup
        results = cleaner.clean_ip_domains(dry_run=dry_run)
        
        logging.info("Cleanup results:")
        for key, value in results.items():
            if isinstance(value, list) and len(value) > 10:
                logging.info(f"  {key}: {len(value)} items (first 10: {value[:10]})")
            else:
                logging.info(f"  {key}: {value}")
        
        # Validate if requested
        if args.validate:
            validation_results = cleaner.validate_remaining_domains()
            logging.info("Validation results:")
            logging.info(f"  Valid domains: {validation_results['valid_domains']}")
            logging.info(f"  Invalid domains: {len(validation_results['invalid_domains'])}")
            
            if validation_results['invalid_domains']:
                logging.warning("Still found invalid domains:")
                for node_type, fqdn in validation_results['invalid_domains'][:10]:
                    logging.warning(f"  {node_type}: {fqdn}")
        
        logging.info("Graph cleanup completed successfully!")
        
    except Exception as e:
        logging.error(f"Failed to clean graph: {e}")
        return 1
    finally:
        if 'cleaner' in locals():
            cleaner.close()
    
    return 0

if __name__ == "__main__":
    exit(main())