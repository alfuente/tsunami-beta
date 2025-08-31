#!/usr/bin/env python3
"""
Export Base Domains to TXT Script

This script exports all base domains from Neo4j to a simple txt file,
one domain per line, for easy processing with other scripts.

Usage:
    python3 export_base_domains_txt.py [--output base_domains.txt]
"""

import argparse
import logging
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Neo4j connection configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

def export_base_domains_txt(output_file="base_domains.txt"):
    """Export all base domains to txt file, one domain per line"""
    
    logger.info(f"Starting base domains export to {output_file}")
    
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    try:
        with driver.session() as session:
            # Query to get all base domains from Domain nodes
            query = """
            MATCH (d:Domain)
            RETURN DISTINCT d.fqdn as base_domain
            ORDER BY d.fqdn ASC
            """
            
            result = session.run(query)
            domains = [record["base_domain"] for record in result if record["base_domain"]]
            
            logger.info(f"Found {len(domains)} base domains to export")
            
            # Write to txt file
            with open(output_file, 'w', encoding='utf-8') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            
            logger.info(f"Successfully exported {len(domains)} base domains to {output_file}")
            logger.info(f"Each domain is on a separate line for easy processing")
            
            return len(domains)
            
    except Exception as e:
        logger.error(f"Error exporting base domains: {e}")
        return 0
    finally:
        driver.close()

def main():
    parser = argparse.ArgumentParser(description='Export base domains from Neo4j to TXT')
    parser.add_argument('--output', '-o', default='base_domains.txt',
                        help='Output TXT file (default: base_domains.txt)')
    
    args = parser.parse_args()
    
    count = export_base_domains_txt(args.output)
    
    if count > 0:
        print(f"\n✅ Successfully exported {count} base domains to {args.output}")
        print(f"📄 Each domain is on a separate line for easy processing")
    else:
        print(f"\n❌ Failed to export domains")

if __name__ == "__main__":
    main()