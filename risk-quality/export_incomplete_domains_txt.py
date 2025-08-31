#!/usr/bin/env python3
"""
Export Incomplete Domains to TXT Script

This script exports base domains from Neo4j that don't have subdomains or providers
to a simple txt file, one domain per line, for further processing and completion.

Usage:
    python3 export_incomplete_domains_txt.py [--output incomplete_domains.txt]
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

def export_incomplete_domains_txt(output_file="incomplete_domains.txt"):
    """Export base domains that don't have subdomains or providers to txt file"""
    
    logger.info(f"Starting incomplete domains export to {output_file}")
    
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    try:
        with driver.session() as session:
            # Query to get base domains that don't have subdomains or providers
            query = """
            MATCH (d:Domain)
            WHERE d.fqdn IS NOT NULL 
            AND NOT EXISTS {
                MATCH (s:Subdomain)
                WHERE s.base_domain = d.fqdn
            }
            AND NOT EXISTS {
                MATCH (d)-[:HAS_PROVIDER]->(:Provider)
            }
            AND NOT EXISTS {
                MATCH (d)-[:USES_SERVICE]->(:Service)
            }
            RETURN DISTINCT d.fqdn as domain
            ORDER BY d.fqdn ASC
            """
            
            result = session.run(query)
            domains = [record["domain"] for record in result if record["domain"]]
            
            logger.info(f"Found {len(domains)} incomplete domains (without subdomains or providers)")
            
            # Write to txt file
            with open(output_file, 'w', encoding='utf-8') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            
            logger.info(f"Successfully exported {len(domains)} incomplete domains to {output_file}")
            logger.info(f"These domains need subdomain discovery and provider analysis")
            
            return len(domains)
            
    except Exception as e:
        logger.error(f"Error exporting incomplete domains: {e}")
        return 0
    finally:
        driver.close()

def get_completion_stats():
    """Get statistics about domain completion status"""
    
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    try:
        with driver.session() as session:
            # Total domains
            total_query = "MATCH (d:Domain) RETURN count(d) as total"
            total_result = session.run(total_query)
            total_domains = total_result.single()["total"]
            
            # Domains with subdomains
            with_subdomains_query = """
            MATCH (d:Domain)
            WHERE EXISTS {
                MATCH (s:Subdomain)
                WHERE s.base_domain = d.fqdn
            }
            RETURN count(d) as with_subdomains
            """
            with_subdomains_result = session.run(with_subdomains_query)
            with_subdomains = with_subdomains_result.single()["with_subdomains"]
            
            # Domains with providers
            with_providers_query = """
            MATCH (d:Domain)
            WHERE EXISTS {
                MATCH (d)-[:HAS_PROVIDER]->(:Provider)
            }
            RETURN count(d) as with_providers
            """
            with_providers_result = session.run(with_providers_query)
            with_providers = with_providers_result.single()["with_providers"]
            
            # Domains with services
            with_services_query = """
            MATCH (d:Domain)
            WHERE EXISTS {
                MATCH (d)-[:USES_SERVICE]->(:Service)
            }
            RETURN count(d) as with_services
            """
            with_services_result = session.run(with_services_query)
            with_services = with_services_result.single()["with_services"]
            
            # Complete domains (have both subdomains and providers/services)
            complete_query = """
            MATCH (d:Domain)
            WHERE EXISTS {
                MATCH (s:Subdomain)
                WHERE s.base_domain = d.fqdn
            }
            AND (
                EXISTS {
                    MATCH (d)-[:HAS_PROVIDER]->(:Provider)
                }
                OR EXISTS {
                    MATCH (d)-[:USES_SERVICE]->(:Service)
                }
            )
            RETURN count(d) as complete
            """
            complete_result = session.run(complete_query)
            complete_domains = complete_result.single()["complete"]
            
            return {
                "total": total_domains,
                "with_subdomains": with_subdomains,
                "with_providers": with_providers,
                "with_services": with_services,
                "complete": complete_domains,
                "incomplete": total_domains - complete_domains
            }
            
    except Exception as e:
        logger.error(f"Error getting completion stats: {e}")
        return {}
    finally:
        driver.close()

def main():
    parser = argparse.ArgumentParser(description='Export incomplete domains from Neo4j to TXT')
    parser.add_argument('--output', '-o', default='incomplete_domains.txt',
                        help='Output TXT file (default: incomplete_domains.txt)')
    parser.add_argument('--stats', '-s', action='store_true',
                        help='Show completion statistics only')
    
    args = parser.parse_args()
    
    if args.stats:
        print("\n📊 Domain Completion Statistics:")
        print("="*50)
        stats = get_completion_stats()
        if stats:
            print(f"📁 Total domains: {stats['total']}")
            print(f"🌐 With subdomains: {stats['with_subdomains']}")
            print(f"🔧 With providers: {stats['with_providers']}")
            print(f"⚙️ With services: {stats['with_services']}")
            print(f"✅ Complete domains: {stats['complete']}")
            print(f"⚠️ Incomplete domains: {stats['incomplete']}")
            
            if stats['total'] > 0:
                completion_rate = (stats['complete'] / stats['total']) * 100
                print(f"📈 Completion rate: {completion_rate:.1f}%")
        return
    
    # Show stats first
    stats = get_completion_stats()
    if stats:
        print(f"\n📊 Found {stats['incomplete']} incomplete domains out of {stats['total']} total")
    
    count = export_incomplete_domains_txt(args.output)
    
    if count > 0:
        print(f"\n✅ Successfully exported {count} incomplete domains to {args.output}")
        print(f"📄 Each domain is on a separate line for easy processing")
        print(f"💡 These domains need subdomain discovery and provider analysis")
        print(f"💡 Use load_domains_via_api.py to process them")
    else:
        print(f"\n❌ No incomplete domains found or export failed")

if __name__ == "__main__":
    main()