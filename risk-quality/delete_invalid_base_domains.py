#!/usr/bin/env python3
"""
Delete Invalid Base Domains Script

This script reads a list of invalid base domains (subdomains incorrectly stored as Domain nodes)
and deletes them from the Neo4j graph along with all their associated relationships.

IMPORTANT: This script performs destructive operations. Always backup your database first!

Usage:
    python3 delete_invalid_base_domains.py --input invalid_base_domains.txt [--dry-run] [--batch-size 100]
"""

import argparse
import logging
import time
from neo4j import GraphDatabase
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Neo4j connection configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

class InvalidDomainDeleter:
    def __init__(self, dry_run=False):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.dry_run = dry_run
        logger.info(f"Connected to Neo4j at {NEO4J_URI}")
        if dry_run:
            logger.info("🧪 DRY RUN MODE: No actual deletions will be performed")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def read_invalid_domains(self, input_file: str) -> List[str]:
        """Read invalid domains from txt file"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            logger.info(f"Read {len(domains)} invalid domains from {input_file}")
            return domains
        except FileNotFoundError:
            logger.error(f"Input file {input_file} not found")
            return []
        except Exception as e:
            logger.error(f"Error reading invalid domains from {input_file}: {e}")
            return []
    
    def get_domain_relationships_count(self, domain: str) -> dict:
        """Get count of relationships for a domain before deletion"""
        query = """
        MATCH (d:Domain {fqdn: $domain})
        OPTIONAL MATCH (d)-[r1]-()
        OPTIONAL MATCH ()-[r2]-(d)
        WITH d, collect(DISTINCT r1) + collect(DISTINCT r2) as all_rels
        RETURN 
            id(d) as node_id,
            size(all_rels) as relationship_count
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, domain=domain)
                record = result.single()
                if record:
                    return {
                        "node_id": record["node_id"],
                        "relationship_count": record["relationship_count"]
                    }
                else:
                    return {"node_id": None, "relationship_count": 0}
        except Exception as e:
            logger.error(f"Error getting relationships count for {domain}: {e}")
            return {"node_id": None, "relationship_count": 0}
    
    def delete_domain_and_relationships(self, domain: str) -> dict:
        """Delete a domain node and all its relationships"""
        if self.dry_run:
            # In dry run, just count what would be deleted
            rel_info = self.get_domain_relationships_count(domain)
            return {
                "domain": domain,
                "status": "dry_run",
                "node_id": rel_info["node_id"],
                "relationships_deleted": rel_info["relationship_count"],
                "node_deleted": rel_info["node_id"] is not None
            }
        
        # Real deletion query
        query = """
        MATCH (d:Domain {fqdn: $domain})
        OPTIONAL MATCH (d)-[r]-()
        WITH d, count(r) as relationship_count, id(d) as node_id
        DETACH DELETE d
        RETURN node_id, relationship_count
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, domain=domain)
                record = result.single()
                
                if record:
                    return {
                        "domain": domain,
                        "status": "deleted",
                        "node_id": record["node_id"],
                        "relationships_deleted": record["relationship_count"],
                        "node_deleted": True
                    }
                else:
                    return {
                        "domain": domain,
                        "status": "not_found",
                        "node_id": None,
                        "relationships_deleted": 0,
                        "node_deleted": False
                    }
                    
        except Exception as e:
            logger.error(f"Error deleting domain {domain}: {e}")
            return {
                "domain": domain,
                "status": "error",
                "error": str(e),
                "node_id": None,
                "relationships_deleted": 0,
                "node_deleted": False
            }
    
    def delete_domains_batch(self, domains: List[str], batch_size: int = 100) -> List[dict]:
        """Delete domains in batches"""
        results = []
        total_domains = len(domains)
        
        logger.info(f"Starting deletion of {total_domains} domains in batches of {batch_size}")
        
        for i in range(0, total_domains, batch_size):
            batch = domains[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_domains + batch_size - 1) // batch_size
            
            logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} domains)")
            
            for domain in batch:
                result = self.delete_domain_and_relationships(domain)
                results.append(result)
                
                if result["status"] == "deleted":
                    logger.info(f"✅ Deleted {domain} (node_id: {result['node_id']}, {result['relationships_deleted']} relationships)")
                elif result["status"] == "dry_run":
                    logger.info(f"🧪 [DRY RUN] Would delete {domain} (node_id: {result['node_id']}, {result['relationships_deleted']} relationships)")
                elif result["status"] == "not_found":
                    logger.warning(f"⚠️ Domain not found: {domain}")
                elif result["status"] == "error":
                    logger.error(f"❌ Error with {domain}: {result.get('error', 'Unknown error')}")
            
            # Small delay between batches
            if i + batch_size < total_domains:
                time.sleep(0.1)
        
        return results
    
    def print_deletion_summary(self, results: List[dict]):
        """Print summary of deletion results"""
        total = len(results)
        deleted = len([r for r in results if r["status"] == "deleted"])
        dry_run = len([r for r in results if r["status"] == "dry_run"])
        not_found = len([r for r in results if r["status"] == "not_found"])
        errors = len([r for r in results if r["status"] == "error"])
        
        total_relationships_deleted = sum([r.get("relationships_deleted", 0) for r in results])
        
        print("\n" + "="*80)
        print("DOMAIN DELETION SUMMARY")
        print("="*80)
        print(f"📊 Total domains processed: {total}")
        
        if dry_run > 0:
            print(f"🧪 Dry run results: {dry_run}")
            print(f"📊 Would delete {total_relationships_deleted} relationships")
        else:
            print(f"✅ Successfully deleted: {deleted}")
            print(f"📊 Total relationships deleted: {total_relationships_deleted}")
        
        print(f"⚠️ Not found: {not_found}")
        print(f"❌ Errors: {errors}")
        
        if total > 0:
            success_rate = (deleted + dry_run) / total * 100
            print(f"📈 Success rate: {success_rate:.1f}%")
        
        # Show errors if any
        if errors > 0:
            print(f"\n❌ Domains with errors:")
            for result in results:
                if result["status"] == "error":
                    print(f"   • {result['domain']}: {result.get('error', 'Unknown error')}")
        
        # Show not found if any
        if not_found > 0 and not_found <= 10:
            print(f"\n⚠️ Domains not found:")
            for result in results:
                if result["status"] == "not_found":
                    print(f"   • {result['domain']}")
        elif not_found > 10:
            print(f"\n⚠️ {not_found} domains not found (too many to list)")
    
    def get_graph_stats_before_after(self):
        """Get graph statistics"""
        queries = {
            "total_domains": "MATCH (d:Domain) RETURN count(d) as count",
            "total_subdomains": "MATCH (s:Subdomain) RETURN count(s) as count",
            "total_relationships": "MATCH ()-[r]-() RETURN count(r) as count"
        }
        
        stats = {}
        try:
            with self.driver.session() as session:
                for stat_name, query in queries.items():
                    result = session.run(query)
                    record = result.single()
                    stats[stat_name] = record["count"] if record else 0
        except Exception as e:
            logger.error(f"Error getting graph stats: {e}")
            stats = {"error": str(e)}
        
        return stats

def main():
    parser = argparse.ArgumentParser(description='Delete invalid base domains from Neo4j graph')
    parser.add_argument('--input', '-i', required=True,
                        help='Input TXT file with invalid domains to delete')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='Dry run mode - show what would be deleted without actually deleting')
    parser.add_argument('--batch-size', '-b', type=int, default=100,
                        help='Batch size for deletions (default: 100)')
    parser.add_argument('--confirm', '-c', action='store_true',
                        help='Skip confirmation prompt (use with caution!)')
    
    args = parser.parse_args()
    
    # Check input file exists
    from pathlib import Path
    if not Path(args.input).exists():
        print(f"❌ Input file {args.input} not found")
        print(f"💡 Generate the file first with: python3 identify_invalid_base_domains.py")
        return
    
    deleter = InvalidDomainDeleter(dry_run=args.dry_run)
    
    try:
        # Read invalid domains
        domains = deleter.read_invalid_domains(args.input)
        
        if not domains:
            print("❌ No domains found in input file")
            return
        
        print(f"📄 Loaded {len(domains)} invalid domains from {args.input}")
        
        # Get initial graph stats
        print("\n📊 Getting initial graph statistics...")
        stats_before = deleter.get_graph_stats_before_after()
        if "error" not in stats_before:
            print(f"   • Domain nodes: {stats_before['total_domains']}")
            print(f"   • Subdomain nodes: {stats_before['total_subdomains']}")
            print(f"   • Total relationships: {stats_before['total_relationships']}")
        
        # Show first few domains to be deleted
        print(f"\n🗑️ Domains to be {'analyzed (dry run)' if args.dry_run else 'deleted'}:")
        for domain in domains[:10]:
            print(f"   • {domain}")
        if len(domains) > 10:
            print(f"   ... and {len(domains) - 10} more")
        
        # Confirmation
        if not args.dry_run and not args.confirm:
            print(f"\n🚨 WARNING: This will permanently delete {len(domains)} Domain nodes and all their relationships!")
            print("   This operation cannot be undone. Make sure you have a database backup!")
            response = input("\nProceed with deletion? (type 'DELETE' to confirm): ")
            if response != "DELETE":
                print("❌ Operation cancelled")
                return
        
        # Perform deletions
        print(f"\n🚀 Starting {'dry run analysis' if args.dry_run else 'deletion'} of {len(domains)} domains...")
        start_time = time.time()
        
        results = deleter.delete_domains_batch(domains, args.batch_size)
        
        end_time = time.time()
        
        # Print summary
        deleter.print_deletion_summary(results)
        
        # Get final graph stats
        if not args.dry_run:
            print("\n📊 Getting final graph statistics...")
            stats_after = deleter.get_graph_stats_before_after()
            if "error" not in stats_after and "error" not in stats_before:
                domains_deleted = stats_before['total_domains'] - stats_after['total_domains']
                relationships_deleted = stats_before['total_relationships'] - stats_after['total_relationships']
                print(f"   • Domain nodes: {stats_after['total_domains']} (deleted: {domains_deleted})")
                print(f"   • Subdomain nodes: {stats_after['total_subdomains']}")
                print(f"   • Total relationships: {stats_after['total_relationships']} (deleted: {relationships_deleted})")
        
        print(f"\n⏱️ Operation completed in {end_time - start_time:.1f} seconds")
        
        if args.dry_run:
            print(f"💡 Run without --dry-run to perform actual deletions")
        else:
            print(f"✅ Graph cleanup completed!")
    
    except Exception as e:
        logger.error(f"Operation failed: {e}")
    
    finally:
        deleter.close()

if __name__ == "__main__":
    main()