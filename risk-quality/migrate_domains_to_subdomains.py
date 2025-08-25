#!/usr/bin/env python3
"""
migrate_domains_to_subdomains.py - Migrate specific Domain nodes to Subdomain nodes

This script migrates the 10 bancochile.cl domains that exist as both Domain and Subdomain
to only exist as Subdomain nodes, preserving all data and relationships.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
import sys
import os

try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Warning: Neo4j driver not available")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DomainToSubdomainMigrator:
    """Migrate Domain nodes to Subdomain nodes"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        # The 10 specific domains to migrate
        self.target_domains = [
            "api.bancochile.cl",
            "extranet.bancochile.cl", 
            "login.bancochile.cl",
            "mail.bancochile.cl",
            "online.bancochile.cl",
            "portal.bancochile.cl",
            "portalempresas.bancochile.cl",
            "portalpersonas.bancochile.cl",
            "servicios.bancochile.cl",
            "www.bancochile.cl"
        ]
        
    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def analyze_domain_node(self, fqdn: str) -> Dict[str, Any]:
        """Analyze a Domain node to understand its properties and relationships"""
        with self.driver.session() as session:
            # Get Domain properties
            domain_query = """
            MATCH (d:Domain {fqdn: $fqdn})
            RETURN properties(d) as props
            """
            result = session.run(domain_query, fqdn=fqdn)
            domain_record = result.single()
            domain_props = domain_record["props"] if domain_record else {}
            
            # Get Subdomain properties
            subdomain_query = """
            MATCH (s:Subdomain {fqdn: $fqdn})
            RETURN properties(s) as props
            """
            result = session.run(subdomain_query, fqdn=fqdn)
            subdomain_record = result.single()
            subdomain_props = subdomain_record["props"] if subdomain_record else {}
            
            # Get Domain relationships
            domain_rels_query = """
            MATCH (d:Domain {fqdn: $fqdn})-[r]-(other)
            WHERE NOT other:Subdomain
            RETURN type(r) as rel_type, labels(other) as other_labels, 
                   properties(other) as other_props, properties(r) as rel_props,
                   startNode(r) = d as is_outgoing
            """
            result = session.run(domain_rels_query, fqdn=fqdn)
            domain_relationships = []
            for record in result:
                domain_relationships.append({
                    "type": record["rel_type"],
                    "other_labels": record["other_labels"],
                    "other_props": record["other_props"],
                    "rel_props": record["rel_props"],
                    "is_outgoing": record["is_outgoing"]
                })
            
            # Get Subdomain relationships
            subdomain_rels_query = """
            MATCH (s:Subdomain {fqdn: $fqdn})-[r]-(other)
            WHERE NOT other:Domain
            RETURN type(r) as rel_type, labels(other) as other_labels,
                   properties(other) as other_props, properties(r) as rel_props,
                   startNode(r) = s as is_outgoing
            """
            result = session.run(subdomain_rels_query, fqdn=fqdn)
            subdomain_relationships = []
            for record in result:
                subdomain_relationships.append({
                    "type": record["rel_type"],
                    "other_labels": record["other_labels"],
                    "other_props": record["other_props"],
                    "rel_props": record["rel_props"],
                    "is_outgoing": record["is_outgoing"]
                })
            
            return {
                "fqdn": fqdn,
                "domain_properties": domain_props,
                "subdomain_properties": subdomain_props,
                "domain_relationships": domain_relationships,
                "subdomain_relationships": subdomain_relationships
            }

    def find_unique_properties(self, domain_props: Dict, subdomain_props: Dict) -> Dict[str, Any]:
        """Find properties that exist in Domain but not in Subdomain or have different values"""
        unique_props = {}
        
        for key, value in domain_props.items():
            if key == 'fqdn':  # Skip FQDN as it's the same
                continue
                
            if key not in subdomain_props:
                # Property exists only in Domain
                unique_props[key] = value
            elif subdomain_props[key] != value and subdomain_props[key] is not None:
                # Property has different values, keep Domain value if Subdomain is null or less complete
                if value is not None:
                    logger.warning(f"Property conflict for {key}: Domain={value}, Subdomain={subdomain_props[key]}")
                    # Keep the non-null value, preferring more recent timestamps if they exist
                    if isinstance(value, str) and isinstance(subdomain_props[key], str):
                        if 'at' in key.lower() or 'time' in key.lower():
                            # For timestamps, keep the more recent one
                            try:
                                domain_time = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                subdomain_time = datetime.fromisoformat(subdomain_props[key].replace('Z', '+00:00'))
                                if domain_time > subdomain_time:
                                    unique_props[key] = value
                            except:
                                unique_props[key] = value
                        else:
                            unique_props[key] = value
            elif subdomain_props[key] is None and value is not None:
                # Subdomain property is null, use Domain value
                unique_props[key] = value
        
        return unique_props

    def migrate_domain_to_subdomain(self, fqdn: str, dry_run: bool = True) -> Dict[str, Any]:
        """Migrate a specific Domain node to Subdomain node"""
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Migrating {fqdn}...")
        
        analysis = self.analyze_domain_node(fqdn)
        unique_props = self.find_unique_properties(
            analysis["domain_properties"], 
            analysis["subdomain_properties"]
        )
        
        migration_result = {
            "fqdn": fqdn,
            "properties_merged": len(unique_props),
            "relationships_migrated": len(analysis["domain_relationships"]),
            "success": False,
            "error": None
        }
        
        if dry_run:
            logger.info(f"[DRY RUN] Would migrate {len(unique_props)} unique properties")
            logger.info(f"[DRY RUN] Would migrate {len(analysis['domain_relationships'])} relationships")
            migration_result["success"] = True
            return migration_result
        
        try:
            with self.driver.session() as session:
                # Start transaction
                with session.begin_transaction() as tx:
                    
                    # 1. Merge unique properties to Subdomain
                    if unique_props:
                        logger.info(f"Merging {len(unique_props)} properties to Subdomain")
                        
                        # Build SET clause for properties
                        set_clauses = []
                        params = {"fqdn": fqdn}
                        
                        for prop, value in unique_props.items():
                            param_name = f"prop_{prop.replace('.', '_').replace('-', '_')}"
                            # Only set if Subdomain property is null or doesn't exist
                            set_clauses.append(f"s.{prop} = COALESCE(s.{prop}, ${param_name})")
                            params[param_name] = value
                        
                        if set_clauses:
                            merge_props_query = f"""
                            MATCH (s:Subdomain {{fqdn: $fqdn}})
                            SET {', '.join(set_clauses)}
                            """
                            tx.run(merge_props_query, **params)
                            logger.info(f"Merged properties: {list(unique_props.keys())}")
                    
                    # 2. Migrate relationships from Domain to Subdomain
                    if analysis["domain_relationships"]:
                        logger.info(f"Migrating {len(analysis['domain_relationships'])} relationships")
                        
                        for rel in analysis["domain_relationships"]:
                            # Check if this relationship already exists on Subdomain
                            check_existing_query = """
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            MATCH (other) WHERE properties(other) = $other_props
                            RETURN count{(s)-[:REL_TYPE]-(other)} > 0 as exists
                            """.replace("REL_TYPE", rel["type"])
                            
                            result = tx.run(check_existing_query, 
                                          fqdn=fqdn, 
                                          other_props=rel["other_props"])
                            
                            exists = result.single()["exists"] if result.single() else False
                            
                            if not exists:
                                # Create the relationship
                                if rel["is_outgoing"]:
                                    create_rel_query = f"""
                                    MATCH (s:Subdomain {{fqdn: $fqdn}})
                                    MATCH (other) WHERE properties(other) = $other_props
                                    CREATE (s)-[r:{rel["type"]}]->(other)
                                    SET r = $rel_props
                                    """
                                else:
                                    create_rel_query = f"""
                                    MATCH (s:Subdomain {{fqdn: $fqdn}})
                                    MATCH (other) WHERE properties(other) = $other_props
                                    CREATE (other)-[r:{rel["type"]}]->(s)
                                    SET r = $rel_props
                                    """
                                
                                tx.run(create_rel_query,
                                      fqdn=fqdn,
                                      other_props=rel["other_props"],
                                      rel_props=rel["rel_props"])
                                
                                logger.info(f"Created relationship: {rel['type']} with {rel['other_labels']}")
                    
                    # 3. Delete the Domain node and its relationships
                    delete_domain_query = """
                    MATCH (d:Domain {fqdn: $fqdn})
                    DETACH DELETE d
                    """
                    tx.run(delete_domain_query, fqdn=fqdn)
                    logger.info(f"Deleted Domain node for {fqdn}")
                    
                    # Commit transaction
                    tx.commit()
                    logger.info(f"Successfully migrated {fqdn}")
                    migration_result["success"] = True
                    
        except Exception as e:
            error_msg = f"Error migrating {fqdn}: {str(e)}"
            logger.error(error_msg)
            migration_result["error"] = error_msg
            
        return migration_result

    def migrate_all_domains(self, dry_run: bool = True) -> Dict[str, Any]:
        """Migrate all target domains"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "dry_run": dry_run,
            "total_domains": len(self.target_domains),
            "successful_migrations": [],
            "failed_migrations": [],
            "migration_details": []
        }
        
        logger.info(f"{'DRY RUN: ' if dry_run else ''}Starting migration of {len(self.target_domains)} domains")
        
        for fqdn in self.target_domains:
            try:
                migration_result = self.migrate_domain_to_subdomain(fqdn, dry_run)
                results["migration_details"].append(migration_result)
                
                if migration_result["success"]:
                    results["successful_migrations"].append(fqdn)
                    logger.info(f"{'[DRY RUN] ' if dry_run else ''}✅ {fqdn} migrated successfully")
                else:
                    results["failed_migrations"].append({
                        "fqdn": fqdn,
                        "error": migration_result["error"]
                    })
                    logger.error(f"❌ {fqdn} migration failed: {migration_result['error']}")
                    
            except Exception as e:
                error_msg = f"Unexpected error migrating {fqdn}: {str(e)}"
                logger.error(error_msg)
                results["failed_migrations"].append({
                    "fqdn": fqdn,
                    "error": error_msg
                })
        
        # Summary
        success_count = len(results["successful_migrations"])
        failed_count = len(results["failed_migrations"])
        
        logger.info(f"{'DRY RUN ' if dry_run else ''}MIGRATION SUMMARY:")
        logger.info(f"  ✅ Successful: {success_count}/{len(self.target_domains)}")
        logger.info(f"  ❌ Failed: {failed_count}/{len(self.target_domains)}")
        
        if failed_count > 0:
            logger.info("Failed migrations:")
            for failure in results["failed_migrations"]:
                logger.info(f"  - {failure['fqdn']}: {failure['error']}")
        
        return results

    def verify_migration(self) -> Dict[str, Any]:
        """Verify that migration was successful"""
        logger.info("Verifying migration results...")
        
        verification = {
            "remaining_domain_duplicates": 0,
            "confirmed_subdomains": [],
            "missing_subdomains": [],
            "verification_success": True
        }
        
        with self.driver.session() as session:
            # Check for remaining duplicates
            duplicates_query = """
            MATCH (d:Domain), (s:Subdomain)
            WHERE d.fqdn = s.fqdn AND d.fqdn IN $target_domains
            RETURN count(*) as remaining_duplicates
            """
            result = session.run(duplicates_query, target_domains=self.target_domains)
            verification["remaining_domain_duplicates"] = result.single()["remaining_duplicates"]
            
            # Check that all target domains exist as Subdomains
            for fqdn in self.target_domains:
                subdomain_exists_query = """
                MATCH (s:Subdomain {fqdn: $fqdn})
                RETURN count(s) > 0 as exists
                """
                result = session.run(subdomain_exists_query, fqdn=fqdn)
                exists = result.single()["exists"]
                
                if exists:
                    verification["confirmed_subdomains"].append(fqdn)
                else:
                    verification["missing_subdomains"].append(fqdn)
                    verification["verification_success"] = False
        
        logger.info(f"Verification results:")
        logger.info(f"  Remaining Domain duplicates: {verification['remaining_domain_duplicates']}")
        logger.info(f"  Confirmed Subdomains: {len(verification['confirmed_subdomains'])}")
        logger.info(f"  Missing Subdomains: {len(verification['missing_subdomains'])}")
        
        if verification["verification_success"]:
            logger.info("✅ Migration verification successful!")
        else:
            logger.error("❌ Migration verification failed!")
            
        return verification

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate Domain nodes to Subdomain nodes')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')  
    parser.add_argument('--neo4j-password', default='neo4j', help='Neo4j password')
    parser.add_argument('--execute', action='store_true', help='Execute migration (default: dry run)')
    parser.add_argument('--verify', action='store_true', help='Verify migration results')
    parser.add_argument('--report', '-r', help='Save migration report to JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        migrator = DomainToSubdomainMigrator(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        
        if args.verify:
            verification = migrator.verify_migration()
            if args.report:
                with open(args.report, 'w') as f:
                    json.dump(verification, f, indent=2)
                logger.info(f"Verification report saved to {args.report}")
        else:
            # Run migration
            dry_run = not args.execute
            results = migrator.migrate_all_domains(dry_run=dry_run)
            
            if args.report:
                with open(args.report, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"Migration report saved to {args.report}")
            
            # If not dry run and successful, verify results
            if args.execute and len(results["failed_migrations"]) == 0:
                logger.info("Running verification...")
                verification = migrator.verify_migration()
        
        migrator.close()
        return 0
        
    except Exception as e:
        logger.error(f"Failed to run migration: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())