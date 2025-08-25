#!/usr/bin/env python3
"""
cleanup_duplicate_domains.py - Clean up duplicate Domain nodes that should be Subdomains

This script identifies Domain nodes that are actually subdomains of existing domains
and either removes them (if they have no unique data) or merges their data into
the corresponding Subdomain nodes.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DuplicateNode:
    domain_fqdn: str
    subdomain_fqdn: str
    domain_properties: Dict[str, Any]
    subdomain_properties: Dict[str, Any]
    has_domain_relationships: bool
    has_subdomain_relationships: bool
    action: str  # 'delete', 'merge', 'keep'

class DomainCleanup:
    """Clean up duplicate Domain nodes that should be Subdomains"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.duplicates: List[DuplicateNode] = []
        
    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def find_duplicate_domains(self) -> List[DuplicateNode]:
        """Find Domain nodes that exist as Subdomain nodes"""
        duplicates = []
        
        with self.driver.session() as session:
            # Find Domain nodes that also exist as Subdomain nodes
            query = """
            MATCH (d:Domain), (s:Subdomain)
            WHERE d.fqdn = s.fqdn
            AND d.fqdn CONTAINS '.'  // Only consider subdomains, not root domains
            RETURN d.fqdn as fqdn, 
                   properties(d) as domain_props,
                   properties(s) as subdomain_props
            ORDER BY d.fqdn
            """
            result = session.run(query)
            
            for record in result:
                fqdn = record["fqdn"]
                domain_props = record["domain_props"]
                subdomain_props = record["subdomain_props"]
                
                # Check if Domain node has relationships
                has_domain_rels = self._check_domain_relationships(session, fqdn)
                has_subdomain_rels = self._check_subdomain_relationships(session, fqdn)
                
                # Determine action
                action = self._determine_action(domain_props, subdomain_props, has_domain_rels, has_subdomain_rels)
                
                duplicate = DuplicateNode(
                    domain_fqdn=fqdn,
                    subdomain_fqdn=fqdn,
                    domain_properties=domain_props,
                    subdomain_properties=subdomain_props,
                    has_domain_relationships=has_domain_rels,
                    has_subdomain_relationships=has_subdomain_rels,
                    action=action
                )
                
                duplicates.append(duplicate)
                
        return duplicates
    
    def _check_domain_relationships(self, session, fqdn: str) -> bool:
        """Check if Domain node has any relationships"""
        query = """
        MATCH (d:Domain {fqdn: $fqdn})--(other)
        WHERE NOT other:Domain AND NOT other:Subdomain
        RETURN count(other) > 0 as has_relationships
        """
        result = session.run(query, fqdn=fqdn)
        record = result.single()
        return record["has_relationships"] if record else False
    
    def _check_subdomain_relationships(self, session, fqdn: str) -> bool:
        """Check if Subdomain node has any relationships"""
        query = """
        MATCH (s:Subdomain {fqdn: $fqdn})--(other)
        WHERE NOT other:Domain AND NOT other:Subdomain
        RETURN count(other) > 0 as has_relationships
        """
        result = session.run(query, fqdn=fqdn)
        record = result.single()
        return record["has_relationships"] if record else False
    
    def _determine_action(self, domain_props: Dict, subdomain_props: Dict, 
                         has_domain_rels: bool, has_subdomain_rels: bool) -> str:
        """Determine what action to take with the duplicate"""
        
        # If Domain has unique relationships, keep both (manual review needed)
        if has_domain_rels and has_subdomain_rels:
            return "keep_both_manual_review"
        
        # If only Subdomain has relationships and more complete data, delete Domain
        if has_subdomain_rels and not has_domain_rels:
            subdomain_data_count = sum(1 for v in subdomain_props.values() if v is not None)
            domain_data_count = sum(1 for v in domain_props.values() if v is not None)
            
            if subdomain_data_count >= domain_data_count:
                return "delete_domain"
        
        # If Domain has more complete data, merge to Subdomain
        if has_domain_rels and not has_subdomain_rels:
            return "merge_to_subdomain"
        
        # If neither has relationships, keep the one with more data
        subdomain_data_count = sum(1 for v in subdomain_props.values() if v is not None)
        domain_data_count = sum(1 for v in domain_props.values() if v is not None)
        
        if subdomain_data_count > domain_data_count:
            return "delete_domain"
        elif domain_data_count > subdomain_data_count:
            return "merge_to_subdomain"
        else:
            return "delete_domain"  # Default: keep Subdomain
    
    def generate_cleanup_report(self) -> Dict[str, Any]:
        """Generate a cleanup report"""
        self.duplicates = self.find_duplicate_domains()
        
        actions = {}
        for duplicate in self.duplicates:
            action = duplicate.action
            if action not in actions:
                actions[action] = []
            actions[action].append(duplicate.domain_fqdn)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_duplicates": len(self.duplicates),
            "actions_summary": {action: len(fqdns) for action, fqdns in actions.items()},
            "actions_detail": actions,
            "duplicates": [
                {
                    "fqdn": dup.domain_fqdn,
                    "action": dup.action,
                    "domain_properties_count": len([v for v in dup.domain_properties.values() if v is not None]),
                    "subdomain_properties_count": len([v for v in dup.subdomain_properties.values() if v is not None]),
                    "has_domain_relationships": dup.has_domain_relationships,
                    "has_subdomain_relationships": dup.has_subdomain_relationships
                }
                for dup in self.duplicates
            ]
        }
        
        return report
    
    def execute_cleanup(self, dry_run: bool = True) -> Dict[str, Any]:
        """Execute the cleanup operations"""
        if not self.duplicates:
            self.duplicates = self.find_duplicate_domains()
        
        results = {
            "deleted_domains": [],
            "merged_to_subdomains": [],
            "kept_for_manual_review": [],
            "errors": []
        }
        
        with self.driver.session() as session:
            for duplicate in self.duplicates:
                try:
                    if duplicate.action == "delete_domain":
                        if not dry_run:
                            self._delete_domain_node(session, duplicate.domain_fqdn)
                        results["deleted_domains"].append(duplicate.domain_fqdn)
                        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Deleted Domain: {duplicate.domain_fqdn}")
                    
                    elif duplicate.action == "merge_to_subdomain":
                        if not dry_run:
                            self._merge_domain_to_subdomain(session, duplicate)
                        results["merged_to_subdomains"].append(duplicate.domain_fqdn)
                        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Merged Domain to Subdomain: {duplicate.domain_fqdn}")
                    
                    elif duplicate.action == "keep_both_manual_review":
                        results["kept_for_manual_review"].append(duplicate.domain_fqdn)
                        logger.warning(f"Manual review needed: {duplicate.domain_fqdn}")
                
                except Exception as e:
                    error_msg = f"Error processing {duplicate.domain_fqdn}: {str(e)}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)
        
        return results
    
    def _delete_domain_node(self, session, fqdn: str):
        """Delete a Domain node and all its relationships"""
        query = """
        MATCH (d:Domain {fqdn: $fqdn})
        DETACH DELETE d
        """
        session.run(query, fqdn=fqdn)
    
    def _merge_domain_to_subdomain(self, session, duplicate: DuplicateNode):
        """Merge Domain node properties and relationships to Subdomain node"""
        # First, copy any unique properties from Domain to Subdomain
        domain_props = duplicate.domain_properties
        
        # Remove system properties that shouldn't be merged
        system_props = ['fqdn']
        clean_props = {k: v for k, v in domain_props.items() if k not in system_props and v is not None}
        
        if clean_props:
            # Build SET clause for properties that don't exist in Subdomain
            set_clauses = []
            params = {"fqdn": duplicate.domain_fqdn}
            
            for prop, value in clean_props.items():
                param_name = f"prop_{prop}"
                set_clauses.append(f"s.{prop} = COALESCE(s.{prop}, ${param_name})")
                params[param_name] = value
            
            if set_clauses:
                query = f"""
                MATCH (s:Subdomain {{fqdn: $fqdn}})
                SET {', '.join(set_clauses)}
                """
                session.run(query, **params)
        
        # Move relationships from Domain to Subdomain (if any)
        move_relationships_query = """
        MATCH (d:Domain {fqdn: $fqdn})-[r]-(other)
        WHERE NOT other:Domain AND NOT other:Subdomain
        MATCH (s:Subdomain {fqdn: $fqdn})
        WHERE NOT (s)-[type(r)]-(other)
        CREATE (s)-[new_r:type(r)]->(other)
        SET new_r = properties(r)
        DELETE r
        """
        session.run(move_relationships_query, fqdn=duplicate.domain_fqdn)
        
        # Finally delete the Domain node
        self._delete_domain_node(session, duplicate.domain_fqdn)
    
    def generate_cleanup_script(self, output_file: str):
        """Generate a Cypher script for cleanup operations"""
        if not self.duplicates:
            self.duplicates = self.find_duplicate_domains()
        
        script_lines = [
            "// Tsunami Beta - Domain Cleanup Script",
            f"// Generated on {datetime.now().isoformat()}",
            "// This script cleans up duplicate Domain nodes that should be Subdomains",
            "",
            "// IMPORTANT: Review this script before execution!",
            "",
        ]
        
        # Group by action
        delete_domains = [d for d in self.duplicates if d.action == "delete_domain"]
        merge_domains = [d for d in self.duplicates if d.action == "merge_to_subdomain"]
        manual_review = [d for d in self.duplicates if d.action == "keep_both_manual_review"]
        
        if delete_domains:
            script_lines.extend([
                "// === DELETE DUPLICATE DOMAIN NODES ===",
                "// These Domain nodes have less complete data than their Subdomain counterparts",
                ""
            ])
            
            for dup in delete_domains:
                script_lines.append(f"// Delete Domain: {dup.domain_fqdn}")
                script_lines.append(f"MATCH (d:Domain {{fqdn: '{dup.domain_fqdn}'}}) DETACH DELETE d;")
                script_lines.append("")
        
        if merge_domains:
            script_lines.extend([
                "// === MERGE DOMAIN NODES TO SUBDOMAINS ===",
                "// These Domain nodes have data that should be preserved in Subdomain nodes",
                ""
            ])
            
            for dup in merge_domains:
                script_lines.append(f"// Merge Domain to Subdomain: {dup.domain_fqdn}")
                script_lines.append(f"// TODO: Manual merge required for {dup.domain_fqdn}")
                script_lines.append("")
        
        if manual_review:
            script_lines.extend([
                "// === MANUAL REVIEW REQUIRED ===",
                "// These nodes have complex relationships and need manual review",
                ""
            ])
            
            for dup in manual_review:
                script_lines.append(f"// Manual review needed: {dup.domain_fqdn}")
        
        script_lines.extend([
            "",
            "// === VERIFICATION QUERIES ===",
            "// Run these after cleanup to verify results",
            "",
            "// Check remaining duplicates",
            "MATCH (d:Domain), (s:Subdomain) WHERE d.fqdn = s.fqdn RETURN count(*) as remaining_duplicates;",
            "",
            "// Check orphaned relationships",
            "MATCH (n) WHERE NOT EXISTS{(n)--(:Domain|:Subdomain)} AND NOT n:Domain AND NOT n:Subdomain RETURN labels(n), count(*);",
        ])
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(script_lines))
        
        logger.info(f"Cleanup script generated: {output_file}")

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Clean up duplicate Domain/Subdomain nodes')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='neo4j', help='Neo4j password')
    parser.add_argument('--report', '-r', help='Generate cleanup report (JSON file)')
    parser.add_argument('--script', '-s', help='Generate cleanup script (Cypher file)')
    parser.add_argument('--execute', action='store_true', help='Execute cleanup (default: dry run)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        cleanup = DomainCleanup(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        
        # Generate report
        if args.report:
            report = cleanup.generate_cleanup_report()
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Cleanup report saved to {args.report}")
            print(f"\nCLEANUP SUMMARY:")
            print(f"Total duplicates found: {report['total_duplicates']}")
            for action, count in report['actions_summary'].items():
                print(f"  {action}: {count}")
        
        # Generate script
        if args.script:
            cleanup.generate_cleanup_script(args.script)
        
        # Execute cleanup
        if args.execute or args.report or args.script:
            dry_run = not args.execute
            results = cleanup.execute_cleanup(dry_run=dry_run)
            
            print(f"\n{'DRY RUN ' if dry_run else ''}CLEANUP RESULTS:")
            print(f"  Domains deleted: {len(results['deleted_domains'])}")
            print(f"  Domains merged: {len(results['merged_to_subdomains'])}")
            print(f"  Manual review needed: {len(results['kept_for_manual_review'])}")
            print(f"  Errors: {len(results['errors'])}")
            
            if results['errors']:
                print("\nERRORS:")
                for error in results['errors']:
                    print(f"  - {error}")
        
        cleanup.close()
        return 0
        
    except Exception as e:
        logger.error(f"Failed to run cleanup: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())