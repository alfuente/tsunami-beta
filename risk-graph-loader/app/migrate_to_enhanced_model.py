#!/usr/bin/env python3
"""
migrate_to_enhanced_model.py - Migration script to update existing graph to new model

This script migrates existing Domain nodes to the new enhanced model with:
1. Proper TLD/Domain/Subdomain distinction
2. Timestamp tracking for analysis and risk scoring
3. Updated relationships and properties
"""

import argparse
from datetime import datetime
from neo4j import GraphDatabase
import tldextract

# TLD extractor instance
tld_extractor = tldextract.TLDExtract()

class GraphMigrator:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.current_time = datetime.now().isoformat()
    
    def setup_new_constraints(self):
        """Setup constraints for the new model."""
        print("Setting up new constraints...")
        
        with self.drv.session() as s:
            # TLD constraints
            s.run("CREATE CONSTRAINT tld_name IF NOT EXISTS FOR (t:TLD) REQUIRE t.name IS UNIQUE")
            
            # Enhanced domain constraints
            s.run("CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE")
            
            # Subdomain constraints
            s.run("CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE")
            
            print("✓ Constraints created")
    
    def migrate_existing_domains(self):
        """Migrate existing Domain nodes to new model."""
        print("Migrating existing Domain nodes...")
        
        with self.drv.session() as s:
            # Get all existing Domain nodes
            result = s.run("MATCH (d:Domain) RETURN d.fqdn as fqdn, d.tld as old_tld, d")
            
            domains_to_migrate = []
            for record in result:
                fqdn = record['fqdn']
                if fqdn:
                    domains_to_migrate.append(fqdn)
            
            print(f"Found {len(domains_to_migrate)} domains to migrate")
            
            # Process each domain
            for i, fqdn in enumerate(domains_to_migrate):
                if i % 100 == 0:
                    print(f"Processing domain {i+1}/{len(domains_to_migrate)}: {fqdn}")
                
                self.migrate_single_domain(fqdn, s)
        
        print("✓ Domain migration completed")
    
    def migrate_single_domain(self, fqdn: str, session):
        """Migrate a single domain to the new model."""
        try:
            extracted = tld_extractor.extract(fqdn)
            
            # Handle extraction failures
            if not extracted.domain or not extracted.suffix:
                parts = fqdn.split('.')
                if len(parts) >= 2:
                    domain = parts[-2]
                    tld = parts[-1]
                    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
                else:
                    domain = fqdn
                    tld = ''
                    subdomain = ''
            else:
                domain = extracted.domain
                tld = extracted.suffix
                subdomain = extracted.subdomain
            
            is_tld_domain = not subdomain
            
            with session.begin_transaction() as tx:
                # Create TLD node
                tx.run("""
                    MERGE (tld:TLD {name: $tld})
                    SET tld.last_updated = $current_time
                """, tld=tld, current_time=self.current_time)
                
                if is_tld_domain:
                    # This is a TLD domain (like "bci.cl")
                    tx.run("""
                        MATCH (old:Domain {fqdn: $fqdn})
                        SET old.domain_name = $domain_name,
                            old.tld = $tld,
                            old.last_analyzed = coalesce(old.last_analyzed, $current_time),
                            old.last_risk_scoring = coalesce(old.last_risk_scoring, $current_time)
                    """, fqdn=fqdn, domain_name=domain, tld=tld, current_time=self.current_time)
                    
                    # Create TLD -> Domain relationship
                    tx.run("""
                        MATCH (tld:TLD {name: $tld})
                        MATCH (d:Domain {fqdn: $fqdn})
                        MERGE (tld)-[:CONTAINS_DOMAIN]->(d)
                    """, tld=tld, fqdn=fqdn)
                    
                else:
                    # This is a subdomain (like "www.bci.cl")
                    parent_fqdn = f"{domain}.{tld}"
                    
                    # Ensure parent domain exists
                    tx.run("""
                        MERGE (parent:Domain {fqdn: $parent_fqdn})
                        SET parent.domain_name = $domain_name,
                            parent.tld = $tld,
                            parent.last_analyzed = coalesce(parent.last_analyzed, $current_time),
                            parent.last_risk_scoring = coalesce(parent.last_risk_scoring, $current_time)
                    """, parent_fqdn=parent_fqdn, domain_name=domain, tld=tld, current_time=self.current_time)
                    
                    # Create TLD -> Domain relationship
                    tx.run("""
                        MATCH (tld:TLD {name: $tld})
                        MATCH (d:Domain {fqdn: $parent_fqdn})
                        MERGE (tld)-[:CONTAINS_DOMAIN]->(d)
                    """, tld=tld, parent_fqdn=parent_fqdn)
                    
                    # Convert existing Domain node to Subdomain
                    tx.run("""
                        MATCH (old:Domain {fqdn: $fqdn})
                        REMOVE old:Domain
                        SET old:Subdomain,
                            old.subdomain_name = $subdomain_name,
                            old.domain_name = $domain_name,
                            old.tld = $tld,
                            old.last_analyzed = coalesce(old.last_analyzed, $current_time),
                            old.last_risk_scoring = coalesce(old.last_risk_scoring, $current_time)
                    """, fqdn=fqdn, subdomain_name=subdomain, domain_name=domain, tld=tld, current_time=self.current_time)
                    
                    # Create Domain -> Subdomain relationship
                    tx.run("""
                        MATCH (parent:Domain {fqdn: $parent_fqdn})
                        MATCH (sub:Subdomain {fqdn: $fqdn})
                        MERGE (parent)-[:HAS_SUBDOMAIN]->(sub)
                    """, parent_fqdn=parent_fqdn, fqdn=fqdn)
                
                tx.commit()
                
        except Exception as e:
            print(f"Error migrating domain {fqdn}: {e}")
    
    def update_relationships(self):
        """Update existing relationships to work with new model."""
        print("Updating existing relationships...")
        
        with self.drv.session() as s:
            # Update HAS_SUBDOMAIN relationships that might be pointing to wrong nodes
            s.run("""
                MATCH (d:Domain)-[r:HAS_SUBDOMAIN]->(target)
                WHERE NOT target:Subdomain
                DELETE r
            """)
            
            # Recreate proper HAS_SUBDOMAIN relationships
            s.run("""
                MATCH (d:Domain), (s:Subdomain)
                WHERE s.domain_name = d.domain_name AND s.tld = d.tld
                AND NOT EXISTS((d)-[:HAS_SUBDOMAIN]->(s))
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """)
            
            print("✓ Relationships updated")
    
    def add_analysis_timestamps(self):
        """Add analysis timestamps to existing nodes."""
        print("Adding analysis timestamps...")
        
        with self.drv.session() as s:
            # Add timestamps to Domain nodes
            s.run("""
                MATCH (d:Domain)
                WHERE d.last_analyzed IS NULL
                SET d.last_analyzed = $current_time
            """, current_time=self.current_time)
            
            s.run("""
                MATCH (d:Domain)
                WHERE d.last_risk_scoring IS NULL
                SET d.last_risk_scoring = $current_time
            """, current_time=self.current_time)
            
            # Add timestamps to Subdomain nodes
            s.run("""
                MATCH (s:Subdomain)
                WHERE s.last_analyzed IS NULL
                SET s.last_analyzed = $current_time
            """, current_time=self.current_time)
            
            s.run("""
                MATCH (s:Subdomain)
                WHERE s.last_risk_scoring IS NULL
                SET s.last_risk_scoring = $current_time
            """, current_time=self.current_time)
            
            print("✓ Analysis timestamps added")
    
    def create_indexes(self):
        """Create indexes for better performance."""
        print("Creating performance indexes...")
        
        with self.drv.session() as s:
            # Indexes for timestamp-based queries
            s.run("CREATE INDEX domain_last_analyzed IF NOT EXISTS FOR (d:Domain) ON (d.last_analyzed)")
            s.run("CREATE INDEX domain_last_risk_scoring IF NOT EXISTS FOR (d:Domain) ON (d.last_risk_scoring)")
            s.run("CREATE INDEX subdomain_last_analyzed IF NOT EXISTS FOR (s:Subdomain) ON (s.last_analyzed)")
            s.run("CREATE INDEX subdomain_last_risk_scoring IF NOT EXISTS FOR (s:Subdomain) ON (s.last_risk_scoring)")
            
            # Indexes for domain structure
            s.run("CREATE INDEX domain_name_tld IF NOT EXISTS FOR (d:Domain) ON (d.domain_name, d.tld)")
            s.run("CREATE INDEX subdomain_domain_tld IF NOT EXISTS FOR (s:Subdomain) ON (s.domain_name, s.tld)")
            
            print("✓ Indexes created")
    
    def validate_migration(self):
        """Validate the migration results."""
        print("Validating migration...")
        
        with self.drv.session() as s:
            # Check TLD nodes
            tld_result = s.run("MATCH (t:TLD) RETURN COUNT(t) as count").single()
            print(f"TLD nodes: {tld_result['count']}")
            
            # Check Domain nodes
            domain_result = s.run("MATCH (d:Domain) RETURN COUNT(d) as count").single()
            print(f"Domain nodes: {domain_result['count']}")
            
            # Check Subdomain nodes
            subdomain_result = s.run("MATCH (s:Subdomain) RETURN COUNT(s) as count").single()
            print(f"Subdomain nodes: {subdomain_result['count']}")
            
            # Check relationships
            tld_domain_rel = s.run("MATCH (t:TLD)-[:CONTAINS_DOMAIN]->(d:Domain) RETURN COUNT(*) as count").single()
            print(f"TLD -> Domain relationships: {tld_domain_rel['count']}")
            
            domain_subdomain_rel = s.run("MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN COUNT(*) as count").single()
            print(f"Domain -> Subdomain relationships: {domain_subdomain_rel['count']}")
            
            # Check for nodes without timestamps
            no_analysis_timestamp = s.run("""
                MATCH (n) WHERE (n:Domain OR n:Subdomain) AND n.last_analyzed IS NULL
                RETURN COUNT(n) as count
            """).single()
            print(f"Nodes without analysis timestamp: {no_analysis_timestamp['count']}")
            
            no_risk_timestamp = s.run("""
                MATCH (n) WHERE (n:Domain OR n:Subdomain) AND n.last_risk_scoring IS NULL
                RETURN COUNT(n) as count
            """).single()
            print(f"Nodes without risk scoring timestamp: {no_risk_timestamp['count']}")
            
            print("✓ Migration validation completed")
    
    def run_full_migration(self):
        """Run the complete migration process."""
        print("Starting enhanced model migration...")
        
        self.setup_new_constraints()
        self.migrate_existing_domains()
        self.update_relationships()
        self.add_analysis_timestamps()
        self.create_indexes()
        self.validate_migration()
        
        print("✓ Migration completed successfully!")
    
    def close(self):
        """Close Neo4j connection."""
        self.drv.close()

def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(description="Migrate graph to enhanced domain model")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--validate-only", action="store_true", help="Only validate current state")
    
    args = parser.parse_args()
    
    migrator = GraphMigrator(args.bolt, args.user, args.password)
    
    try:
        if args.validate_only:
            migrator.validate_migration()
        else:
            migrator.run_full_migration()
    finally:
        migrator.close()

if __name__ == "__main__":
    main()