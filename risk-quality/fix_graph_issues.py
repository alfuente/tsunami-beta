#!/usr/bin/env python3
"""
fix_graph_issues.py - Script to fix specific graph issues identified in validation

Fixes:
1. Remove test domains (example.com, github.com) and their relationships
2. Add missing required properties to existing nodes
3. Clean up isolated nodes that shouldn't exist
"""

import sys
import logging
from datetime import datetime
from typing import List, Dict, Any

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Error: Neo4j driver not available")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GraphFixer:
    """Fixes specific issues in the Neo4j graph"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="neo4j"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.test_domains = ["example.com", "github.com"]
        
    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()
            
    def remove_test_domains(self) -> None:
        """Remove test domains and all their relationships"""
        logger.info("Removing test domains and their relationships...")
        
        with self.driver.session() as session:
            for domain in self.test_domains:
                logger.info(f"Removing domain: {domain}")
                
                # Get count before deletion
                count_query = "MATCH (d:Domain {fqdn: $fqdn}) RETURN count(d) as count"
                result = session.run(count_query, fqdn=domain)
                count = result.single()["count"]
                
                if count > 0:
                    # Delete domain and all its relationships
                    delete_query = """
                    MATCH (d:Domain {fqdn: $fqdn})
                    DETACH DELETE d
                    """
                    session.run(delete_query, fqdn=domain)
                    logger.info(f"Removed {count} domain node(s) for {domain}")
                else:
                    logger.info(f"Domain {domain} not found in graph")
                    
    def fix_domain_properties(self) -> None:
        """Add missing required properties to Domain nodes"""
        logger.info("Fixing Domain node properties...")
        
        with self.driver.session() as session:
            # Add 'id' property (use fqdn as id if missing)
            id_query = """
            MATCH (d:Domain)
            WHERE d.id IS NULL
            SET d.id = d.fqdn
            RETURN count(d) as updated
            """
            result = session.run(id_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'id' property for {updated} Domain nodes")
            
            # Add 'tld' property (extract from fqdn)
            tld_query = """
            MATCH (d:Domain)
            WHERE d.tld IS NULL AND d.fqdn IS NOT NULL
            SET d.tld = CASE 
                WHEN d.fqdn CONTAINS '.' THEN split(d.fqdn, '.')[-1]
                ELSE 'unknown'
            END
            RETURN count(d) as updated
            """
            result = session.run(tld_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'tld' property for {updated} Domain nodes")
            
            # Add 'status' property (default to 'active')
            status_query = """
            MATCH (d:Domain)
            WHERE d.status IS NULL
            SET d.status = 'active'
            RETURN count(d) as updated
            """
            result = session.run(status_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'status' property for {updated} Domain nodes")
            
    def fix_service_properties(self) -> None:
        """Add missing required properties to Service nodes"""
        logger.info("Fixing Service node properties...")
        
        with self.driver.session() as session:
            # Add 'id' property where missing (use internal Neo4j ID as fallback)
            id_query = """
            MATCH (s:Service)
            WHERE s.id IS NULL
            SET s.id = toString(id(s))
            RETURN count(s) as updated
            """
            result = session.run(id_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'id' property for {updated} Service nodes")
            
            # Add 'name' property (use port/protocol info if available)
            name_query = """
            MATCH (s:Service)
            WHERE s.name IS NULL
            SET s.name = CASE 
                WHEN s.port IS NOT NULL AND s.protocol IS NOT NULL THEN s.protocol + '/' + toString(s.port)
                WHEN s.port IS NOT NULL THEN 'port-' + toString(s.port)
                WHEN s.protocol IS NOT NULL THEN s.protocol
                ELSE 'service-' + toString(id(s))
            END
            RETURN count(s) as updated
            """
            result = session.run(name_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'name' property for {updated} Service nodes")
            
            # Add 'type' property (infer from port/protocol)
            type_query = """
            MATCH (s:Service)
            WHERE s.type IS NULL
            SET s.type = CASE 
                WHEN s.port IN [80, 8080, 8000] THEN 'web'
                WHEN s.port IN [443, 8443] THEN 'https'
                WHEN s.port IN [22] THEN 'ssh'
                WHEN s.port IN [25, 587] THEN 'smtp'
                WHEN s.port IN [53] THEN 'dns'
                WHEN s.port IN [21] THEN 'ftp'
                WHEN s.port IN [23] THEN 'telnet'
                WHEN s.protocol IS NOT NULL THEN s.protocol
                ELSE 'unknown'
            END
            RETURN count(s) as updated
            """
            result = session.run(type_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'type' property for {updated} Service nodes")
            
    def fix_provider_properties(self) -> None:
        """Add missing required properties to Provider nodes"""
        logger.info("Fixing Provider node properties...")
        
        with self.driver.session() as session:
            # Add 'id' property where missing
            id_query = """
            MATCH (p:Provider)
            WHERE p.id IS NULL
            SET p.id = CASE 
                WHEN p.name IS NOT NULL THEN toLower(replace(p.name, ' ', '_'))
                ELSE 'provider_' + toString(id(p))
            END
            RETURN count(p) as updated
            """
            result = session.run(id_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'id' property for {updated} Provider nodes")
            
            # Add 'country' property (default to 'unknown' for now)
            country_query = """
            MATCH (p:Provider)
            WHERE p.country IS NULL
            SET p.country = 'unknown'
            RETURN count(p) as updated
            """
            result = session.run(country_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'country' property for {updated} Provider nodes")
            
    def fix_technology_properties(self) -> None:
        """Add missing required properties to Technology nodes"""
        logger.info("Fixing Technology node properties...")
        
        with self.driver.session() as session:
            # Add 'id' property where missing
            id_query = """
            MATCH (t:Technology)
            WHERE t.id IS NULL
            SET t.id = CASE 
                WHEN t.name IS NOT NULL THEN toLower(replace(t.name, ' ', '_'))
                ELSE 'tech_' + toString(id(t))
            END
            RETURN count(t) as updated
            """
            result = session.run(id_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'id' property for {updated} Technology nodes")
            
            # Add 'version' property (default to 'unknown')
            version_query = """
            MATCH (t:Technology)
            WHERE t.version IS NULL
            SET t.version = 'unknown'
            RETURN count(t) as updated
            """
            result = session.run(version_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'version' property for {updated} Technology nodes")
            
            # Add 'type' property where missing (categorize based on name)
            type_query = """
            MATCH (t:Technology)
            WHERE t.type IS NULL
            SET t.type = CASE 
                WHEN t.name =~ '(?i).*(apache|nginx|iis|tomcat|jetty).*' THEN 'web_server'
                WHEN t.name =~ '(?i).*(mysql|postgresql|oracle|mongodb|redis).*' THEN 'database'
                WHEN t.name =~ '(?i).*(php|python|java|nodejs|ruby).*' THEN 'runtime'
                WHEN t.name =~ '(?i).*(javascript|css|html).*' THEN 'frontend'
                WHEN t.name =~ '(?i).*(ssl|tls|openssl).*' THEN 'security'
                WHEN t.name =~ '(?i).*(linux|windows|ubuntu|centos).*' THEN 'os'
                ELSE 'unknown'
            END
            RETURN count(t) as updated
            """
            result = session.run(type_query)
            updated = result.single()["updated"]
            logger.info(f"Updated 'type' property for {updated} Technology nodes")
            
    def clean_isolated_nodes(self) -> None:
        """Remove truly isolated nodes that shouldn't exist"""
        logger.info("Cleaning isolated nodes...")
        
        with self.driver.session() as session:
            # Remove isolated RiskConfiguration nodes (likely orphaned)
            risk_config_query = """
            MATCH (rc:RiskConfiguration)
            WHERE NOT (rc)--()
            DELETE rc
            RETURN count(rc) as deleted
            """
            result = session.run(risk_config_query)
            deleted = result.single()["deleted"]
            if deleted > 0:
                logger.info(f"Removed {deleted} isolated RiskConfiguration nodes")
                
            # Log but don't delete isolated vulnerabilities (might be intentional)
            vuln_query = """
            MATCH (v:Vulnerability)
            WHERE NOT (v)--()
            RETURN count(v) as isolated
            """
            result = session.run(vuln_query)
            isolated = result.single()["isolated"]
            if isolated > 0:
                logger.info(f"Found {isolated} isolated Vulnerability nodes (keeping for reference)")
                
    def run_fixes(self) -> None:
        """Run all fix operations"""
        logger.info("=" * 50)
        logger.info("STARTING GRAPH FIXES")
        logger.info("=" * 50)
        
        try:
            # 1. Remove test domains
            self.remove_test_domains()
            
            # 2. Fix missing properties
            self.fix_domain_properties()
            self.fix_service_properties() 
            self.fix_provider_properties()
            self.fix_technology_properties()
            
            # 3. Clean isolated nodes
            self.clean_isolated_nodes()
            
            logger.info("=" * 50)
            logger.info("GRAPH FIXES COMPLETED SUCCESSFULLY")
            logger.info("=" * 50)
            
        except Exception as e:
            logger.error(f"Error during graph fixes: {e}")
            raise

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix specific graph issues')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='neo4j', help='Neo4j password')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed without making changes')
    
    args = parser.parse_args()
    
    try:
        fixer = GraphFixer(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        
        if args.dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
            # TODO: Implement dry-run mode
        else:
            fixer.run_fixes()
            
        fixer.close()
        logger.info("Fix script completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Failed to run fixes: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())