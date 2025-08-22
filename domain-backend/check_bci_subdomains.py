#!/usr/bin/env python3

import os
from neo4j import GraphDatabase
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_bci_subdomains():
    """Check subdomain data for bci.cl"""
    
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "test.password")
    
    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        with driver.session() as session:
            # Count subdomain nodes for bci.cl
            result = session.run("""
                MATCH (s:Subdomain) 
                WHERE s.fqdn CONTAINS "bci.cl"
                RETURN count(*) as count
            """)
            subdomain_count = result.single()['count']
            logger.info(f"Found {subdomain_count} subdomain nodes for bci.cl")
            
            # Show some example subdomain nodes with risk scores
            result = session.run("""
                MATCH (s:Subdomain) 
                WHERE s.fqdn CONTAINS "bci.cl" AND s.risk_score IS NOT NULL
                RETURN s.fqdn, s.risk_score, s.risk_tier 
                ORDER BY s.risk_score DESC
                LIMIT 10
            """)
            
            logger.info("Subdomain risk scores:")
            for record in result:
                fqdn = record['s.fqdn']
                risk_score = record['s.risk_score']
                risk_tier = record['s.risk_tier']
                logger.info(f"  {fqdn}: {risk_score} ({risk_tier})")
            
            # Check available relationships
            result = session.run("CALL db.relationshipTypes()")
            relationships = [record['relationshipType'] for record in result]
            logger.info(f"Available relationship types: {relationships}")
            
            # Show some example subdomain data
            result = session.run("""
                MATCH (s:Subdomain) 
                WHERE s.fqdn CONTAINS "bci.cl"
                RETURN s.fqdn, keys(s) as properties
                LIMIT 5
            """)
            
            logger.info("Example subdomain nodes:")
            for record in result:
                fqdn = record['s.fqdn']
                properties = record['properties']
                logger.info(f"  {fqdn}: {properties}")
            
            # Check for any subdomain relationships
            result = session.run("""
                MATCH (s:Subdomain)-[r]-(n)
                WHERE s.fqdn CONTAINS "bci.cl"
                RETURN type(r) as rel_type, count(*) as count
                ORDER BY count DESC
                LIMIT 10
            """)
            
            logger.info("Subdomain relationships:")
            for record in result:
                rel_type = record['rel_type']
                count = record['count']
                logger.info(f"  {rel_type}: {count}")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        return False
    finally:
        if 'driver' in locals():
            driver.close()
    
    return True

if __name__ == "__main__":
    check_bci_subdomains()