#!/usr/bin/env python3

import os
from neo4j import GraphDatabase
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_neo4j_connection():
    """Test Neo4j connection using same config as async API"""
    
    # Get Neo4j config from environment (same as async API)
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "test.password")
    
    logger.info(f"Testing Neo4j connection to {neo4j_uri}")
    logger.info(f"Using user: {neo4j_user}")
    
    try:
        driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        # Test connection
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            record = result.single()
            logger.info(f"Connection successful. Test query result: {record['test']}")
            
            # Check if we have domain nodes
            result = session.run("MATCH (n:Domain {fqdn: 'bci.cl'}) RETURN n LIMIT 1")
            domain_record = result.single()
            if domain_record:
                logger.info("Found bci.cl domain node in Neo4j")
                domain_data = dict(domain_record['n'])
                logger.info(f"Domain node data: {domain_data}")
            else:
                logger.warning("bci.cl domain node NOT found in Neo4j")
            
            # Check technology nodes
            result = session.run("MATCH (n:Technology) RETURN count(n) as tech_count")
            tech_count = result.single()['tech_count']
            logger.info(f"Found {tech_count} technology nodes in Neo4j")
            
            # Check if we have any relationships with technologies
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})-[:USES_TECHNOLOGY]->(t:Technology) 
                RETURN count(*) as tech_relations
            """)
            tech_relations = result.single()['tech_relations']
            logger.info(f"Found {tech_relations} technology relationships for bci.cl")
            
            # Show actual fields available in domain node
            result = session.run("MATCH (d:Domain {fqdn: 'bci.cl'}) RETURN keys(d) as available_fields")
            fields = result.single()['available_fields']
            logger.info(f"Available fields in domain node: {fields}")
            
            # Show technology relationships details
            result = session.run("""
                MATCH (d:Domain {fqdn: 'bci.cl'})-[:USES_TECHNOLOGY]->(t:Technology) 
                RETURN t.name, t.category, t.confidence LIMIT 5
            """)
            tech_details = [(record['t.name'], record['t.category'], record['t.confidence']) for record in result]
            logger.info(f"Technology details: {tech_details}")
            
            # List all labels to see what we have
            result = session.run("CALL db.labels()")
            labels = [record['label'] for record in result]
            logger.info(f"Available node labels in Neo4j: {labels}")
            
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")
        return False
    finally:
        if 'driver' in locals():
            driver.close()
    
    return True

if __name__ == "__main__":
    test_neo4j_connection()