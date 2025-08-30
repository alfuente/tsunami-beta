#!/usr/bin/env python3
"""
debug_neo4j_data.py - Debug Neo4j data structure for web services

Investigates the current data structure in Neo4j to understand why the web subdomain
extraction is not finding results.
"""

import logging
import sys
from typing import Dict, List, Any

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Error: Neo4j driver not available. Run: pip install neo4j")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Neo4jDebugger:
    def __init__(self, neo4j_uri="bolt://localhost:7687", 
                 neo4j_user="neo4j", neo4j_password="neo4j"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    def close(self):
        if hasattr(self, 'driver'):
            self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Neo4j query and return results"""
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return list(result)
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def debug_node_types(self):
        """Check what node types exist in the database"""
        print("="*60)
        print("NODE TYPES IN DATABASE")
        print("="*60)
        
        query = """
        CALL db.labels() YIELD label
        RETURN label
        ORDER BY label
        """
        results = self.run_query(query)
        
        for record in results:
            label = record['label']
            count_query = f"MATCH (n:{label}) RETURN count(n) as count"
            count_results = self.run_query(count_query)
            count = count_results[0]['count'] if count_results else 0
            print(f"  {label}: {count} nodes")

    def debug_relationships(self):
        """Check what relationship types exist"""
        print("\n" + "="*60)
        print("RELATIONSHIP TYPES IN DATABASE")
        print("="*60)
        
        query = """
        CALL db.relationshipTypes() YIELD relationshipType
        RETURN relationshipType
        ORDER BY relationshipType
        """
        results = self.run_query(query)
        
        for record in results:
            rel_type = record['relationshipType']
            count_query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count"
            count_results = self.run_query(count_query)
            count = count_results[0]['count'] if count_results else 0
            print(f"  {rel_type}: {count} relationships")

    def debug_subdomains(self):
        """Check subdomain node structure"""
        print("\n" + "="*60)
        print("SUBDOMAIN NODES SAMPLE")
        print("="*60)
        
        query = """
        MATCH (s:Subdomain)
        RETURN s.fqdn as fqdn, 
               labels(s) as labels,
               keys(s) as properties
        LIMIT 5
        """
        results = self.run_query(query)
        
        for i, record in enumerate(results, 1):
            print(f"\n{i}. {record.get('fqdn', 'N/A')}")
            print(f"   Labels: {record.get('labels', [])}")
            print(f"   Properties: {record.get('properties', [])}")

    def debug_services(self):
        """Check service node structure"""
        print("\n" + "="*60)
        print("SERVICE NODES SAMPLE")
        print("="*60)
        
        query = """
        MATCH (s:Service)
        RETURN s.service_name as name,
               s.port as port,
               labels(s) as labels,
               keys(s) as properties
        LIMIT 5
        """
        results = self.run_query(query)
        
        for i, record in enumerate(results, 1):
            print(f"\n{i}. {record.get('name', 'N/A')} on port {record.get('port', 'N/A')}")
            print(f"   Labels: {record.get('labels', [])}")
            print(f"   Properties: {record.get('properties', [])}")

    def debug_subdomain_service_relationships(self):
        """Check how subdomains relate to services"""
        print("\n" + "="*60)
        print("SUBDOMAIN-SERVICE RELATIONSHIPS")
        print("="*60)
        
        # Check various possible relationships
        relationships_to_check = [
            "DEPENDS_ON",
            "HAS_SERVICE", 
            "RUNS_SERVICE",
            "PROVIDES",
            "HOSTS"
        ]
        
        for rel in relationships_to_check:
            query = f"""
            MATCH (s:Subdomain)-[r:{rel}]->(svc:Service)
            WHERE svc.port IN [80, 443, 8080, 8443]
            RETURN count(*) as count
            """
            results = self.run_query(query)
            count = results[0]['count'] if results else 0
            print(f"  Subdomain-[{rel}]->Service (web ports): {count}")

    def debug_web_services_detailed(self):
        """Check for web services in detail"""
        print("\n" + "="*60)
        print("WEB SERVICES DETAILED ANALYSIS")
        print("="*60)
        
        # Check services on web ports
        query = """
        MATCH (s:Service)
        WHERE s.port IN [80, 443, 8080, 8443]
        RETURN s.port as port, count(*) as count
        ORDER BY s.port
        """
        results = self.run_query(query)
        
        print("Services by web port:")
        for record in results:
            port = record.get('port', 'N/A')
            count = record.get('count', 0)
            print(f"  Port {port}: {count} services")

        # Check if any subdomains are connected to these services
        query = """
        MATCH (s:Service)
        WHERE s.port IN [80, 443, 8080, 8443]
        MATCH (sub)-[r]->(s)
        RETURN labels(sub)[0] as node_type, type(r) as relationship, count(*) as count
        """
        results = self.run_query(query)
        
        if results:
            print("\nConnections to web services:")
            for record in results:
                node_type = record.get('node_type', 'N/A')
                rel_type = record.get('relationship', 'N/A')
                count = record.get('count', 0)
                print(f"  {node_type}-[{rel_type}]->Service: {count}")
        else:
            print("\nNo connections found to web services!")

    def debug_alternative_queries(self):
        """Try alternative queries to find web-related data"""
        print("\n" + "="*60)
        print("ALTERNATIVE QUERIES FOR WEB DATA")
        print("="*60)
        
        # Try to find any subdomain with port information
        queries = [
            ("Subdomains with any port property", """
                MATCH (s:Subdomain)
                WHERE s.port IS NOT NULL OR s.ports IS NOT NULL
                RETURN count(*) as count
            """),
            ("Subdomains with services_count", """
                MATCH (s:Subdomain)
                WHERE s.services_count IS NOT NULL AND s.services_count > 0
                RETURN count(*) as count
            """),
            ("Any node with port 80 or 443", """
                MATCH (n)
                WHERE n.port IN [80, 443, 8080, 8443]
                RETURN labels(n)[0] as node_type, count(*) as count
            """),
            ("Domains with web services", """
                MATCH (d:Domain)-[:RESOLVES_TO]->(s:Service)
                WHERE s.port IN [80, 443, 8080, 8443]
                RETURN count(*) as count
            """),
            ("Any web-related relationships", """
                MATCH (a)-[r]-(b)
                WHERE (a.port IN [80, 443, 8080, 8443] OR b.port IN [80, 443, 8080, 8443])
                RETURN count(*) as count
            """)
        ]
        
        for description, query in queries:
            results = self.run_query(query)
            count = 0
            if results and 'count' in results[0]:
                count = results[0]['count']
            elif results and 'node_type' in results[0]:
                # Handle grouped results
                for record in results:
                    node_type = record.get('node_type', 'Unknown')
                    node_count = record.get('count', 0)
                    print(f"  {description}: {node_type} = {node_count}")
                continue
            
            print(f"  {description}: {count}")

    def suggest_fixes(self):
        """Suggest possible fixes based on findings"""
        print("\n" + "="*60)
        print("SUGGESTED FIXES")
        print("="*60)
        
        # Check if we have any subdomains at all
        subdomain_count_query = "MATCH (s:Subdomain) RETURN count(s) as count"
        subdomain_results = self.run_query(subdomain_count_query)
        subdomain_count = subdomain_results[0]['count'] if subdomain_results else 0
        
        service_count_query = "MATCH (s:Service) RETURN count(s) as count"
        service_results = self.run_query(service_count_query)
        service_count = service_results[0]['count'] if service_results else 0
        
        print(f"Total subdomains: {subdomain_count}")
        print(f"Total services: {service_count}")
        
        if subdomain_count == 0:
            print("\n❌ No Subdomain nodes found!")
            print("   Suggestion: Run subdomain discovery first")
        elif service_count == 0:
            print("\n❌ No Service nodes found!")
            print("   Suggestion: Run service discovery on subdomains")
        else:
            print("\n✅ Both Subdomain and Service nodes exist")
            print("   Suggestion: Check relationship patterns and update query")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Debug Neo4j data structure for web services")
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687',
                       help='Neo4j URI (default: bolt://localhost:7687)')
    parser.add_argument('--neo4j-user', default='neo4j',
                       help='Neo4j username (default: neo4j)')
    parser.add_argument('--neo4j-password', default='neo4j',
                       help='Neo4j password (default: neo4j)')
    
    args = parser.parse_args()
    
    try:
        with Neo4jDebugger(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        ) as debugger:
            
            print("🔍 DEBUGGING NEO4J DATA STRUCTURE FOR WEB SERVICES")
            print("=" * 80)
            
            debugger.debug_node_types()
            debugger.debug_relationships()
            debugger.debug_subdomains()
            debugger.debug_services()
            debugger.debug_subdomain_service_relationships()
            debugger.debug_web_services_detailed()
            debugger.debug_alternative_queries()
            debugger.suggest_fixes()
            
            print(f"\n{'=' * 80}")
            print("🏁 DEBUG ANALYSIS COMPLETE")
            print("=" * 80)
    
    except Exception as e:
        logger.error(f"Debug analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()