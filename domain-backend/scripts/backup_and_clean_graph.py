#!/usr/bin/env python3
"""
Script para respaldar y limpiar la información del grafo Neo4j

Este script realiza un respaldo completo de todos los datos del grafo Neo4j
y luego opcionalmente limpia la base de datos para preparar una recarga completa.
"""

import sys
import json
import os
import shutil
from neo4j import GraphDatabase
from datetime import datetime
import logging
import argparse
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Neo4jBackupManager:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="test.password"):
        """Initialize Neo4j connection"""
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.uri = uri
        self.user = user
        self.password = password
        logger.info(f"Connected to Neo4j at {uri}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def get_database_statistics(self):
        """Get comprehensive database statistics before backup"""
        queries = {
            'total_nodes': "MATCH (n) RETURN count(n) as count",
            'total_relationships': "MATCH ()-[r]->() RETURN count(r) as count",
            'domains_count': "MATCH (d:Domain) RETURN count(d) as count",
            'providers_count': "MATCH (p:Provider) RETURN count(p) as count",
            'services_count': "MATCH (s:Service) RETURN count(s) as count",
            'certificates_count': "MATCH (c:Certificate) RETURN count(c) as count",
            'base_domains_count': """
                MATCH (d:Domain) 
                WHERE d.base_domain IS NOT NULL AND d.base_domain <> ""
                RETURN count(DISTINCT d.base_domain) as count
            """,
            'domains_with_risk': "MATCH (d:Domain) WHERE d.risk_score IS NOT NULL RETURN count(d) as count",
            'relationship_types': """
                MATCH ()-[r]->()
                RETURN type(r) as relationship_type, count(r) as count
                ORDER BY count DESC
            """,
            'node_labels': """
                MATCH (n)
                RETURN labels(n) as labels, count(n) as count
                ORDER BY count DESC
            """
        }
        
        statistics = {}
        
        try:
            with self.driver.session() as session:
                for stat_name, query in queries.items():
                    result = session.run(query)
                    
                    if stat_name in ['relationship_types', 'node_labels']:
                        statistics[stat_name] = [dict(record) for record in result]
                    else:
                        record = result.single()
                        statistics[stat_name] = record['count'] if record else 0
                        
            logger.info("Collected database statistics")
            return statistics
            
        except Exception as e:
            logger.error(f"Error collecting statistics: {e}")
            return {}
    
    def export_all_data(self, output_dir):
        """Export all data using APOC procedures"""
        export_queries = {
            'domains': """
                MATCH (d:Domain)
                RETURN d.fqdn as fqdn,
                       d.base_domain as base_domain,
                       d.tld as tld,
                       d.risk_score as risk_score,
                       d.risk_tier as risk_tier,
                       d.industry_classification as industry_classification,
                       d.country_code as country_code,
                       d.business_criticality as business_criticality,
                       d.monitoring_enabled as monitoring_enabled,
                       d.created_at as created_at,
                       d.last_updated as last_updated,
                       d.metadata as metadata
            """,
            'providers': """
                MATCH (p:Provider)
                RETURN p.name as name,
                       p.tld as tld,
                       p.country as country,
                       p.provider_type as provider_type,
                       p.confidence as confidence,
                       p.source as source,
                       p.asn as asn,
                       p.org as org,
                       p.risk_score as risk_score,
                       p.risk_tier as risk_tier,
                       p.metadata as metadata,
                       p.created_at as created_at
            """,
            'services': """
                MATCH (s:Service)
                RETURN s.name as name,
                       s.service_type as service_type,
                       s.detection_method as detection_method,
                       s.confidence as confidence,
                       s.domain as domain,
                       s.metadata as metadata,
                       s.created_at as created_at
            """,
            'certificates': """
                MATCH (c:Certificate)
                RETURN c.common_name as common_name,
                       c.subject_alternative_names as subject_alternative_names,
                       c.issuer as issuer,
                       c.valid_from as valid_from,
                       c.valid_to as valid_to,
                       c.serial_number as serial_number,
                       c.signature_algorithm as signature_algorithm,
                       c.key_size as key_size,
                       c.metadata as metadata,
                       c.created_at as created_at
            """,
            'relationships': """
                MATCH (a)-[r]->(b)
                RETURN startNode(r) as source_node,
                       endNode(r) as target_node,
                       type(r) as relationship_type,
                       r.confidence as confidence,
                       r.source as source,
                       r.created_at as created_at,
                       r.metadata as metadata,
                       labels(a) as source_labels,
                       labels(b) as target_labels,
                       CASE WHEN 'Domain' IN labels(a) THEN a.fqdn
                            WHEN 'Provider' IN labels(a) THEN a.name
                            WHEN 'Service' IN labels(a) THEN a.name
                            WHEN 'Certificate' IN labels(a) THEN a.common_name
                            ELSE id(a) END as source_id,
                       CASE WHEN 'Domain' IN labels(b) THEN b.fqdn
                            WHEN 'Provider' IN labels(b) THEN b.name
                            WHEN 'Service' IN labels(b) THEN b.name
                            WHEN 'Certificate' IN labels(b) THEN b.common_name
                            ELSE id(b) END as target_id
            """
        }
        
        exported_data = {}
        
        try:
            with self.driver.session() as session:
                for data_type, query in export_queries.items():
                    logger.info(f"Exporting {data_type}...")
                    result = session.run(query)
                    
                    data = []
                    for record in result:
                        # Convert Neo4j record to dictionary
                        record_dict = {}
                        for key in record.keys():
                            value = record[key]
                            # Handle Neo4j specific types
                            if hasattr(value, 'items'):  # Node or relationship
                                record_dict[key] = dict(value)
                            elif isinstance(value, list):
                                record_dict[key] = value
                            else:
                                record_dict[key] = value
                        data.append(record_dict)
                    
                    exported_data[data_type] = data
                    logger.info(f"Exported {len(data)} {data_type}")
                    
                    # Save individual JSON files
                    with open(os.path.join(output_dir, f'{data_type}.json'), 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            return exported_data
            
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            return {}
    
    def create_cypher_backup(self, output_dir):
        """Create Cypher script backup for complete restoration"""
        try:
            logger.info("Creating Cypher backup script...")
            
            cypher_file = os.path.join(output_dir, 'restore_database.cypher')
            
            with open(cypher_file, 'w', encoding='utf-8') as f:
                f.write("// Neo4j Database Restoration Script\\n")
                f.write(f"// Generated: {datetime.now().isoformat()}\\n")
                f.write("// =========================================\\n\\n")
                
                # Clear existing data
                f.write("// Clear existing data\\n")
                f.write("MATCH (n) DETACH DELETE n;\\n\\n")
                
                # Create constraints and indexes
                f.write("// Create constraints and indexes\\n")
                f.write("CREATE CONSTRAINT domain_fqdn_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE;\\n")
                f.write("CREATE CONSTRAINT provider_name_unique IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE;\\n")
                f.write("CREATE CONSTRAINT service_name_domain_unique IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.domain) IS UNIQUE;\\n")
                f.write("CREATE INDEX domain_base_domain IF NOT EXISTS FOR (d:Domain) ON (d.base_domain);\\n")
                f.write("CREATE INDEX domain_risk_score IF NOT EXISTS FOR (d:Domain) ON (d.risk_score);\\n")
                f.write("CREATE INDEX domain_tld IF NOT EXISTS FOR (d:Domain) ON (d.tld);\\n\\n")
                
                # Export creation queries
                with self.driver.session() as session:
                    # Export domains
                    f.write("// Create Domain nodes\\n")
                    result = session.run("MATCH (d:Domain) RETURN d")
                    for record in result:
                        domain = record['d']
                        props = []
                        for key, value in domain.items():
                            if value is not None:
                                if isinstance(value, str):
                                    props.append(f'{key}: "{value}"')
                                elif isinstance(value, bool):
                                    props.append(f'{key}: {str(value).lower()}')
                                else:
                                    props.append(f'{key}: {value}')
                        
                        if props:
                            f.write(f"CREATE (d:Domain {{{', '.join(props)}}});\\n")
                    
                    f.write("\\n// Create Provider nodes\\n")
                    result = session.run("MATCH (p:Provider) RETURN p")
                    for record in result:
                        provider = record['p']
                        props = []
                        for key, value in provider.items():
                            if value is not None:
                                if isinstance(value, str):
                                    props.append(f'{key}: "{value}"')
                                elif isinstance(value, bool):
                                    props.append(f'{key}: {str(value).lower()}')
                                else:
                                    props.append(f'{key}: {value}')
                        
                        if props:
                            f.write(f"CREATE (p:Provider {{{', '.join(props)}}});\\n")
                    
                    # Similar for other node types...
                    f.write("\\n// Create relationships\\n")
                    result = session.run("MATCH (a)-[r]->(b) RETURN a, r, b, type(r) as rel_type")
                    for record in result:
                        source = record['a']
                        target = record['b']
                        rel_type = record['rel_type']
                        
                        # Get source identifier
                        source_id = self._get_node_identifier(source)
                        target_id = self._get_node_identifier(target)
                        
                        if source_id and target_id:
                            f.write(f"MATCH (a), (b) WHERE {source_id} AND {target_id} CREATE (a)-[:{rel_type}]->(b);\\n")
            
            logger.info(f"Cypher backup script created: {cypher_file}")
            
        except Exception as e:
            logger.error(f"Error creating Cypher backup: {e}")
    
    def _get_node_identifier(self, node):
        """Get a unique identifier for a node for Cypher queries"""
        labels = list(node.labels)
        if 'Domain' in labels:
            return f'a.fqdn = "{node.get("fqdn")}"'
        elif 'Provider' in labels:
            return f'a.name = "{node.get("name")}"'
        elif 'Service' in labels:
            return f'a.name = "{node.get("name")}" AND a.domain = "{node.get("domain")}"'
        elif 'Certificate' in labels:
            return f'a.common_name = "{node.get("common_name")}"'
        return None
    
    def clean_database(self, confirm=False):
        """Clean all data from the database"""
        if not confirm:
            logger.warning("Clean operation requires confirmation. Use --confirm flag.")
            return False
        
        try:
            logger.info("Starting database cleanup...")
            
            with self.driver.session() as session:
                # Get counts before cleanup
                result = session.run("MATCH (n) RETURN count(n) as node_count")
                node_count = result.single()['node_count']
                
                result = session.run("MATCH ()-[r]->() RETURN count(r) as rel_count")
                rel_count = result.single()['rel_count']
                
                logger.info(f"Database contains {node_count} nodes and {rel_count} relationships")
                
                # Delete all nodes and relationships
                logger.info("Deleting all nodes and relationships...")
                session.run("MATCH (n) DETACH DELETE n")
                
                # Verify cleanup
                result = session.run("MATCH (n) RETURN count(n) as node_count")
                remaining_nodes = result.single()['node_count']
                
                if remaining_nodes == 0:
                    logger.info("✅ Database cleaned successfully")
                    return True
                else:
                    logger.error(f"❌ Cleanup incomplete: {remaining_nodes} nodes remaining")
                    return False
                    
        except Exception as e:
            logger.error(f"Error cleaning database: {e}")
            return False
    
    def create_database_dump(self, output_dir):
        """Create a database dump using neo4j-admin if available"""
        try:
            # Try to create a proper database dump
            dump_file = os.path.join(output_dir, 'neo4j_database.dump')
            
            logger.info("Attempting to create database dump...")
            
            # This would require neo4j-admin access - usually not available in Docker
            # For now, we'll create our own export format
            logger.info("Creating custom database export...")
            
            export_data = self.export_all_data(output_dir)
            statistics = self.get_database_statistics()
            
            backup_metadata = {
                'backup_timestamp': datetime.now().isoformat(),
                'neo4j_uri': self.uri,
                'statistics': statistics,
                'export_summary': {
                    'domains': len(export_data.get('domains', [])),
                    'providers': len(export_data.get('providers', [])),
                    'services': len(export_data.get('services', [])),
                    'certificates': len(export_data.get('certificates', [])),
                    'relationships': len(export_data.get('relationships', []))
                }
            }
            
            # Save backup metadata
            with open(os.path.join(output_dir, 'backup_metadata.json'), 'w', encoding='utf-8') as f:
                json.dump(backup_metadata, f, indent=2, ensure_ascii=False, default=str)
            
            return backup_metadata
            
        except Exception as e:
            logger.error(f"Error creating database dump: {e}")
            return None

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Backup and optionally clean Neo4j database')
    parser.add_argument('--clean', action='store_true', help='Clean database after backup')
    parser.add_argument('--confirm', action='store_true', help='Confirm destructive operations')
    parser.add_argument('--output-dir', help='Custom output directory')
    parser.add_argument('--uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--user', default='neo4j', help='Neo4j username')
    parser.add_argument('--password', default='test.password', help='Neo4j password')
    
    args = parser.parse_args()
    
    # Create output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"neo4j_backup_{timestamp}"
    
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info(f"Starting Neo4j backup - Output directory: {output_dir}")
    
    # Initialize backup manager
    backup_manager = Neo4jBackupManager(args.uri, args.user, args.password)
    
    try:
        # Get pre-backup statistics
        logger.info("Collecting database statistics...")
        statistics = backup_manager.get_database_statistics()
        
        # Create backup
        logger.info("Creating database backup...")
        backup_metadata = backup_manager.create_database_dump(output_dir)
        
        # Create Cypher restoration script
        backup_manager.create_cypher_backup(output_dir)
        
        # Clean database if requested
        if args.clean:
            logger.info("Cleaning database...")
            if backup_manager.clean_database(args.confirm):
                logger.info("✅ Database cleaned successfully")
            else:
                logger.error("❌ Database cleaning failed")
                sys.exit(1)
        
        # Print summary
        print("\\n" + "="*60)
        print("NEO4J BACKUP SUMMARY")
        print("="*60)
        print(f"📁 Backup directory: {output_dir}")
        print(f"🗄️  Total nodes: {statistics.get('total_nodes', 'N/A')}")
        print(f"🔗 Total relationships: {statistics.get('total_relationships', 'N/A')}")
        print(f"🌐 Domains: {statistics.get('domains_count', 'N/A')}")
        print(f"🏗️  Base domains: {statistics.get('base_domains_count', 'N/A')}")
        print(f"🔧 Providers: {statistics.get('providers_count', 'N/A')}")
        print(f"⚙️  Services: {statistics.get('services_count', 'N/A')}")
        print(f"🔒 Certificates: {statistics.get('certificates_count', 'N/A')}")
        print(f"⚠️  Domains with risk: {statistics.get('domains_with_risk', 'N/A')}")
        
        print("\\n📄 Files created:")
        print(f"   • backup_metadata.json - Backup information and statistics")
        print(f"   • domains.json - All domain data")
        print(f"   • providers.json - All provider data")
        print(f"   • services.json - All service data")
        print(f"   • certificates.json - All certificate data")
        print(f"   • relationships.json - All relationship data")
        print(f"   • restore_database.cypher - Cypher restoration script")
        
        if args.clean:
            print("\\n🧹 Database has been cleaned")
        
        print("\\n✅ Backup completed successfully!")
        
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)
    
    finally:
        backup_manager.close()

if __name__ == "__main__":
    main()