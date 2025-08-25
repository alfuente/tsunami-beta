#!/usr/bin/env python3
"""
graph_validator.py - Tsunami Beta Graph Quality Validator

Validates that the Neo4j graph contains all required information according to the data model.
Identifies missing nodes, relationships, and properties to ensure data completeness.

Based on the model defined in docs/Modelo.md
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
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

class ValidationLevel(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"

@dataclass
class ValidationResult:
    level: ValidationLevel
    category: str
    description: str
    details: Dict[str, Any]
    remediation_action: Optional[str] = None

@dataclass
class ValidationReport:
    timestamp: datetime
    total_issues: int
    errors: int
    warnings: int
    info: int
    results: List[ValidationResult]
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'total_issues': self.total_issues,
            'errors': self.errors,
            'warnings': self.warnings,
            'info': self.info,
            'results': [self._result_to_dict(result) for result in self.results]
        }
    
    def _result_to_dict(self, result):
        return {
            'level': result.level.value,
            'category': result.category,
            'description': result.description,
            'details': result.details,
            'remediation_action': result.remediation_action
        }

class GraphValidator:
    """Main validator class for graph quality validation"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.results: List[ValidationResult] = []
        
        # Expected node types from the model
        self.expected_node_types = {
            'Organization', 'Domain', 'DNSServer', 'Certificate', 
            'Service', 'Provider', 'Technology', 'Vulnerability'
        }
        
        # Expected relationship types from the model
        self.expected_relationship_types = {
            'OWNS', 'DEPENDS_ON', 'RESOLVES_TO', 'SECURED_BY', 
            'PROVIDES', 'ISSUED_BY', 'USES_TECH', 'SUPPLIES_TO', 'HAS_VULNERABILITY'
        }
        
        # Required properties per node type
        self.required_node_properties = {
            'Organization': ['id', 'name', 'type', 'country'],
            'Domain': ['id', 'fqdn', 'tld', 'status'],
            'DNSServer': ['id', 'hostname', 'ip_address', 'type'],
            'Certificate': ['id', 'serial_number', 'subject_cn', 'issuer_cn'],
            'Service': ['id', 'name', 'type', 'provider_name'],
            'Provider': ['id', 'name', 'type', 'country'],
            'Technology': ['id', 'name', 'version', 'type'],
            'Vulnerability': ['cve_id', 'cvss_score', 'description']
        }

    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def add_result(self, level: ValidationLevel, category: str, description: str, 
                   details: Dict[str, Any], remediation_action: Optional[str] = None):
        """Add a validation result to the report"""
        result = ValidationResult(level, category, description, details, remediation_action)
        self.results.append(result)
        logger.info(f"{level.value}: {category} - {description}")

    def validate_node_types_exist(self) -> None:
        """Validate that all expected node types exist in the graph"""
        with self.driver.session() as session:
            query = "CALL db.labels() YIELD label RETURN collect(label) as labels"
            result = session.run(query)
            existing_labels = set(result.single()["labels"])
            
            missing_types = self.expected_node_types - existing_labels
            
            if missing_types:
                self.add_result(
                    ValidationLevel.ERROR,
                    "Missing Node Types",
                    f"Graph is missing {len(missing_types)} expected node types",
                    {"missing_types": list(missing_types)},
                    "Use domain-backend to create missing node types"
                )
            else:
                self.add_result(
                    ValidationLevel.INFO,
                    "Node Types Complete",
                    "All expected node types are present in the graph",
                    {"present_types": list(existing_labels & self.expected_node_types)}
                )

    def validate_relationship_types_exist(self) -> None:
        """Validate that all expected relationship types exist in the graph"""
        with self.driver.session() as session:
            query = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as types"
            result = session.run(query)
            existing_types = set(result.single()["types"])
            
            missing_types = self.expected_relationship_types - existing_types
            
            if missing_types:
                self.add_result(
                    ValidationLevel.ERROR,
                    "Missing Relationship Types",
                    f"Graph is missing {len(missing_types)} expected relationship types",
                    {"missing_types": list(missing_types)},
                    "Use domain-backend to create missing relationships"
                )
            else:
                self.add_result(
                    ValidationLevel.INFO,
                    "Relationship Types Complete",
                    "All expected relationship types are present in the graph",
                    {"present_types": list(existing_types & self.expected_relationship_types)}
                )

    def validate_node_properties(self) -> None:
        """Validate that nodes have required properties"""
        with self.driver.session() as session:
            for node_type, required_props in self.required_node_properties.items():
                # Check if node type exists
                count_query = f"MATCH (n:{node_type}) RETURN count(n) as count"
                count_result = session.run(count_query)
                node_count = count_result.single()["count"]
                
                if node_count == 0:
                    self.add_result(
                        ValidationLevel.WARNING,
                        "Empty Node Type",
                        f"No {node_type} nodes found in the graph",
                        {"node_type": node_type, "expected_properties": required_props},
                        f"Use domain-backend to populate {node_type} nodes"
                    )
                    continue
                
                # Check for required properties
                for prop in required_props:
                    missing_query = f"""
                    MATCH (n:{node_type}) 
                    WHERE n.{prop} IS NULL OR n.{prop} = ''
                    RETURN count(n) as missing_count
                    """
                    missing_result = session.run(missing_query)
                    missing_count = missing_result.single()["missing_count"]
                    
                    if missing_count > 0:
                        percentage = (missing_count / node_count) * 100
                        level = ValidationLevel.ERROR if percentage > 10 else ValidationLevel.WARNING
                        
                        self.add_result(
                            level,
                            "Missing Properties",
                            f"{missing_count} {node_type} nodes missing required property '{prop}' ({percentage:.1f}%)",
                            {
                                "node_type": node_type,
                                "property": prop,
                                "missing_count": missing_count,
                                "total_count": node_count,
                                "percentage": percentage
                            },
                            f"Update {node_type} nodes to include {prop} property"
                        )

    def validate_domain_relationships(self) -> None:
        """Validate critical domain relationships"""
        with self.driver.session() as session:
            # Domains without organizations
            orphaned_domains_query = """
            MATCH (d:Domain)
            WHERE NOT (d)<-[:OWNS]-(:Organization)
            RETURN count(d) as orphaned_count
            """
            result = session.run(orphaned_domains_query)
            orphaned_count = result.single()["orphaned_count"]
            
            if orphaned_count > 0:
                self.add_result(
                    ValidationLevel.WARNING,
                    "Orphaned Domains",
                    f"{orphaned_count} domains not owned by any organization",
                    {"orphaned_count": orphaned_count},
                    "Create Organization nodes and OWNS relationships"
                )
            
            # Domains without DNS resolution
            no_dns_query = """
            MATCH (d:Domain)
            WHERE NOT (d)-[:RESOLVES_TO]->(:DNSServer)
            RETURN count(d) as no_dns_count
            """
            result = session.run(no_dns_query)
            no_dns_count = result.single()["no_dns_count"]
            
            if no_dns_count > 0:
                self.add_result(
                    ValidationLevel.ERROR,
                    "Missing DNS Resolution",
                    f"{no_dns_count} domains without DNS resolution data",
                    {"no_dns_count": no_dns_count},
                    "Run DNS analysis for domains missing resolution data"
                )

    def validate_security_data(self) -> None:
        """Validate security-related data completeness"""
        with self.driver.session() as session:
            # Domains without certificates
            no_cert_query = """
            MATCH (d:Domain)
            WHERE NOT (d)-[:SECURED_BY]->(:Certificate)
            RETURN count(d) as no_cert_count
            """
            result = session.run(no_cert_query)
            no_cert_count = result.single()["no_cert_count"]
            
            if no_cert_count > 0:
                self.add_result(
                    ValidationLevel.WARNING,
                    "Missing Certificate Data",
                    f"{no_cert_count} domains without SSL/TLS certificate data",
                    {"no_cert_count": no_cert_count},
                    "Run TLS analysis to collect certificate information"
                )
            
            # Expired certificates
            expired_cert_query = """
            MATCH (c:Certificate)
            WHERE c.valid_to < datetime()
            RETURN count(c) as expired_count
            """
            result = session.run(expired_cert_query)
            expired_count = result.single()["expired_count"]
            
            if expired_count > 0:
                self.add_result(
                    ValidationLevel.ERROR,
                    "Expired Certificates",
                    f"{expired_count} expired certificates found in the graph",
                    {"expired_count": expired_count},
                    "Update certificate data and implement renewal monitoring"
                )

    def validate_risk_scores(self) -> None:
        """Validate risk score completeness"""
        with self.driver.session() as session:
            risk_entities = ['Domain', 'Service', 'Provider', 'Technology']
            
            for entity_type in risk_entities:
                no_risk_query = f"""
                MATCH (n:{entity_type})
                WHERE n.risk_score IS NULL
                RETURN count(n) as no_risk_count, count(*) as total_count
                """
                result = session.run(no_risk_query)
                record = result.single()
                no_risk_count = record["no_risk_count"]
                total_count = record["total_count"]
                
                if no_risk_count > 0 and total_count > 0:
                    percentage = (no_risk_count / total_count) * 100
                    level = ValidationLevel.ERROR if percentage > 50 else ValidationLevel.WARNING
                    
                    self.add_result(
                        level,
                        "Missing Risk Scores",
                        f"{no_risk_count} {entity_type} nodes missing risk scores ({percentage:.1f}%)",
                        {
                            "entity_type": entity_type,
                            "no_risk_count": no_risk_count,
                            "total_count": total_count,
                            "percentage": percentage
                        },
                        f"Run risk calculation for {entity_type} nodes"
                    )

    def validate_technology_data(self) -> None:
        """Validate technology detection completeness"""
        with self.driver.session() as session:
            # Domains without technology information
            no_tech_query = """
            MATCH (d:Domain)
            WHERE NOT (d)-[:USES_TECH]->(:Technology)
            RETURN count(d) as no_tech_count
            """
            result = session.run(no_tech_query)
            no_tech_count = result.single()["no_tech_count"]
            
            if no_tech_count > 0:
                self.add_result(
                    ValidationLevel.INFO,
                    "Missing Technology Data",
                    f"{no_tech_count} domains without technology detection data",
                    {"no_tech_count": no_tech_count},
                    "Run web technology analysis for domains"
                )

    def validate_provider_data(self) -> None:
        """Validate provider and service data completeness"""
        with self.driver.session() as session:
            # Services without providers
            orphaned_services_query = """
            MATCH (s:Service)
            WHERE NOT (s)<-[:PROVIDES]-(:Provider)
            RETURN count(s) as orphaned_count
            """
            result = session.run(orphaned_services_query)
            orphaned_count = result.single()["orphaned_count"]
            
            if orphaned_count > 0:
                self.add_result(
                    ValidationLevel.WARNING,
                    "Orphaned Services",
                    f"{orphaned_count} services not linked to any provider",
                    {"orphaned_count": orphaned_count},
                    "Create Provider nodes and PROVIDES relationships"
                )

    def validate_graph_connectivity(self) -> None:
        """Validate overall graph connectivity"""
        with self.driver.session() as session:
            # Find disconnected components
            components_query = """
            MATCH (n)
            WHERE NOT (n)--()
            RETURN labels(n) as node_labels, count(n) as isolated_count
            """
            result = session.run(components_query)
            isolated_nodes = {}
            total_isolated = 0
            
            for record in result:
                node_labels = record["node_labels"]
                isolated_count = record["isolated_count"]
                # Convert list of labels to string for dictionary key
                label_key = "/".join(node_labels) if node_labels else "Unknown"
                isolated_nodes[label_key] = isolated_count
                total_isolated += isolated_count
            
            if total_isolated > 0:
                self.add_result(
                    ValidationLevel.WARNING,
                    "Isolated Nodes",
                    f"{total_isolated} nodes are not connected to any other nodes",
                    {"isolated_by_type": isolated_nodes, "total_isolated": total_isolated},
                    "Review and create appropriate relationships for isolated nodes"
                )

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get general graph statistics"""
        stats = {}
        
        with self.driver.session() as session:
            try:
                # Node counts by type
                node_counts = {}
                for node_type in self.expected_node_types:
                    count_query = f"MATCH (n:{node_type}) RETURN count(n) as count"
                    result = session.run(count_query)
                    record = result.single()
                    count = record["count"] if record else 0
                    node_counts[node_type] = count
                
                # Total nodes and relationships
                total_nodes_result = session.run("MATCH (n) RETURN count(n) as total")
                total_nodes_record = total_nodes_result.single()
                total_nodes = total_nodes_record["total"] if total_nodes_record else 0
                
                total_rels_result = session.run("MATCH ()-[r]->() RETURN count(r) as total")
                total_rels_record = total_rels_result.single()
                total_relationships = total_rels_record["total"] if total_rels_record else 0
                
                # Relationship counts by type
                rel_counts = {}
                existing_rels_result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
                existing_rels = [record["relationshipType"] for record in existing_rels_result]
                
                for rel_type in existing_rels:
                    count_query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count"
                    result = session.run(count_query)
                    record = result.single()
                    count = record["count"] if record else 0
                    rel_counts[rel_type] = count
                
                # Risk score coverage
                risk_coverage = {}
                for entity_type in ['Domain', 'Service', 'Provider', 'Technology']:
                    if node_counts.get(entity_type, 0) > 0:
                        with_risk_query = f"""
                        MATCH (n:{entity_type})
                        WITH count(n) as total,
                             count(CASE WHEN n.risk_score IS NOT NULL AND n.risk_score > 0 THEN 1 END) as with_risk
                        RETURN total, with_risk, (with_risk * 100.0 / total) as coverage_pct
                        """
                        result = session.run(with_risk_query)
                        record = result.single()
                        if record:
                            risk_coverage[entity_type] = {
                                'total': record['total'],
                                'with_risk': record['with_risk'],
                                'coverage_percent': round(record['coverage_pct'], 1)
                            }
                
                stats = {
                    'total_nodes': total_nodes,
                    'total_relationships': total_relationships,
                    'node_counts': node_counts,
                    'relationship_counts': rel_counts,
                    'risk_score_coverage': risk_coverage,
                    'graph_density': round((total_relationships / max(total_nodes * (total_nodes - 1), 1)) * 100, 3)
                }
                
            except Exception as e:
                logger.error(f"Error getting graph statistics: {e}")
                stats = {'error': str(e)}
        
        return stats

    def run_full_validation(self) -> ValidationReport:
        """Run all validation checks and return a comprehensive report"""
        logger.info("Starting full graph validation...")
        self.results.clear()
        
        # Get graph statistics first
        graph_stats = self.get_graph_statistics()
        logger.info("=" * 60)
        logger.info("GRAPH STATISTICS")
        logger.info("=" * 60)
        logger.info(f"📊 Total Nodes: {graph_stats.get('total_nodes', 0):,}")
        logger.info(f"🔗 Total Relationships: {graph_stats.get('total_relationships', 0):,}")
        logger.info(f"📈 Graph Density: {graph_stats.get('graph_density', 0)}%")
        
        # Node counts
        logger.info("\n📦 NODE COUNTS BY TYPE:")
        for node_type, count in graph_stats.get('node_counts', {}).items():
            status = "✅" if count > 0 else "❌"
            logger.info(f"  {status} {node_type}: {count:,}")
        
        # Relationship counts
        logger.info("\n🔗 RELATIONSHIP COUNTS:")
        rel_counts = graph_stats.get('relationship_counts', {})
        if rel_counts:
            for rel_type, count in rel_counts.items():
                logger.info(f"  • {rel_type}: {count:,}")
        else:
            logger.info("  ❌ No relationships found")
        
        # Risk score coverage
        logger.info("\n⚡ RISK SCORE COVERAGE:")
        risk_coverage = graph_stats.get('risk_score_coverage', {})
        for entity_type, coverage in risk_coverage.items():
            coverage_pct = coverage['coverage_percent']
            status = "✅" if coverage_pct > 80 else "⚠️" if coverage_pct > 50 else "❌"
            logger.info(f"  {status} {entity_type}: {coverage['with_risk']}/{coverage['total']} ({coverage_pct}%)")
        
        logger.info("=" * 60)
        logger.info("VALIDATION RESULTS")
        logger.info("=" * 60)
        
        try:
            # Core structure validation
            self.validate_node_types_exist()
            self.validate_relationship_types_exist()
            self.validate_node_properties()
            
            # Domain-specific validations
            self.validate_domain_relationships()
            self.validate_security_data()
            self.validate_risk_scores()
            self.validate_technology_data()
            self.validate_provider_data()
            
            # Overall connectivity
            self.validate_graph_connectivity()
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            self.add_result(
                ValidationLevel.ERROR,
                "Validation Exception",
                f"Error during validation: {str(e)}",
                {"exception": str(e)},
                "Check Neo4j connection and database status"
            )
        
        # Generate summary
        errors = sum(1 for r in self.results if r.level == ValidationLevel.ERROR)
        warnings = sum(1 for r in self.results if r.level == ValidationLevel.WARNING)
        info = sum(1 for r in self.results if r.level == ValidationLevel.INFO)
        
        report = ValidationReport(
            timestamp=datetime.now(),
            total_issues=len(self.results),
            errors=errors,
            warnings=warnings,
            info=info,
            results=self.results.copy()
        )
        
        # Add statistics to the report
        report.graph_statistics = graph_stats
        
        logger.info("=" * 60)
        logger.info("VALIDATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"🔍 Total Issues Found: {len(self.results)}")
        logger.info(f"❌ Errors: {errors}")
        logger.info(f"⚠️  Warnings: {warnings}")
        logger.info(f"ℹ️  Info: {info}")
        
        # Health score calculation
        total_possible_issues = len(self.expected_node_types) + len(self.expected_relationship_types) + 20  # Approximate
        health_score = max(0, 100 - (errors * 5 + warnings * 2))
        logger.info(f"🎯 Graph Health Score: {health_score}% ({self._get_health_status(health_score)})")
        
        return report

    def _get_health_status(self, score: float) -> str:
        """Get health status based on score"""
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Good"
        elif score >= 50:
            return "Fair"
        elif score >= 25:
            return "Poor"
        else:
            return "Critical"

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate Tsunami Beta graph quality')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='neo4j', help='Neo4j password')
    parser.add_argument('--output', '-o', help='Output file for validation report (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        validator = GraphValidator(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        report = validator.run_full_validation()
        validator.close()
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"Validation report saved to {args.output}")
        else:
            print(json.dumps(report.to_dict(), indent=2))
        
        # Exit with error code if there are errors
        return 1 if report.errors > 0 else 0
        
    except Exception as e:
        logger.error(f"Failed to run validation: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())