#!/usr/bin/env python3
"""
graph_relative_analyzer.py - Tsunami Beta Graph Relative Nodes and Edges Analyzer

Analyzes the Neo4j graph to identify relative nodes and edges, detecting patterns and relationships
that indicate dependencies, connections, and structural relationships between entities.

This script helps identify:
- Orphaned nodes without relationships
- Highly connected nodes (potential hubs)
- Missing critical relationships
- Relationship patterns and anomalies
"""

import json
import logging
from datetime import datetime
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
    print("Error: Neo4j driver not available. Run: pip install neo4j")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RelativeAnalysisLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class RelativeAnalysisResult:
    level: RelativeAnalysisLevel
    category: str
    description: str
    count: int
    entities: List[str]
    recommendations: List[str]
    details: Dict[str, Any]

@dataclass
class GraphRelativeReport:
    timestamp: datetime
    total_nodes: int
    total_relationships: int
    orphaned_nodes: int
    hub_nodes: int
    analysis_results: List[RelativeAnalysisResult]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_nodes": self.total_nodes,
            "total_relationships": self.total_relationships,
            "orphaned_nodes": self.orphaned_nodes,
            "hub_nodes": self.hub_nodes,
            "analysis_results": [asdict(result) for result in self.analysis_results]
        }

class GraphRelativeAnalyzer:
    def __init__(self, neo4j_uri="bolt://localhost:7687", 
                 neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.results: List[RelativeAnalysisResult] = []

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

    def analyze_orphaned_nodes(self) -> RelativeAnalysisResult:
        """Find nodes without any relationships"""
        query = """
        MATCH (n)
        WHERE NOT (n)--()
        RETURN labels(n)[0] as node_type, 
               CASE 
                 WHEN n.name IS NOT NULL THEN n.name
                 WHEN n.domain IS NOT NULL THEN n.domain
                 WHEN n.ip IS NOT NULL THEN n.ip
                 ELSE toString(id(n))
               END as identifier,
               count(*) as count
        ORDER BY count DESC
        """
        
        results = self.run_query(query)
        orphaned = []
        total_orphaned = 0
        
        for record in results:
            node_type = record.get('node_type', 'Unknown')
            identifier = record.get('identifier', 'N/A')
            count = record.get('count', 0)
            total_orphaned += count
            orphaned.append(f"{node_type}:{identifier} (count: {count})")
        
        level = RelativeAnalysisLevel.HIGH if total_orphaned > 10 else RelativeAnalysisLevel.MEDIUM
        
        return RelativeAnalysisResult(
            level=level,
            category="Orphaned Nodes",
            description=f"Found {total_orphaned} nodes without any relationships",
            count=total_orphaned,
            entities=orphaned[:20],  # Limit to first 20 for readability
            recommendations=[
                "Review orphaned nodes for data quality issues",
                "Consider connecting isolated nodes to appropriate entities",
                "Investigate if these nodes should be removed from the graph"
            ],
            details={"query_used": query, "total_orphaned": total_orphaned}
        )

    def analyze_hub_nodes(self, threshold: int = 50) -> RelativeAnalysisResult:
        """Find highly connected nodes (potential hubs)"""
        query = f"""
        MATCH (n)--()
        WITH n, count(*) as degree
        WHERE degree >= {threshold}
        RETURN labels(n)[0] as node_type,
               CASE 
                 WHEN n.name IS NOT NULL THEN n.name
                 WHEN n.domain IS NOT NULL THEN n.domain
                 WHEN n.ip IS NOT NULL THEN n.ip
                 ELSE toString(id(n))
               END as identifier,
               degree
        ORDER BY degree DESC
        LIMIT 20
        """
        
        results = self.run_query(query)
        hubs = []
        
        for record in results:
            node_type = record.get('node_type', 'Unknown')
            identifier = record.get('identifier', 'N/A')
            degree = record.get('degree', 0)
            hubs.append(f"{node_type}:{identifier} (degree: {degree})")
        
        level = RelativeAnalysisLevel.INFO if len(hubs) < 5 else RelativeAnalysisLevel.MEDIUM
        
        return RelativeAnalysisResult(
            level=level,
            category="Hub Nodes",
            description=f"Found {len(hubs)} highly connected nodes (degree >= {threshold})",
            count=len(hubs),
            entities=hubs,
            recommendations=[
                "Monitor hub nodes for performance impact",
                "Consider if these high-degree nodes represent valid business relationships",
                "Review if hub nodes need additional analysis or monitoring"
            ],
            details={"threshold": threshold, "hub_count": len(hubs)}
        )

    def analyze_missing_domain_organizations(self) -> RelativeAnalysisResult:
        """Find domains without organization ownership"""
        query = """
        MATCH (d:Domain)
        WHERE NOT (d)<-[:OWNS]-(:Organization)
        RETURN d.domain as domain
        ORDER BY d.domain
        LIMIT 100
        """
        
        results = self.run_query(query)
        domains_without_orgs = [record['domain'] for record in results if record['domain']]
        
        level = RelativeAnalysisLevel.HIGH if len(domains_without_orgs) > 20 else RelativeAnalysisLevel.MEDIUM
        
        return RelativeAnalysisResult(
            level=level,
            category="Domains Without Organizations",
            description=f"Found {len(domains_without_orgs)} domains not owned by any organization",
            count=len(domains_without_orgs),
            entities=domains_without_orgs,
            recommendations=[
                "Identify and create missing Organization nodes",
                "Establish OWNS relationships between organizations and domains",
                "Review domain registration data to determine ownership"
            ],
            details={"missing_ownership_count": len(domains_without_orgs)}
        )

    def analyze_missing_dns_resolution(self) -> RelativeAnalysisResult:
        """Find domains without DNS resolution data"""
        query = """
        MATCH (d:Domain)
        WHERE NOT (d)-[:RESOLVES_TO]->(:DNSServer)
        AND NOT (d)-[:RESOLVES_TO]->(:Service)
        RETURN d.domain as domain
        ORDER BY d.domain  
        LIMIT 100
        """
        
        results = self.run_query(query)
        domains_without_dns = [record['domain'] for record in results if record['domain']]
        
        level = RelativeAnalysisLevel.CRITICAL if len(domains_without_dns) > 50 else RelativeAnalysisLevel.HIGH
        
        return RelativeAnalysisResult(
            level=level,
            category="Domains Without DNS Resolution",
            description=f"Found {len(domains_without_dns)} domains without DNS resolution data",
            count=len(domains_without_dns),
            entities=domains_without_dns,
            recommendations=[
                "Run DNS analysis for these domains",
                "Create RESOLVES_TO relationships to appropriate DNS servers or services",
                "Verify these domains are still active and resolvable"
            ],
            details={"missing_dns_count": len(domains_without_dns)}
        )

    def analyze_services_without_technologies(self) -> RelativeAnalysisResult:
        """Find services without technology identification"""
        query = """
        MATCH (s:Service)
        WHERE NOT (s)-[:USES_TECH]->(:Technology)
        RETURN s.service_name as service_name, s.port as port
        ORDER BY s.service_name
        LIMIT 100
        """
        
        results = self.run_query(query)
        services_without_tech = []
        for record in results:
            service = record.get('service_name', 'Unknown')
            port = record.get('port', 'N/A')
            services_without_tech.append(f"{service}:{port}")
        
        level = RelativeAnalysisLevel.MEDIUM
        
        return RelativeAnalysisResult(
            level=level,
            category="Services Without Technologies",
            description=f"Found {len(services_without_tech)} services without technology identification",
            count=len(services_without_tech),
            entities=services_without_tech,
            recommendations=[
                "Run technology detection on these services",
                "Create Technology nodes and USES_TECH relationships",
                "Analyze service fingerprints to identify technologies"
            ],
            details={"services_without_tech_count": len(services_without_tech)}
        )

    def analyze_certificates_without_domains(self) -> RelativeAnalysisResult:
        """Find certificates not associated with any domains"""
        query = """
        MATCH (c:Certificate)
        WHERE NOT (c)<-[:SECURED_BY]-(:Domain)
        RETURN c.subject as subject, c.serial_number as serial
        ORDER BY c.subject
        LIMIT 50
        """
        
        results = self.run_query(query)
        orphaned_certs = []
        for record in results:
            subject = record.get('subject', 'Unknown')
            serial = record.get('serial', 'N/A')
            orphaned_certs.append(f"{subject} (Serial: {serial})")
        
        level = RelativeAnalysisLevel.MEDIUM if len(orphaned_certs) > 10 else RelativeAnalysisLevel.LOW
        
        return RelativeAnalysisResult(
            level=level,
            category="Orphaned Certificates",
            description=f"Found {len(orphaned_certs)} certificates not associated with domains",
            count=len(orphaned_certs),
            entities=orphaned_certs,
            recommendations=[
                "Review certificate data to identify associated domains",
                "Create SECURED_BY relationships between domains and certificates",
                "Consider removing certificates not tied to any domains"
            ],
            details={"orphaned_certs_count": len(orphaned_certs)}
        )

    def analyze_relationship_patterns(self) -> RelativeAnalysisResult:
        """Analyze relationship patterns and identify anomalies"""
        query = """
        MATCH ()-[r]->()
        RETURN type(r) as relationship_type, count(*) as count
        ORDER BY count DESC
        """
        
        results = self.run_query(query)
        patterns = []
        total_relationships = 0
        
        for record in results:
            rel_type = record.get('relationship_type', 'Unknown')
            count = record.get('count', 0)
            total_relationships += count
            patterns.append(f"{rel_type}: {count}")
        
        # Identify potential anomalies
        anomalies = []
        if results:
            max_count = results[0].get('count', 0)
            for record in results:
                count = record.get('count', 0)
                rel_type = record.get('relationship_type', 'Unknown')
                # Flag relationships that are less than 1% of the most common type
                if max_count > 100 and count < (max_count * 0.01):
                    anomalies.append(f"{rel_type}: {count} (potentially rare)")
        
        level = RelativeAnalysisLevel.INFO
        
        return RelativeAnalysisResult(
            level=level,
            category="Relationship Patterns",
            description=f"Analyzed {len(patterns)} relationship types with {total_relationships} total relationships",
            count=len(patterns),
            entities=patterns[:15],  # Show top 15 relationship types
            recommendations=[
                "Monitor relationship distribution for data quality",
                "Investigate rare relationship types for accuracy",
                "Ensure balanced relationship patterns across the graph"
            ],
            details={
                "total_relationships": total_relationships,
                "relationship_types": len(patterns),
                "potential_anomalies": anomalies
            }
        )

    def get_graph_statistics(self) -> Tuple[int, int]:
        """Get basic graph statistics"""
        # Count nodes
        node_query = "MATCH (n) RETURN count(n) as node_count"
        node_results = self.run_query(node_query)
        total_nodes = node_results[0]['node_count'] if node_results else 0
        
        # Count relationships  
        rel_query = "MATCH ()-[r]->() RETURN count(r) as rel_count"
        rel_results = self.run_query(rel_query)
        total_relationships = rel_results[0]['rel_count'] if rel_results else 0
        
        return total_nodes, total_relationships

    def run_relative_analysis(self) -> GraphRelativeReport:
        """Run complete relative analysis of the graph"""
        logger.info("Starting graph relative analysis...")
        
        # Get basic statistics
        total_nodes, total_relationships = self.get_graph_statistics()
        logger.info(f"Graph contains {total_nodes} nodes and {total_relationships} relationships")
        
        # Run all analyses
        analyses = [
            self.analyze_orphaned_nodes(),
            self.analyze_hub_nodes(),
            self.analyze_missing_domain_organizations(),
            self.analyze_missing_dns_resolution(),
            self.analyze_services_without_technologies(),
            self.analyze_certificates_without_domains(),
            self.analyze_relationship_patterns()
        ]
        
        # Count specific statistics
        orphaned_count = next(
            (a.count for a in analyses if a.category == "Orphaned Nodes"), 0
        )
        hub_count = next(
            (a.count for a in analyses if a.category == "Hub Nodes"), 0
        )
        
        return GraphRelativeReport(
            timestamp=datetime.now(),
            total_nodes=total_nodes,
            total_relationships=total_relationships,
            orphaned_nodes=orphaned_count,
            hub_nodes=hub_count,
            analysis_results=analyses
        )

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze relative nodes and edges in Neo4j graph")
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687',
                      help='Neo4j URI (default: bolt://localhost:7687)')
    parser.add_argument('--neo4j-user', default='neo4j',
                      help='Neo4j username (default: neo4j)')
    parser.add_argument('--neo4j-password', default='neo4j',
                      help='Neo4j password (default: neo4j)')
    parser.add_argument('--output', '-o',
                      help='Output file for JSON report (default: stdout)')
    parser.add_argument('--hub-threshold', type=int, default=50,
                      help='Minimum connections to consider a node a hub (default: 50)')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        with GraphRelativeAnalyzer(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        ) as analyzer:
            
            # Override hub threshold if specified
            if hasattr(analyzer, 'hub_threshold'):
                analyzer.hub_threshold = args.hub_threshold
            
            report = analyzer.run_relative_analysis()
            
            # Output results
            report_json = json.dumps(report.to_dict(), indent=2)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report_json)
                logger.info(f"Report saved to {args.output}")
            else:
                print(report_json)
            
            # Print summary to stderr so it doesn't interfere with JSON output
            print(f"\n=== Graph Relative Analysis Summary ===", file=sys.stderr)
            print(f"Total Nodes: {report.total_nodes}", file=sys.stderr)
            print(f"Total Relationships: {report.total_relationships}", file=sys.stderr)
            print(f"Orphaned Nodes: {report.orphaned_nodes}", file=sys.stderr)
            print(f"Hub Nodes: {report.hub_nodes}", file=sys.stderr)
            print(f"Analysis Categories: {len(report.analysis_results)}", file=sys.stderr)
            
            # Count issues by level
            level_counts = {}
            for result in report.analysis_results:
                level = result.level.value
                level_counts[level] = level_counts.get(level, 0) + 1
            
            for level, count in level_counts.items():
                print(f"{level} Issues: {count}", file=sys.stderr)
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()