"""
Neo4j connector and data loading utilities for Risk Stats
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import asyncio
import json

try:
    from neo4j import GraphDatabase, Driver
    import networkx as nx
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    from .models import DependencyGraph, GraphNode, GraphEdge, NodeType, ExtendedRisk
    from .config import config
except ImportError:
    from models import DependencyGraph, GraphNode, GraphEdge, NodeType, ExtendedRisk
    from config import config

logger = logging.getLogger(__name__)

class Neo4jConnector:
    """Handles Neo4j connections and graph operations"""
    
    def __init__(self):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required: pip install neo4j")
        
        self.driver: Optional[Driver] = None
        self._connect()
    
    def _connect(self):
        """Establish Neo4j connection"""
        try:
            self.driver = GraphDatabase.driver(
                config.neo4j.uri,
                auth=(config.neo4j.user, config.neo4j.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            logger.info("Connected to Neo4j successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def execute_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Neo4j query"""
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return list(result)
        except Exception as e:
            logger.error(f"Query failed: {e}")
            raise

    def load_dependency_graph(self, node_types: List[str] = None, 
                            limit: Optional[int] = None) -> DependencyGraph:
        """Load dependency graph from Neo4j"""
        logger.info("Loading dependency graph from Neo4j...")
        
        # Default node types if not specified
        if node_types is None:
            node_types = ['Organization', 'Domain', 'Subdomain', 'Service', 'Provider', 'Technology']
        
        graph = DependencyGraph()
        
        # Load nodes
        nodes = self._load_nodes(node_types, limit)
        for node in nodes:
            graph.add_node(node)
        
        # Load edges (relationships)
        edges = self._load_edges(list(graph.nodes.keys()))
        for edge in edges:
            graph.add_edge(edge)
        
        logger.info(f"Loaded graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges")
        return graph

    def _load_nodes(self, node_types: List[str], limit: Optional[int] = None) -> List[GraphNode]:
        """Load nodes from Neo4j"""
        nodes = []
        
        for node_type in node_types:
            query = f"""
            MATCH (n:{node_type})
            RETURN n, labels(n) as labels
            {f'LIMIT {limit // len(node_types)}' if limit else ''}
            """
            
            results = self.execute_query(query)
            
            for record in results:
                node_data = dict(record['n'])
                labels = record['labels']
                
                # Extract extended risk if exists
                extended_risk = None
                if 'ext_risk' in node_data:
                    try:
                        risk_data = json.loads(node_data['ext_risk']) if isinstance(node_data['ext_risk'], str) else node_data['ext_risk']
                        extended_risk = ExtendedRisk.from_dict(risk_data)
                    except Exception as e:
                        logger.warning(f"Failed to parse ext_risk for node {node_data.get('id', 'unknown')}: {e}")
                
                # Create GraphNode
                node = GraphNode(
                    id=node_data.get('id', str(node_data.get('fqdn', node_data.get('name', '')))),
                    node_type=NodeType(node_type),
                    name=node_data.get('name', node_data.get('fqdn', node_data.get('id', 'Unknown'))),
                    sector=self._extract_sector(node_data, labels),
                    is_critical=node_data.get('is_critical', False),
                    properties=node_data,
                    extended_risk=extended_risk
                )
                
                nodes.append(node)
        
        return nodes

    def _load_edges(self, node_ids: List[str]) -> List[GraphEdge]:
        """Load edges between specified nodes"""
        if not node_ids:
            return []
        
        # Create parameterized query for large node lists
        query = """
        MATCH (a)-[r]->(b)
        WHERE (a.id IN $node_ids OR a.fqdn IN $node_ids OR a.name IN $node_ids)
        AND (b.id IN $node_ids OR b.fqdn IN $node_ids OR b.name IN $node_ids)
        RETURN a, b, r, type(r) as rel_type
        """
        
        edges = []
        batch_size = 1000  # Process in batches to avoid memory issues
        
        for i in range(0, len(node_ids), batch_size):
            batch_ids = node_ids[i:i+batch_size]
            results = self.execute_query(query, {"node_ids": batch_ids})
            
            for record in results:
                source_data = dict(record['a'])
                target_data = dict(record['b'])
                rel_data = dict(record['r']) if record['r'] else {}
                rel_type = record['rel_type']
                
                # Extract node identifiers
                source_id = source_data.get('id', source_data.get('fqdn', source_data.get('name', '')))
                target_id = target_data.get('id', target_data.get('fqdn', target_data.get('name', '')))
                
                if source_id and target_id:
                    # Calculate edge weight based on relationship type and properties
                    weight = self._calculate_edge_weight(rel_type, rel_data, source_data, target_data)
                    
                    edge = GraphEdge(
                        source=source_id,
                        target=target_id,
                        relationship_type=rel_type,
                        weight=weight,
                        properties=rel_data
                    )
                    
                    edges.append(edge)
        
        return edges

    def _extract_sector(self, node_data: Dict, labels: List[str]) -> Optional[str]:
        """Extract sector information from node data"""
        # Try explicit sector property
        if 'sector' in node_data:
            return node_data['sector']
        
        # Try to infer from industry or organization type
        if 'industry' in node_data:
            return self._map_industry_to_sector(node_data['industry'])
        
        # Try to infer from domain or name patterns
        name = node_data.get('name', node_data.get('fqdn', ''))
        return self._infer_sector_from_name(name)

    def _map_industry_to_sector(self, industry: str) -> str:
        """Map industry to standardized sector"""
        industry_lower = industry.lower()
        
        sector_mapping = {
            'bank': 'banking',
            'financial': 'banking', 
            'telecom': 'telecommunications',
            'telco': 'telecommunications',
            'energy': 'energy',
            'electric': 'energy',
            'government': 'government',
            'gov': 'government',
            'health': 'health',
            'hospital': 'health',
            'mining': 'mining',
            'retail': 'retail',
            'education': 'education',
            'transport': 'transport',
            'manufacturing': 'manufacturing'
        }
        
        for key, sector in sector_mapping.items():
            if key in industry_lower:
                return sector
        
        return 'other'

    def _infer_sector_from_name(self, name: str) -> str:
        """Infer sector from name patterns"""
        name_lower = name.lower()
        
        # Banking patterns
        if any(pattern in name_lower for pattern in ['banco', 'bank', 'bci', 'santander', 'chile']):
            return 'banking'
        
        # Government patterns  
        if any(pattern in name_lower for pattern in ['.gob.', 'gobierno', 'minsal', 'sii']):
            return 'government'
        
        # Telecommunications
        if any(pattern in name_lower for pattern in ['entel', 'movistar', 'claro', 'wom']):
            return 'telecommunications'
        
        # Default
        return 'other'

    def _calculate_edge_weight(self, rel_type: str, rel_data: Dict, 
                              source_data: Dict, target_data: Dict) -> float:
        """Calculate edge weight based on relationship type and properties"""
        
        # Base weights by relationship type
        base_weights = {
            'DEPENDS_ON': 3.0,
            'RUNS_SERVICE': 2.5, 
            'USES_PROVIDER': 2.0,
            'SECURED_BY': 1.8,
            'RESOLVES_TO': 1.5,
            'HAS_SUBDOMAIN': 1.2,
            'USES_TECH': 1.0,
            'REFERENCES': 0.5
        }
        
        base_weight = base_weights.get(rel_type, 1.0)
        
        # Adjust based on criticality
        if source_data.get('is_critical') or target_data.get('is_critical'):
            base_weight *= 1.5
        
        # Adjust based on relationship properties
        if 'weight' in rel_data:
            base_weight *= rel_data['weight']
        
        return min(base_weight, 10.0)  # Cap at 10.0

    def save_extended_risk(self, node_id: str, extended_risk: ExtendedRisk) -> bool:
        """Save extended risk data to a node"""
        try:
            risk_json = json.dumps(extended_risk.to_dict())
            
            query = """
            MATCH (n)
            WHERE n.id = $node_id OR n.fqdn = $node_id OR n.name = $node_id
            SET n.ext_risk = $risk_data,
                n.ext_risk_updated_at = datetime()
            RETURN count(n) as updated_count
            """
            
            result = self.execute_query(query, {
                "node_id": node_id,
                "risk_data": risk_json
            })
            
            updated_count = result[0]['updated_count'] if result else 0
            
            if updated_count > 0:
                logger.debug(f"Saved extended risk for node {node_id}")
                return True
            else:
                logger.warning(f"No node found with id {node_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to save extended risk for node {node_id}: {e}")
            return False

    def batch_save_extended_risks(self, risk_data: Dict[str, ExtendedRisk]) -> int:
        """Batch save extended risk data for multiple nodes"""
        saved_count = 0
        
        # Process in batches to avoid memory issues
        batch_size = config.batch_size
        items = list(risk_data.items())
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i+batch_size]
            
            try:
                with self.driver.session() as session:
                    with session.begin_transaction() as tx:
                        for node_id, extended_risk in batch:
                            risk_json = json.dumps(extended_risk.to_dict())
                            
                            result = tx.run("""
                                MATCH (n)
                                WHERE n.id = $node_id OR n.fqdn = $node_id OR n.name = $node_id
                                SET n.ext_risk = $risk_data,
                                    n.ext_risk_updated_at = datetime()
                                RETURN count(n) as updated_count
                            """, {
                                "node_id": node_id,
                                "risk_data": risk_json
                            })
                            
                            updated_count = result.single()['updated_count']
                            saved_count += updated_count
                        
                        tx.commit()
                
                logger.info(f"Batch saved {len(batch)} extended risk records")
                
            except Exception as e:
                logger.error(f"Failed to save batch of extended risks: {e}")
        
        return saved_count

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get basic graph statistics"""
        stats = {}
        
        # Node counts by type
        node_query = """
        MATCH (n)
        RETURN labels(n)[0] as node_type, count(n) as count
        ORDER BY count DESC
        """
        
        results = self.execute_query(node_query)
        stats['node_counts'] = {record['node_type']: record['count'] for record in results}
        
        # Relationship counts by type
        rel_query = """
        MATCH ()-[r]->()
        RETURN type(r) as rel_type, count(r) as count  
        ORDER BY count DESC
        """
        
        results = self.execute_query(rel_query)
        stats['relationship_counts'] = {record['rel_type']: record['count'] for record in results}
        
        # Extended risk coverage
        ext_risk_query = """
        MATCH (n)
        WHERE n.ext_risk IS NOT NULL
        RETURN labels(n)[0] as node_type, count(n) as count
        """
        
        results = self.execute_query(ext_risk_query)
        stats['ext_risk_coverage'] = {record['node_type']: record['count'] for record in results}
        
        return stats

    def create_networkx_graph(self, dependency_graph: DependencyGraph) -> 'nx.DiGraph':
        """Convert DependencyGraph to NetworkX graph for analysis"""
        try:
            import networkx as nx
        except ImportError:
            raise ImportError("NetworkX is required for graph analysis: pip install networkx")
        
        G = nx.DiGraph()
        
        # Add nodes with attributes
        for node_id, node in dependency_graph.nodes.items():
            G.add_node(node_id, 
                      node_type=node.node_type.value,
                      name=node.name,
                      sector=node.sector,
                      is_critical=node.is_critical,
                      **node.properties)
        
        # Add edges with weights
        for edge in dependency_graph.edges:
            G.add_edge(edge.source, edge.target,
                      relationship_type=edge.relationship_type,
                      weight=edge.weight,
                      **edge.properties)
        
        return G