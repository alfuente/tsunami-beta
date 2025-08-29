#!/usr/bin/env python3
"""
Graph Visualization API - Backend for 3D Graph Visualization

This API provides endpoints to extract graph data from Neo4j and serve it
in formats suitable for 3D visualization with Three.js/D3.js.

Features:
- Complete graph export with configurable depth
- Domain-focused subgraphs
- Risk-based filtering and coloring
- Real-time graph updates
- Performance optimized queries
"""

from fastapi import FastAPI, HTTPException, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import json
import logging
from datetime import datetime
from neo4j import GraphDatabase
from neo4j.time import DateTime as Neo4jDateTime
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Neo4j connection configuration
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

def convert_neo4j_properties(props_dict: Dict) -> Dict:
    """Convert Neo4j properties to JSON-serializable format"""
    converted = {}
    for key, value in props_dict.items():
        if isinstance(value, Neo4jDateTime):
            # Convert Neo4j DateTime to ISO string
            converted[key] = value.iso_format()
        elif hasattr(value, 'iso_format'):  # Other Neo4j temporal types
            converted[key] = value.iso_format()
        else:
            converted[key] = value
    return converted

app = FastAPI(
    title="Graph Visualization API",
    description="Backend API for 3D graph visualization of domain security data",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class GraphNode(BaseModel):
    id: str
    label: str
    labels: List[str]
    properties: Dict[str, Any]
    size: Optional[float] = 1.0
    color: Optional[str] = "#666666"
    x: Optional[float] = None
    y: Optional[float] = None
    z: Optional[float] = None

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    properties: Dict[str, Any]
    weight: Optional[float] = 1.0
    color: Optional[str] = "#999999"

class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any]

class GraphVisualizationAPI:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        
    def get_node_color(self, node_labels: List[str], properties: Dict[str, Any]) -> str:
        """Determine node color based on node type"""
        if "Domain" in node_labels:
            return "#2E86AB"  # Blue - for all domains
        elif "Subdomain" in node_labels:
            return "#A23B72"  # Purple - for subdomains
        elif "Provider" in node_labels:
            return "#F18F01"  # Orange - for all providers
        elif "Technology" in node_labels:
            return "#C73E1D"  # Red - for technologies
        elif "Certificate" in node_labels:
            return "#28A745"  # Green - for certificates
        elif "Service" in node_labels:
            return "#6F42C1"  # Purple - for services
        elif "Vulnerability" in node_labels:
            return "#DC3545"  # Red - for vulnerabilities
        elif "Industry" in node_labels:
            return "#17A2B8"  # Teal - for industries
        elif "Organization" in node_labels:
            return "#FFC107"  # Yellow - for organizations
        else:
            return "#6C757D"  # Gray for unknown types
    
    def get_node_size(self, node_labels: List[str], properties: Dict[str, Any]) -> float:
        """Determine node size based on importance and industry category"""
        if "Domain" in node_labels:
            risk_score = properties.get("risk_score", 0)
            base_size = max(4.0, risk_score / 10)  # Size 4-10 based on risk
            
            # Apply industry-based size normalization
            fqdn = properties.get("fqdn", "")
            
            # Banking and Finance domains get consistent sizing
            if any(bank in fqdn.lower() for bank in [
                "banco", "bci.cl", "santander.cl", "itau.cl", "falabella.cl",
                "coopeuch.cl", "security.cl", "ripley.cl", "consorcio.cl"
            ]):
                return max(6.0, base_size)  # Banking domains minimum size 6
                
            # Government domains  
            elif ".gob.cl" in fqdn or fqdn in ["sii.cl", "bcentral.cl", "cmfchile.cl"]:
                return max(5.5, base_size)  # Government domains
                
            # Major telecoms
            elif fqdn in ["entel.cl", "movistar.cl", "claro.cl", "wom.cl", "vtr.com"]:
                return max(5.5, base_size)  # Telecom domains
                
            return base_size
        elif "Subdomain" in node_labels:
            return 3.0  # Doubled from 1.5
        elif "Provider" in node_labels:
            # Larger nodes for important providers
            return 4.0  # Doubled from 2.0
        elif "Technology" in node_labels:
            return 3.6  # Doubled from 1.8
        elif "Certificate" in node_labels:
            return 2.4  # Doubled from 1.2
        elif "Vulnerability" in node_labels:
            cvss_score = properties.get("cvss_score", 0)
            return max(2.0, cvss_score / 1.5)  # Size 2-6.6 based on CVSS (doubled)
        elif "Industry" in node_labels:
            return 5.0  # Large nodes for industries
        elif "Organization" in node_labels:
            return 4.5  # Large nodes for organizations
        else:
            return 2.0  # Doubled from 1.0
    
    def get_edge_color(self, relationship_type: str, properties: Dict[str, Any]) -> str:
        """Determine edge color based on relationship type"""
        color_map = {
            "HAS_SUBDOMAIN": "#44aa44",
            "USES_PROVIDER": "#4488ff",
            "USES_TECHNOLOGY": "#ffcc44", 
            "RUNS_SERVICE": "#cc44ff",
            "SECURED_BY": "#44cccc",
            "RESOLVES_TO": "#888888",
            "ISSUED_BY": "#ff8844",
            "IS_VERSION_OF": "#cccccc",
            "BELONGS_TO_INDUSTRY": "#17A2B8",
            "BELONGS_TO_ORGANIZATION": "#FFC107",
            "REFERENCES": "#FF6B6B"  # Soft coral color for content-based references
        }
        return color_map.get(relationship_type, "#999999")
    
    def execute_domain_multi_query(self, domain: str, include_vulnerabilities: bool = True) -> GraphData:
        """Execute multiple focused queries for a domain to avoid cartesian products"""
        logger.info(f"Starting multi-query execution for domain: {domain}")
        start_time = datetime.now()
        
        all_nodes = {}
        all_edges = []
        total_records = 0
        
        try:
            with self.driver.session() as session:
                # Query 1: Get the domain itself
                domain_query = "MATCH (d:Domain {fqdn: $domain}) RETURN d"
                result = session.run(domain_query, {"domain": domain})
                for record in result:
                    total_records += 1
                    d = record["d"]
                    if d:
                        node_id = str(d.id)
                        node_props = convert_neo4j_properties(dict(d))
                        node_labels = list(d.labels)
                        all_nodes[node_id] = GraphNode(
                            id=node_id,
                            label=node_props.get('fqdn', f"Node {node_id}"),
                            labels=node_labels,
                            properties=node_props,
                            size=self.get_node_size(node_labels, node_props),
                            color=self.get_node_color(node_labels, node_props)
                        )
                
                # Query 2: Get direct providers
                provider_query = """
                MATCH (d:Domain {fqdn: $domain})-[r:USES_PROVIDER]->(p:Provider)
                RETURN d, r, p
                """
                result = session.run(provider_query, {"domain": domain})
                for record in result:
                    total_records += 1
                    d, r, p = record["d"], record["r"], record["p"]
                    # Add provider node
                    if p:
                        node_id = str(p.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(p))
                            node_labels = list(p.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('name', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        # Add edge
                        if r:
                            edge_id = f"{d.id}-{r.type}-{p.id}"
                            edge_props = convert_neo4j_properties(dict(r))
                            all_edges.append(GraphEdge(
                                id=edge_id,
                                source=str(d.id),
                                target=str(p.id),
                                relationship_type=r.type,
                                properties=edge_props,
                                weight=edge_props.get('confidence', 1.0),
                                color=self.get_edge_color(r.type, edge_props)
                            ))
                
                # Query 3: Get subdomains and their providers
                subdomain_query = """
                MATCH (d:Domain {fqdn: $domain})-[:HAS_SUBDOMAIN]->(sub:Subdomain)
                OPTIONAL MATCH (sub)-[r:USES_PROVIDER]->(p:Provider)
                RETURN d, sub, r, p
                """
                result = session.run(subdomain_query, {"domain": domain})
                for record in result:
                    total_records += 1
                    d, sub, r, p = record["d"], record["sub"], record["r"], record["p"]
                    # Add subdomain node
                    if sub:
                        node_id = str(sub.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(sub))
                            node_labels = list(sub.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('fqdn', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        # Add HAS_SUBDOMAIN edge
                        subdomain_edge_id = f"{d.id}-HAS_SUBDOMAIN-{sub.id}"
                        if not any(edge.id == subdomain_edge_id for edge in all_edges):
                            all_edges.append(GraphEdge(
                                id=subdomain_edge_id,
                                source=str(d.id),
                                target=str(sub.id),
                                relationship_type="HAS_SUBDOMAIN",
                                properties={},
                                weight=1.0,
                                color=self.get_edge_color("HAS_SUBDOMAIN", {})
                            ))
                    
                    # Add provider node and edge if exists
                    if p and r:
                        node_id = str(p.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(p))
                            node_labels = list(p.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('name', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        # Add edge
                        edge_id = f"{sub.id}-{r.type}-{p.id}"
                        edge_props = convert_neo4j_properties(dict(r))
                        all_edges.append(GraphEdge(
                            id=edge_id,
                            source=str(sub.id),
                            target=str(p.id),
                            relationship_type=r.type,
                            properties=edge_props,
                            weight=edge_props.get('confidence', 1.0),
                            color=self.get_edge_color(r.type, edge_props)
                        ))
                
                # Query 4: Get technologies and services
                tech_query = """
                MATCH (d:Domain {fqdn: $domain})
                OPTIONAL MATCH (d)-[r1:USES_TECHNOLOGY]->(t:Technology)
                OPTIONAL MATCH (d)-[r2:RUNS_SERVICE]->(s:Service)  
                OPTIONAL MATCH (d)-[r3:SECURED_BY]->(c:Certificate)
                RETURN d, r1, t, r2, s, r3, c
                """
                result = session.run(tech_query, {"domain": domain})
                for record in result:
                    total_records += 1
                    d, r1, t, r2, s, r3, c = record["d"], record["r1"], record["t"], record["r2"], record["s"], record["r3"], record["c"]
                    
                    # Add technology node and edge
                    if t and r1:
                        node_id = str(t.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(t))
                            node_labels = list(t.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('name', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        edge_id = f"{d.id}-{r1.type}-{t.id}"
                        edge_props = convert_neo4j_properties(dict(r1))
                        all_edges.append(GraphEdge(
                            id=edge_id,
                            source=str(d.id),
                            target=str(t.id),
                            relationship_type=r1.type,
                            properties=edge_props,
                            weight=edge_props.get('confidence', 1.0),
                            color=self.get_edge_color(r1.type, edge_props)
                        ))
                    
                    # Add service node and edge  
                    if s and r2:
                        node_id = str(s.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(s))
                            node_labels = list(s.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('name', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        edge_id = f"{d.id}-{r2.type}-{s.id}"
                        edge_props = convert_neo4j_properties(dict(r2))
                        all_edges.append(GraphEdge(
                            id=edge_id,
                            source=str(d.id),
                            target=str(s.id),
                            relationship_type=r2.type,
                            properties=edge_props,
                            weight=edge_props.get('confidence', 1.0),
                            color=self.get_edge_color(r2.type, edge_props)
                        ))
                    
                    # Add certificate node and edge
                    if c and r3:
                        node_id = str(c.id)
                        if node_id not in all_nodes:
                            node_props = convert_neo4j_properties(dict(c))
                            node_labels = list(c.labels)
                            all_nodes[node_id] = GraphNode(
                                id=node_id,
                                label=node_props.get('subject', f"Node {node_id}"),
                                labels=node_labels,
                                properties=node_props,
                                size=self.get_node_size(node_labels, node_props),
                                color=self.get_node_color(node_labels, node_props)
                            )
                        edge_id = f"{d.id}-{r3.type}-{c.id}"
                        edge_props = convert_neo4j_properties(dict(r3))
                        all_edges.append(GraphEdge(
                            id=edge_id,
                            source=str(d.id),
                            target=str(c.id),
                            relationship_type=r3.type,
                            properties=edge_props,
                            weight=edge_props.get('confidence', 1.0),
                            color=self.get_edge_color(r3.type, edge_props)
                        ))
                
                # Query 5: Get vulnerabilities if requested
                if include_vulnerabilities:
                    vuln_query = """
                    MATCH (d:Domain {fqdn: $domain})-[:USES_TECHNOLOGY]->(t:Technology)-[r:HAS_VULNERABILITY]->(v:Vulnerability)
                    RETURN t, r, v
                    """
                    result = session.run(vuln_query, {"domain": domain})
                    for record in result:
                        total_records += 1
                        t, r, v = record["t"], record["r"], record["v"]
                        
                        if v and r:
                            node_id = str(v.id)
                            if node_id not in all_nodes:
                                node_props = convert_neo4j_properties(dict(v))
                                node_labels = list(v.labels)
                                all_nodes[node_id] = GraphNode(
                                    id=node_id,
                                    label=node_props.get('name', f"Node {node_id}"),
                                    labels=node_labels,
                                    properties=node_props,
                                    size=self.get_node_size(node_labels, node_props),
                                    color=self.get_node_color(node_labels, node_props)
                                )
                            edge_id = f"{t.id}-{r.type}-{v.id}"
                            edge_props = convert_neo4j_properties(dict(r))
                            all_edges.append(GraphEdge(
                                id=edge_id,
                                source=str(t.id),
                                target=str(v.id),
                                relationship_type=r.type,
                                properties=edge_props,
                                weight=edge_props.get('confidence', 1.0),
                                color=self.get_edge_color(r.type, edge_props)
                            ))
                
                end_time = datetime.now()
                execution_time = (end_time - start_time).total_seconds()
                
                logger.info(f"Multi-query completed in {execution_time:.2f} seconds")
                logger.info(f"Processed {total_records} records, found {len(all_nodes)} nodes and {len(all_edges)} edges")
                
                return GraphData(
                    nodes=list(all_nodes.values()),
                    edges=all_edges,
                    metadata={
                        "node_count": len(all_nodes),
                        "edge_count": len(all_edges),
                        "record_count": total_records,
                        "execution_time_seconds": execution_time,
                        "generated_at": datetime.now().isoformat(),
                        "query": "multi-query approach for domain subgraph",
                        "domain": domain
                    }
                )
                
        except Exception as e:
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            logger.error(f"Multi-query failed after {execution_time:.2f} seconds: {e}")
            raise

    def execute_graph_query(self, query: str, parameters: Dict[str, Any] = None) -> GraphData:
        """Execute a Cypher query and return formatted graph data"""
        if parameters is None:
            parameters = {}
            
        logger.info(f"Starting query execution with parameters: {parameters}")
        start_time = datetime.now()
        
        try:
            with self.driver.session() as session:
                logger.info("Neo4j session created, executing query...")
                result = session.run(query, parameters)
                logger.info("Query executed, processing results...")
                
                nodes = {}
                edges = []
                record_count = 0
                
                for record in result:
                    record_count += 1
                    if record_count % 100 == 0:
                        logger.info(f"Processed {record_count} records so far...")
                    
                    # Process ALL values in the record to find nodes
                    for key, value in record.items():
                        if value is None:
                            continue
                            
                        # Check if it's a node
                        if hasattr(value, 'labels') and hasattr(value, 'id'):
                            node_id = str(value.id)
                            if node_id not in nodes:
                                node_labels = list(value.labels)
                                node_props = convert_neo4j_properties(dict(value))
                                
                                # Create display label
                                display_label = node_props.get('fqdn', 
                                    node_props.get('name',
                                        node_props.get('title', f"Node {node_id}")))
                                
                                nodes[node_id] = GraphNode(
                                    id=node_id,
                                    label=display_label,
                                    labels=node_labels,
                                    properties=node_props,
                                    size=self.get_node_size(node_labels, node_props),
                                    color=self.get_node_color(node_labels, node_props)
                                )
                    
                        # Check if it's a relationship
                        elif hasattr(value, 'type') and hasattr(value, 'start_node') and hasattr(value, 'end_node'):
                            # Also add start and end nodes of relationships
                            for node in [value.start_node, value.end_node]:
                                node_id = str(node.id)
                                if node_id not in nodes:
                                    node_labels = list(node.labels)
                                    node_props = convert_neo4j_properties(dict(node))
                                    
                                    display_label = node_props.get('fqdn', 
                                        node_props.get('name',
                                            node_props.get('title', f"Node {node_id}")))
                                    
                                    nodes[node_id] = GraphNode(
                                        id=node_id,
                                        label=display_label,
                                        labels=node_labels,
                                        properties=node_props,
                                        size=self.get_node_size(node_labels, node_props),
                                        color=self.get_node_color(node_labels, node_props)
                                    )
                            
                            # Add the relationship
                            edge_id = f"{value.start_node.id}-{value.type}-{value.end_node.id}"
                            edge_props = convert_neo4j_properties(dict(value))
                            
                            edges.append(GraphEdge(
                                id=edge_id,
                                source=str(value.start_node.id),
                                target=str(value.end_node.id),
                                relationship_type=value.type,
                                properties=edge_props,
                                weight=edge_props.get('confidence', 1.0),
                                color=self.get_edge_color(value.type, edge_props)
                            ))
                
                # Create virtual USES_PROVIDER relationships when domains and providers exist but no USES_PROVIDER relationships
                domain_nodes = [node for node in nodes.values() if 'Domain' in node.labels]
                provider_nodes = [node for node in nodes.values() if 'Provider' in node.labels]
                existing_uses_provider = len([edge for edge in edges if edge.relationship_type == "USES_PROVIDER"])
                
                # If we have domains and providers but no USES_PROVIDER relationships, create virtual ones
                if domain_nodes and provider_nodes and existing_uses_provider == 0:
                    logger.info("Creating virtual USES_PROVIDER relationships for aggregated provider data")
                    for record in session.run(query, parameters):
                        d_node = record.get('d')
                        p_node = record.get('p')
                        if d_node and p_node:
                            virtual_edge_id = f"{d_node.id}-USES_PROVIDER-{p_node.id}"
                            # Only create if virtual doesn't exist
                            if not any(edge.id == virtual_edge_id for edge in edges):
                                edges.append(GraphEdge(
                                    id=virtual_edge_id,
                                    source=str(d_node.id),
                                    target=str(p_node.id),
                                    relationship_type="USES_PROVIDER",
                                    properties={"source": "aggregated_from_subdomains"},
                                    weight=1.0,
                                    color=self.get_edge_color("USES_PROVIDER", {})
                                ))
                
                end_time = datetime.now()
                execution_time = (end_time - start_time).total_seconds()
                
                logger.info(f"Query completed in {execution_time:.2f} seconds")
                logger.info(f"Processed {record_count} records, found {len(nodes)} nodes and {len(edges)} edges")
                
                return GraphData(
                    nodes=list(nodes.values()),
                    edges=edges,
                    metadata={
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                        "record_count": record_count,
                        "execution_time_seconds": execution_time,
                        "generated_at": datetime.now().isoformat(),
                        "query": query
                    }
                )
        except Exception as e:
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            logger.error(f"Query failed after {execution_time:.2f} seconds: {e}")
            raise

# Initialize API instance
graph_api = GraphVisualizationAPI()

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Graph Visualization API",
        "version": "1.0.0",
        "endpoints": [
            "/graph/complete - Complete graph data",
            "/graph/domain/{domain} - Domain-focused subgraph",
            "/graph/provider/{provider} - Provider-focused subgraph", 
            "/graph/risk/{level} - Risk-based filtering",
            "/stats - Graph statistics"
        ]
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    try:
        with graph_api.driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
        return {"status": "healthy", "neo4j": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/graph/complete", response_model=GraphData, tags=["Graph Data"])
async def get_complete_graph(
    limit: int = Query(500, description="Maximum number of nodes to return"),
    include_subdomains: bool = Query(True, description="Include subdomain nodes"),
    include_organizations: bool = Query(True, description="Include organization nodes"),
    include_industries: bool = Query(True, description="Include industry nodes"),
    include_references: bool = Query(False, description="Include domain REFERENCES relationships"),
    min_risk_score: float = Query(0.0, description="Minimum risk score filter")
) -> GraphData:
    """Get complete graph data with optional filtering"""
    
    logger.info(f"GET /graph/complete - limit: {limit}, include_organizations: {include_organizations}, include_industries: {include_industries}")
    
    # Build conditional query based on what to include
    optional_matches = []
    returns = ["d"]
    
    # Always include providers (core functionality) - from domain and subdomain
    optional_matches.append("OPTIONAL MATCH (d)-[r1:USES_PROVIDER]->(p:Provider)")
    optional_matches.append("OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)-[:USES_PROVIDER]->(p)")
    returns.extend(["r1", "p"])
    
    # Conditionally include industries
    if include_industries:
        optional_matches.append("OPTIONAL MATCH (d)-[r2:BELONGS_TO_INDUSTRY]->(i:Industry)")
        returns.extend(["r2", "i"])
    
    # Conditionally include organizations  
    if include_organizations:
        optional_matches.append("OPTIONAL MATCH (d)-[r3:BELONGS_TO_ORGANIZATION]->(o:Organization)")
        returns.extend(["r3", "o"])
    
    # Conditionally include domain references (REFERENCES relationships) 
    if include_references:
        optional_matches.append("OPTIONAL MATCH (d)-[r4:REFERENCES]->(ref_domain:Domain)")
        returns.extend(["r4", "ref_domain"])
    
    query = f"""
    MATCH (d:Domain)
    WHERE d.risk_score >= $min_risk_score
    AND ((d)-[:USES_PROVIDER]->() OR (d)-[:BELONGS_TO_INDUSTRY]->() OR (d)-[:BELONGS_TO_ORGANIZATION]->())
    WITH d 
    ORDER BY d.fqdn ASC
    LIMIT $limit
    
    {' '.join(optional_matches)}
    
    RETURN {', '.join(returns)}
    ORDER BY d.fqdn
    """
    
    try:
        return graph_api.execute_graph_query(query, {
            "limit": limit,
            "min_risk_score": min_risk_score
        })
    except Exception as e:
        logger.error(f"Error executing complete graph query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/domain/{domain}", response_model=GraphData, tags=["Graph Data"])
async def get_domain_subgraph(
    domain: str = Path(..., description="Domain to focus on"),
    depth: int = Query(2, description="Graph traversal depth"),
    include_vulnerabilities: bool = Query(True, description="Include vulnerability nodes")
) -> GraphData:
    """Get subgraph focused on a specific domain using multiple focused queries"""
    
    try:
        # Use the new multi-query approach
        return graph_api.execute_domain_multi_query(domain, include_vulnerabilities)
    except Exception as e:
        logger.error(f"Error executing domain subgraph query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/provider/{provider_name}", response_model=GraphData, tags=["Graph Data"])
async def get_provider_subgraph(
    provider_name: str = Path(..., description="Provider name to focus on"),
    limit: int = Query(100, description="Maximum domains per provider")
) -> GraphData:
    """Get subgraph showing all domains using a specific provider"""
    
    query = """
    MATCH (p:Provider {name: $provider_name})-[r1:USES_PROVIDER]-(d:Domain)
    WITH p, r1, d LIMIT $limit
    
    OPTIONAL MATCH (d)-[r2:HAS_SUBDOMAIN]->(s:Subdomain)
    OPTIONAL MATCH (d)-[r3:USES_TECHNOLOGY]->(t:Technology)
    
    RETURN p, d, s, t, r1, r2, r3
    """
    
    try:
        return graph_api.execute_graph_query(query, {
            "provider_name": provider_name,
            "limit": limit
        })
    except Exception as e:
        logger.error(f"Error executing provider subgraph query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/risk/{risk_level}", response_model=GraphData, tags=["Graph Data"])
async def get_risk_filtered_graph(
    risk_level: str = Path(..., description="Risk level: low, medium, high, critical"),
    limit: int = Query(200, description="Maximum number of nodes")
) -> GraphData:
    """Get graph data filtered by risk level"""
    
    risk_ranges = {
        "low": (0, 25),
        "medium": (25, 50), 
        "high": (50, 75),
        "critical": (75, 100)
    }
    
    if risk_level.lower() not in risk_ranges:
        raise HTTPException(status_code=400, detail="Invalid risk level. Use: low, medium, high, critical")
    
    min_risk, max_risk = risk_ranges[risk_level.lower()]
    
    query = """
    MATCH (d:Domain)
    WHERE d.risk_score >= $min_risk AND d.risk_score < $max_risk
    WITH d LIMIT $limit
    
    OPTIONAL MATCH (d)-[r2:USES_PROVIDER]->(p:Provider)
    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->()-[:USES_PROVIDER]->(sp:Provider)
    WITH d, t, srv, c, o, tv, r2, r3, r4, r5, r7, r8, coalesce(p, sp) as p
    OPTIONAL MATCH (d)-[r3:USES_TECHNOLOGY]->(t:Technology)
    OPTIONAL MATCH (t)-[r4:HAS_VULNERABILITY]->(v:Vulnerability)
    WHERE v.severity = CASE 
        WHEN $risk_level = 'critical' THEN 'Critical'
        WHEN $risk_level = 'high' THEN 'High' 
        ELSE v.severity
    END
    
    RETURN d, p, t, v, r2, r3, r4
    """
    
    try:
        return graph_api.execute_graph_query(query, {
            "min_risk": min_risk,
            "max_risk": max_risk,
            "limit": limit,
            "risk_level": risk_level
        })
    except Exception as e:
        logger.error(f"Error executing risk filtered query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/simple", response_model=GraphData, tags=["Graph Data"])
async def get_simple_graph(
    limit: int = Query(10, description="Maximum number of nodes to return")
) -> GraphData:
    """Get a simple graph with just domains for testing"""
    
    logger.info(f"GET /graph/simple - limit: {limit}")
    
    query = """
    MATCH (d:Domain)
    RETURN d
    LIMIT $limit
    """
    
    try:
        return graph_api.execute_graph_query(query, {"limit": limit})
    except Exception as e:
        logger.error(f"Error executing simple graph query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/industries", tags=["Data"])
async def get_industries():
    """Get all industries in the graph"""
    
    try:
        with graph_api.driver.session() as session:
            query = """
            MATCH (i:Industry)
            OPTIONAL MATCH (i)<-[:BELONGS_TO_INDUSTRY]-(d:Domain)
            WITH i, count(d) as domain_count
            // Merge Banking and Finance into single category
            WITH CASE 
                WHEN i.name IN ["Banking", "Finance"] THEN "Banking"
                ELSE i.name
            END as industry_name, sum(domain_count) as total_domains
            RETURN industry_name as name, total_domains as domain_count
            ORDER BY total_domains DESC, industry_name ASC
            """
            
            result = session.run(query)
            industries = []
            
            for record in result:
                industries.append({
                    "name": record["name"],
                    "domain_count": record["domain_count"]
                })
            
            return {
                "industries": industries,
                "total_count": len(industries),
                "generated_at": datetime.now().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Error getting industries: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/industry/{industry_name}", response_model=GraphData, tags=["Graph Data"])
async def get_industry_graph(
    industry_name: str = Path(..., description="Industry name to filter by"),
    limit: int = Query(100, description="Maximum number of domains per industry"),
    include_providers: bool = Query(True, description="Include provider relationships"),
    include_organizations: bool = Query(True, description="Include organization nodes"),
    include_industries: bool = Query(True, description="Include industry nodes"),
    include_subdomains: bool = Query(False, description="Include subdomain nodes and their relationships")
) -> GraphData:
    """Get graph data filtered by industry"""
    
    logger.info(f"GET /graph/industry/{industry_name} - limit: {limit}, include_providers: {include_providers}, include_organizations: {include_organizations}, include_industries: {include_industries}, include_subdomains: {include_subdomains}")
    
    # Build conditional query based on what to include
    optional_matches = []
    returns = ["d"]
    
    # Conditionally include providers - from domain 
    if include_providers:
        optional_matches.append("OPTIONAL MATCH (d)-[r1:USES_PROVIDER]->(p:Provider)")
        returns.extend(["r1", "p"])
    
    # Conditionally include industries (always include the source industry)
    if include_industries:
        optional_matches.append("OPTIONAL MATCH (d)-[r2:BELONGS_TO_INDUSTRY]->(i2:Industry {name: $industry_name})")
        returns.extend(["r2", "i2"])
    
    # Conditionally include organizations
    if include_organizations:
        optional_matches.append("OPTIONAL MATCH (d)-[r3:BELONGS_TO_ORGANIZATION]->(o:Organization)")
        returns.extend(["r3", "o"])
    
    # Handle Banking/Finance merge and always include providers
    if industry_name in ["Banking", "Finance"]:
        # Merge Banking and Finance into unified query
        additional_returns = returns[3:] if len(returns) > 3 else []
        additional_matches = optional_matches[1:] if len(optional_matches) > 1 else []
        
        return_clause = "d, r1, p"
        if additional_returns:
            return_clause += f", {', '.join(additional_returns)}"
            
        if include_subdomains:
            query = f"""
            // First get unique banking/finance domains with limit
            MATCH (d:Domain)-[:BELONGS_TO_INDUSTRY]->(i:Industry)
            WHERE i.name IN ["Banking", "Finance"] 
            WITH DISTINCT d
            ORDER BY d.risk_score DESC
            LIMIT $limit
            
            // Get direct providers from domain
            OPTIONAL MATCH (d)-[r1:USES_PROVIDER]->(p:Provider)
            
            // Get subdomains and their relationships
            OPTIONAL MATCH (d)-[r_sub_rel:HAS_SUBDOMAIN]->(sub:Subdomain)
            OPTIONAL MATCH (sub)-[r_sub:USES_PROVIDER]->(p_sub:Provider)
            
            {' '.join(additional_matches)}
            
            RETURN d, r1, p, r_sub_rel, sub, r_sub, p_sub{', ' + ', '.join(additional_returns) if additional_returns else ''}
            ORDER BY d.fqdn
            """
        else:
            query = f"""
            // First get unique banking/finance domains with limit
            MATCH (d:Domain)-[:BELONGS_TO_INDUSTRY]->(i:Industry)
            WHERE i.name IN ["Banking", "Finance"] 
            WITH DISTINCT d
            ORDER BY d.risk_score DESC
            LIMIT $limit
            
            // Get all unique providers (direct and from subdomains)
            OPTIONAL MATCH (d)-[:USES_PROVIDER]->(p_direct:Provider)
            OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->()-[:USES_PROVIDER]->(p_sub:Provider)
            
            WITH d, collect(DISTINCT p_direct) + collect(DISTINCT p_sub) as all_providers
            UNWIND all_providers as p
            WITH d, p WHERE p IS NOT NULL
            WITH d, p, null as r1  // Create virtual relationship
            
            {' '.join(additional_matches)}
            
            RETURN d, r1, p{', ' + ', '.join(additional_returns) if additional_returns else ''}
            ORDER BY d.fqdn
            """
    else:
        additional_returns = returns[3:] if len(returns) > 3 else []
        additional_matches = optional_matches[1:] if len(optional_matches) > 1 else []
        
        return_clause = "d, r1, p"
        if additional_returns:
            return_clause += f", {', '.join(additional_returns)}"
            
        if include_subdomains:
            query = f"""
            // First get unique domains for this industry with limit
            MATCH (i:Industry {{name: $industry_name}})<-[:BELONGS_TO_INDUSTRY]-(d:Domain)
            WITH DISTINCT d
            ORDER BY d.risk_score DESC
            LIMIT $limit
            
            // Get direct providers from domain
            OPTIONAL MATCH (d)-[r1:USES_PROVIDER]->(p:Provider)
            
            // Get subdomains and their relationships
            OPTIONAL MATCH (d)-[r_sub_rel:HAS_SUBDOMAIN]->(sub:Subdomain)
            OPTIONAL MATCH (sub)-[r_sub:USES_PROVIDER]->(p_sub:Provider)
            
            {' '.join(additional_matches)}
            
            RETURN d, r1, p, r_sub_rel, sub, r_sub, p_sub{', ' + ', '.join(additional_returns) if additional_returns else ''}
            ORDER BY d.fqdn
            """
        else:
            query = f"""
            // First get unique domains for this industry with limit
            MATCH (i:Industry {{name: $industry_name}})<-[:BELONGS_TO_INDUSTRY]-(d:Domain)
            WITH DISTINCT d
            ORDER BY d.risk_score DESC
            LIMIT $limit
            
            // Get all unique providers (direct and from subdomains)
            OPTIONAL MATCH (d)-[:USES_PROVIDER]->(p_direct:Provider)
            OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->()-[:USES_PROVIDER]->(p_sub:Provider)
            
            WITH d, collect(DISTINCT p_direct) + collect(DISTINCT p_sub) as all_providers
            UNWIND all_providers as p
            WITH d, p WHERE p IS NOT NULL
            WITH d, p, null as r1  // Create virtual relationship
            
            {' '.join(additional_matches)}
            
            RETURN d, r1, p{', ' + ', '.join(additional_returns) if additional_returns else ''}
            ORDER BY d.fqdn
            """
    
    try:
        return graph_api.execute_graph_query(query, {
            "industry_name": industry_name,
            "limit": limit
        })
    except Exception as e:
        logger.error(f"Error executing industry graph query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats", tags=["Statistics"])
async def get_graph_statistics():
    """Get comprehensive graph statistics"""
    
    try:
        with graph_api.driver.session() as session:
            # Node counts by type
            node_stats = session.run("""
            MATCH (n)
            WITH DISTINCT labels(n) as labels, COUNT(*) as count
            RETURN labels, count
            ORDER BY count DESC
            """).data()
            
            # Relationship counts by type
            rel_stats = session.run("""
            MATCH ()-[r]->()
            WITH type(r) as rel_type, COUNT(*) as count
            RETURN rel_type, count
            ORDER BY count DESC
            """).data()
            
            # Risk distribution
            risk_distribution = session.run("""
            MATCH (d:Domain)
            WHERE d.risk_score IS NOT NULL
            WITH CASE 
                WHEN d.risk_score < 25 THEN 'Low'
                WHEN d.risk_score < 50 THEN 'Medium'
                WHEN d.risk_score < 75 THEN 'High'
                ELSE 'Critical'
            END as risk_level, COUNT(*) as count
            RETURN risk_level, count
            """).data()
            
            # Provider usage
            provider_stats = session.run("""
            MATCH (p:Provider)<-[r:USES_PROVIDER]-(d:Domain)
            WITH p.name as provider, p.type as provider_type, COUNT(d) as domain_count
            RETURN provider, provider_type, domain_count
            ORDER BY domain_count DESC
            LIMIT 10
            """).data()
            
            return {
                "node_statistics": node_stats,
                "relationship_statistics": rel_stats,
                "risk_distribution": risk_distribution,
                "top_providers": provider_stats,
                "generated_at": datetime.now().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Error getting graph statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/search", response_model=GraphData, tags=["Graph Data"])
async def search_graph(
    query_string: str = Query(..., description="Search string for domains, providers, or technologies"),
    node_types: Optional[List[str]] = Query(None, description="Node types to search in"),
    limit: int = Query(50, description="Maximum results")
) -> GraphData:
    """Search graph nodes by text query"""
    
    # Default to searching all major node types
    if not node_types:
        node_types = ["Domain", "Provider", "Technology", "Service"]
    
    search_conditions = []
    for node_type in node_types:
        if node_type == "Domain":
            search_conditions.append("(d:Domain WHERE d.fqdn CONTAINS $query)")
        elif node_type == "Provider":
            search_conditions.append("(p:Provider WHERE p.name CONTAINS $query)")
        elif node_type == "Technology":
            search_conditions.append("(t:Technology WHERE t.name CONTAINS $query)")
        elif node_type == "Service":
            search_conditions.append("(s:Service WHERE s.name CONTAINS $query)")
    
    if not search_conditions:
        raise HTTPException(status_code=400, detail="No valid node types specified")
    
    search_query = " UNION ".join([f"MATCH {cond} RETURN n" for cond in search_conditions])
    
    query = f"""
    CALL {{
        {search_query.replace('n', 'd').replace('(d:Domain', '(n:Domain').replace('(p:Provider', '(n:Provider').replace('(t:Technology', '(n:Technology').replace('(s:Service', '(n:Service')}
    }}
    WITH n LIMIT $limit
    
    // Get relationships for found nodes
    OPTIONAL MATCH (n)-[r1]-(connected)
    WHERE connected:Domain OR connected:Provider OR connected:Technology OR connected:Service
    
    RETURN n, r1, connected
    """
    
    try:
        return graph_api.execute_graph_query(query, {
            "query": query_string,
            "limit": limit
        })
    except Exception as e:
        logger.error(f"Error executing search query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/graph/domain/{domain}/references", response_model=GraphData, tags=["Graph Data"])
async def get_domain_references_graph(
    domain: str = Path(..., description="Domain to get references for"),
    limit: int = Query(20, description="Maximum references to include"),
    direction: str = Query("both", description="Reference direction: 'outgoing', 'incoming', or 'both'"),
    min_confidence: float = Query(0.0, description="Minimum confidence threshold")
) -> GraphData:
    """Get graph showing domain references (REFERENCES relationships) for a specific domain"""
    
    query_parts = []
    
    if direction in ["outgoing", "both"]:
        query_parts.append(f"""
            // Outgoing references 
            MATCH (source:Domain {{fqdn: $domain}})-[r:REFERENCES]->(target:Domain)
            WHERE r.confidence >= $min_confidence
            WITH source, r, target
            LIMIT {limit}
            RETURN source as node1, target as node2, r as relationship, 'outgoing' as direction
        """)
    
    if direction in ["incoming", "both"]:
        query_parts.append(f"""
            // Incoming references
            MATCH (source:Domain)-[r:REFERENCES]->(target:Domain {{fqdn: $domain}})
            WHERE r.confidence >= $min_confidence
            WITH source, r, target
            LIMIT {limit}
            RETURN source as node1, target as node2, r as relationship, 'incoming' as direction
        """)
    
    if not query_parts:
        raise HTTPException(status_code=400, detail="Invalid direction parameter")
    
    query = " UNION ALL ".join(query_parts)
    
    try:
        return graph_api.execute_graph_query(query, {
            "domain": domain,
            "min_confidence": min_confidence
        })
    except Exception as e:
        logger.error(f"Error executing domain references query: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/graph/references/statistics", tags=["Graph Data"])
async def get_references_statistics():
    """Get statistics about REFERENCES relationships in the graph"""
    
    try:
        with graph_api.driver.session() as session:
            # Basic reference statistics
            basic_stats = session.run("""
                MATCH ()-[r:REFERENCES]->()
                RETURN count(r) as total_references,
                       avg(r.confidence) as avg_confidence,
                       collect(DISTINCT r.reference_type) as reference_types,
                       collect(DISTINCT r.reference_context) as reference_contexts
            """).single()
            
            # Top referencing domains
            top_ref_data = session.run("""
                MATCH (d:Domain)-[r:REFERENCES]->()
                RETURN d.fqdn as domain, count(r) as outgoing_references
                ORDER BY outgoing_references DESC
                LIMIT 10
            """).data()
            
            # Top referenced domains
            top_target_data = session.run("""
                MATCH ()-[r:REFERENCES]->(d:Domain)
                RETURN d.fqdn as domain, count(r) as incoming_references
                ORDER BY incoming_references DESC
                LIMIT 10
            """).data()
            
            # References by type
            by_type_data = session.run("""
                MATCH ()-[r:REFERENCES]->()
                RETURN r.reference_type as type, count(r) as count
                ORDER BY count DESC
            """).data()
            
            # References by context
            by_context_data = session.run("""
                MATCH ()-[r:REFERENCES]->()
                RETURN r.reference_context as context, count(r) as count
                ORDER BY count DESC
            """).data()
            
            return {
                "total_references": basic_stats["total_references"] if basic_stats else 0,
                "average_confidence": round(basic_stats["avg_confidence"], 3) if basic_stats and basic_stats["avg_confidence"] else 0,
                "reference_types": basic_stats["reference_types"] if basic_stats else [],
                "reference_contexts": basic_stats["reference_contexts"] if basic_stats else [],
                "top_referencing_domains": top_ref_data,
                "top_referenced_domains": top_target_data,
                "references_by_type": by_type_data,
                "references_by_context": by_context_data,
                "generated_at": datetime.now().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Error getting references statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("graph_visualization_api:app", host="0.0.0.0", port=8500, reload=True)