"""
Data models for Risk Stats calculations
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class NodeType(Enum):
    ORGANIZATION = "Organization"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    SERVICE = "Service"
    PROVIDER = "Provider"
    TECHNOLOGY = "Technology"

@dataclass
class ExtendedRisk:
    """Extended risk metrics to be stored in ext_risk property"""
    
    # Core metrics
    systemic_criticality_index: float = 0.0  # ICS - Índice de Criticidad Sistémica
    provider_concentration_risk: float = 0.0  # HHI-M risk
    supply_chain_resilience: float = 0.0     # IRC - Índice de Resiliencia de Cadena
    national_risk_index: float = 0.0         # IRN - Índice de Riesgo Nacional
    
    # Centrality metrics
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    closeness_centrality: float = 0.0
    pagerank: float = 0.0
    eigenvector_centrality: float = 0.0
    
    # Classification results
    risk_level: RiskLevel = RiskLevel.LOW
    systemic_classification: str = ""
    critical_sectors_affected: List[str] = field(default_factory=list)
    
    # Risk factors breakdown
    risk_factors: Dict[str, float] = field(default_factory=dict)
    
    # Propagation analysis
    cascade_potential: float = 0.0
    single_point_of_failure: bool = False
    cluster_risk_amplification: float = 1.0
    
    # Metadata
    calculation_timestamp: datetime = field(default_factory=datetime.now)
    algorithm_version: str = "1.0"
    confidence_score: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Neo4j storage"""
        return {
            "systemic_criticality_index": self.systemic_criticality_index,
            "provider_concentration_risk": self.provider_concentration_risk, 
            "supply_chain_resilience": self.supply_chain_resilience,
            "national_risk_index": self.national_risk_index,
            "degree_centrality": self.degree_centrality,
            "betweenness_centrality": self.betweenness_centrality,
            "closeness_centrality": self.closeness_centrality,
            "pagerank": self.pagerank,
            "eigenvector_centrality": self.eigenvector_centrality,
            "risk_level": self.risk_level.value,
            "systemic_classification": self.systemic_classification,
            "critical_sectors_affected": self.critical_sectors_affected,
            "risk_factors": self.risk_factors,
            "cascade_potential": self.cascade_potential,
            "single_point_of_failure": self.single_point_of_failure,
            "cluster_risk_amplification": self.cluster_risk_amplification,
            "calculation_timestamp": self.calculation_timestamp.isoformat(),
            "algorithm_version": self.algorithm_version,
            "confidence_score": self.confidence_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExtendedRisk':
        """Create from dictionary (from Neo4j)"""
        risk_level = RiskLevel(data.get('risk_level', 'low'))
        timestamp = datetime.fromisoformat(data.get('calculation_timestamp', datetime.now().isoformat()))
        
        return cls(
            systemic_criticality_index=data.get('systemic_criticality_index', 0.0),
            provider_concentration_risk=data.get('provider_concentration_risk', 0.0),
            supply_chain_resilience=data.get('supply_chain_resilience', 0.0),
            national_risk_index=data.get('national_risk_index', 0.0),
            degree_centrality=data.get('degree_centrality', 0.0),
            betweenness_centrality=data.get('betweenness_centrality', 0.0),
            closeness_centrality=data.get('closeness_centrality', 0.0),
            pagerank=data.get('pagerank', 0.0),
            eigenvector_centrality=data.get('eigenvector_centrality', 0.0),
            risk_level=risk_level,
            systemic_classification=data.get('systemic_classification', ''),
            critical_sectors_affected=data.get('critical_sectors_affected', []),
            risk_factors=data.get('risk_factors', {}),
            cascade_potential=data.get('cascade_potential', 0.0),
            single_point_of_failure=data.get('single_point_of_failure', False),
            cluster_risk_amplification=data.get('cluster_risk_amplification', 1.0),
            calculation_timestamp=timestamp,
            algorithm_version=data.get('algorithm_version', '1.0'),
            confidence_score=data.get('confidence_score', 1.0)
        )

@dataclass 
class GraphNode:
    """Represents a node in the dependency graph"""
    id: str
    node_type: NodeType
    name: str
    sector: Optional[str] = None
    is_critical: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)
    extended_risk: Optional[ExtendedRisk] = None

@dataclass
class GraphEdge:
    """Represents an edge in the dependency graph"""
    source: str
    target: str
    relationship_type: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DependencyGraph:
    """Complete dependency graph for calculations"""
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_node(self, node: GraphNode):
        """Add a node to the graph"""
        self.nodes[node.id] = node
    
    def add_edge(self, edge: GraphEdge):
        """Add an edge to the graph"""
        self.edges.append(edge)
    
    def get_neighbors(self, node_id: str) -> List[str]:
        """Get all neighbors of a node"""
        neighbors = []
        for edge in self.edges:
            if edge.source == node_id:
                neighbors.append(edge.target)
            elif edge.target == node_id:
                neighbors.append(edge.source)
        return neighbors

@dataclass
class RiskCalculationResult:
    """Result of a risk calculation operation"""
    node_id: str
    node_type: NodeType
    extended_risk: ExtendedRisk
    calculation_details: Dict[str, Any] = field(default_factory=dict)
    
@dataclass
class BatchRiskResults:
    """Results of batch risk calculations"""
    timestamp: datetime
    total_nodes_processed: int
    successful_calculations: int
    failed_calculations: int
    execution_time_seconds: float
    results: List[RiskCalculationResult] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_nodes_processed": self.total_nodes_processed,
            "successful_calculations": self.successful_calculations,
            "failed_calculations": self.failed_calculations,
            "execution_time_seconds": self.execution_time_seconds,
            "success_rate": self.successful_calculations / max(self.total_nodes_processed, 1),
            "results_summary": {
                "by_risk_level": self._count_by_risk_level(),
                "by_node_type": self._count_by_node_type()
            },
            "errors_summary": len(self.errors)
        }
    
    def _count_by_risk_level(self) -> Dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for result in self.results:
            counts[result.extended_risk.risk_level.value] += 1
        return counts
    
    def _count_by_node_type(self) -> Dict[str, int]:
        counts = {}
        for result in self.results:
            node_type = result.node_type.value
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts

@dataclass
class PropagationSimulationResult:
    """Result of risk propagation simulation"""
    initial_node: str
    simulation_steps: int
    total_affected_nodes: int
    final_infection_rate: float
    cascade_paths: List[List[str]] = field(default_factory=list)
    time_to_peak: int = 0
    recovery_time: int = 0
    affected_sectors: List[str] = field(default_factory=list)