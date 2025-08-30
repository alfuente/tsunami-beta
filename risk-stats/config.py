"""
Configuration for Risk Stats Module
"""

import os
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class Neo4jConfig:
    uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user: str = os.getenv("NEO4J_USER", "neo4j")
    password: str = os.getenv("NEO4J_PASSWORD", "test.password")

@dataclass
class RiskCalculationConfig:
    # Thresholds for Chilean context
    concentration_threshold: float = 0.25  # HHI > 0.25 = highly concentrated
    foreign_dependency_threshold: float = 0.70  # > 70% = high risk
    critical_recovery_time_days: int = 7  # > 7 days = critical
    geographic_concentration_threshold: int = 3  # < 3 regions = concentrated
    
    # Centrality weights for ICS (Índice de Criticidad Sistémica)
    ics_weights: Dict[str, float] = None
    
    # Sectoral weights for Chilean economy
    sectoral_weights: Dict[str, float] = None
    
    # Risk propagation parameters
    propagation_base_rate: float = 0.1
    incubation_rate: float = 0.2
    recovery_rate: float = 0.05
    
    def __post_init__(self):
        if self.ics_weights is None:
            self.ics_weights = {
                'degree': 0.30,
                'betweenness': 0.25,
                'pagerank': 0.25,
                'closeness': 0.20
            }
        
        if self.sectoral_weights is None:
            self.sectoral_weights = {
                'banking': 3.0,          # Bancario - crítico
                'telecommunications': 2.8,  # Telecomunicaciones - crítico
                'energy': 2.7,          # Energía - crítico
                'government': 2.5,      # Gobierno - muy importante
                'mining': 2.3,          # Minería - muy importante (contexto chileno)
                'health': 2.2,          # Salud - muy importante
                'retail': 1.8,          # Retail - importante
                'education': 1.5,       # Educación - importante
                'transport': 1.7,       # Transporte - importante
                'manufacturing': 1.4,   # Manufactura - moderado
                'other': 1.0           # Otros sectores
            }

@dataclass
class SystemConfig:
    neo4j: Neo4jConfig = None
    risk: RiskCalculationConfig = None
    
    # API Configuration
    host: str = "0.0.0.0"
    port: int = int(os.getenv("PORT", "8002"))
    debug: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # Processing Configuration
    batch_size: int = 1000
    max_graph_load_size: int = 50000  # Max nodes to load in memory
    calculation_timeout: int = 300  # 5 minutes
    
    def __post_init__(self):
        if self.neo4j is None:
            self.neo4j = Neo4jConfig()
        if self.risk is None:
            self.risk = RiskCalculationConfig()

# Global configuration instance
config = SystemConfig()
