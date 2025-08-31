"""
Risk calculation engine implementing algorithms from docs/stats.md
"""

import logging
import math
import random
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from collections import defaultdict
import asyncio

try:
    import networkx as nx
    import numpy as np
    from sklearn.cluster import AgglomerativeClustering
    from sklearn.preprocessing import StandardScaler
    HAS_ANALYSIS_LIBS = True
except ImportError:
    HAS_ANALYSIS_LIBS = False

try:
    from .models import (
        DependencyGraph, GraphNode, GraphEdge, ExtendedRisk, RiskLevel,
        RiskCalculationResult, BatchRiskResults, PropagationSimulationResult
    )
    from .config import config
except ImportError:
    from models import (
        DependencyGraph, GraphNode, GraphEdge, ExtendedRisk, RiskLevel,
        RiskCalculationResult, BatchRiskResults, PropagationSimulationResult
    )
    from config import config

logger = logging.getLogger(__name__)

class RiskCalculator:
    """Main risk calculation engine"""
    
    def __init__(self):
        if not HAS_ANALYSIS_LIBS:
            raise ImportError("Analysis libraries required: pip install networkx numpy scikit-learn")
        
        self.config = config.risk

    # Algorithm 1: Systemic Criticality and Centrality Algorithm (ACCS)
    def calculate_systemic_criticality_index(self, graph: 'nx.DiGraph', node_id: str) -> Tuple[float, Dict[str, float]]:
        """
        Calculate Índice de Criticidad Sistémica (ICS) for a node
        
        ICS = 0.3 × Normalized(Degree) + 
              0.25 × Normalized(Betweenness) + 
              0.25 × Normalized(PageRank) + 
              0.2 × Normalized(Closeness) + 
              Critical_Sector_Bonus
        """
        try:
            # Calculate centrality metrics
            degree_centrality = dict(graph.degree(weight='weight'))
            betweenness_centrality = nx.betweenness_centrality(graph, weight='weight')
            pagerank = nx.pagerank(graph, weight='weight')
            
            # Closeness centrality (handle disconnected components)
            try:
                closeness_centrality = nx.closeness_centrality(graph, distance='weight')
            except:
                # Fallback for disconnected graphs
                closeness_centrality = {node: 0.0 for node in graph.nodes()}
            
            # Normalize metrics to [0,1] range
            def normalize_dict(d: Dict[str, float]) -> Dict[str, float]:
                values = list(d.values())
                if not values or max(values) == min(values):
                    return {k: 0.0 for k in d}
                min_val, max_val = min(values), max(values)
                return {k: (v - min_val) / (max_val - min_val) for k, v in d.items()}
            
            norm_degree = normalize_dict(degree_centrality)
            norm_betweenness = normalize_dict(betweenness_centrality)
            norm_pagerank = normalize_dict(pagerank)
            norm_closeness = normalize_dict(closeness_centrality)
            
            # Get values for specific node
            if node_id not in graph.nodes():
                return 0.0, {}
            
            node_data = graph.nodes[node_id]
            sector = node_data.get('sector', 'other')
            is_critical = node_data.get('is_critical', False)
            
            # Calculate sector bonus
            sector_weight = self.config.sectoral_weights.get(sector, 1.0)
            critical_bonus = 0.5 if is_critical else 0.0
            sector_bonus = (sector_weight - 1.0) * 0.1 + critical_bonus  # Convert to bonus
            
            # Calculate ICS
            ics_components = {
                'degree': norm_degree.get(node_id, 0.0) * self.config.ics_weights['degree'],
                'betweenness': norm_betweenness.get(node_id, 0.0) * self.config.ics_weights['betweenness'],
                'pagerank': norm_pagerank.get(node_id, 0.0) * self.config.ics_weights['pagerank'],
                'closeness': norm_closeness.get(node_id, 0.0) * self.config.ics_weights['closeness'],
                'sector_bonus': sector_bonus
            }
            
            ics = sum(ics_components.values())
            
            return ics, ics_components
            
        except Exception as e:
            logger.error(f"Failed to calculate ICS for node {node_id}: {e}")
            return 0.0, {}

    # Algorithm 2: Provider Concentration Algorithm (ACP)
    def calculate_provider_concentration_risk(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """
        Calculate provider concentration risk using modified HHI
        """
        try:
            if node_id not in graph.nodes():
                return 0.0
            
            # Find all providers this node depends on
            providers = []
            for neighbor in graph.neighbors(node_id):
                edge_data = graph.get_edge_data(node_id, neighbor)
                if edge_data and edge_data.get('relationship_type') in ['USES_PROVIDER', 'DEPENDS_ON']:
                    neighbor_data = graph.nodes[neighbor]
                    if neighbor_data.get('node_type') == 'Provider':
                        weight = edge_data.get('weight', 1.0)
                        providers.append((neighbor, weight))
            
            if not providers:
                return 0.0  # No provider dependencies
            
            # Calculate market shares (weights)
            total_weight = sum(weight for _, weight in providers)
            market_shares = [weight / total_weight for _, weight in providers]
            
            # Calculate HHI (Herfindahl-Hirschman Index)
            hhi = sum(share ** 2 for share in market_shares)
            
            # Normalize and classify risk
            if hhi < 0.15:
                risk_score = 0.2  # Competitive
            elif hhi < 0.25:
                risk_score = 0.5  # Moderately concentrated  
            else:
                risk_score = 0.9  # Highly concentrated
            
            return risk_score
            
        except Exception as e:
            logger.error(f"Failed to calculate provider concentration risk for {node_id}: {e}")
            return 0.0

    # Algorithm 3: Risk Propagation Algorithm (APR) 
    def simulate_risk_propagation(self, graph: 'nx.DiGraph', initial_node: str,
                                 max_time: int = 50) -> PropagationSimulationResult:
        """
        Simulate risk propagation using epidemiological model
        States: Susceptible (S), Exposed (E), Infected (I), Recovered (R)
        """
        try:
            if initial_node not in graph.nodes():
                return PropagationSimulationResult(
                    initial_node=initial_node,
                    simulation_steps=0,
                    total_affected_nodes=0,
                    final_infection_rate=0.0
                )
            
            # Initialize states
            states = {node: 'S' for node in graph.nodes()}
            states[initial_node] = 'I'
            
            affected_nodes = {initial_node}
            cascade_paths = []
            time_to_peak = 0
            peak_infection_count = 1
            
            for t in range(max_time):
                new_states = states.copy()
                current_infected = sum(1 for state in states.values() if state == 'I')
                
                # Track peak
                if current_infected > peak_infection_count:
                    peak_infection_count = current_infected
                    time_to_peak = t
                
                for node in graph.nodes():
                    if states[node] == 'I':
                        # Infect neighbors
                        for neighbor in graph.neighbors(node):
                            if states[neighbor] == 'S':
                                edge_data = graph.get_edge_data(node, neighbor)
                                weight = edge_data.get('weight', 1.0) if edge_data else 1.0
                                
                                prob_infection = self._calculate_infection_probability(
                                    weight, self.config.propagation_base_rate, t
                                )
                                
                                if random.random() < prob_infection:
                                    new_states[neighbor] = 'E'
                                    affected_nodes.add(neighbor)
                                    cascade_paths.append([node, neighbor])
                    
                    elif states[node] == 'E':
                        # Transition to infected
                        if random.random() < self.config.incubation_rate:
                            new_states[node] = 'I'
                    
                    elif states[node] == 'I':
                        # Recover
                        if random.random() < self.config.recovery_rate:
                            new_states[node] = 'R'
                
                states = new_states
                
                # Check for convergence
                if sum(1 for state in states.values() if state in ['E', 'I']) == 0:
                    break
            
            # Calculate results
            total_affected = len(affected_nodes)
            final_infection_rate = total_affected / len(graph.nodes())
            
            # Extract affected sectors
            affected_sectors = set()
            for node in affected_nodes:
                sector = graph.nodes[node].get('sector', 'other')
                affected_sectors.add(sector)
            
            return PropagationSimulationResult(
                initial_node=initial_node,
                simulation_steps=t + 1,
                total_affected_nodes=total_affected,
                final_infection_rate=final_infection_rate,
                cascade_paths=cascade_paths[:100],  # Limit paths for memory
                time_to_peak=time_to_peak,
                recovery_time=max_time - time_to_peak if t == max_time - 1 else t - time_to_peak,
                affected_sectors=list(affected_sectors)
            )
            
        except Exception as e:
            logger.error(f"Risk propagation simulation failed for {initial_node}: {e}")
            return PropagationSimulationResult(
                initial_node=initial_node,
                simulation_steps=0,
                total_affected_nodes=0,
                final_infection_rate=0.0
            )

    def _calculate_infection_probability(self, weight: float, base_rate: float, time: int) -> float:
        """Calculate infection probability based on weight and time"""
        dependency_factor = min(weight / 10.0, 1.0)
        time_factor = 1 - math.exp(-0.1 * time)  # Exponential saturation
        return base_rate * dependency_factor * time_factor

    # Algorithm 4: Supply Chain Resilience (AECS)
    def calculate_supply_chain_resilience(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """
        Calculate Índice de Resiliencia de Cadena (IRC) for a node
        """
        try:
            if node_id not in graph.nodes():
                return 0.0
            
            # Analyze supply chain dependencies up to 3 levels deep
            supply_chain = self._analyze_supply_chain_dependencies(graph, node_id, max_depth=3)
            
            if not supply_chain:
                return 1.0  # No dependencies = perfect resilience
            
            # Calculate resilience factors
            factors = {
                'geographic_diversification': self._calculate_geographic_diversification(supply_chain),
                'provider_redundancy': self._calculate_provider_redundancy(supply_chain),
                'recovery_time': self._estimate_recovery_time(supply_chain),
                'alternatives_available': self._evaluate_alternatives(supply_chain),
                'critical_dependencies': self._evaluate_critical_dependencies(supply_chain)
            }
            
            # Chilean context weights (high geographic diversification weight)
            weights = {
                'geographic_diversification': 0.3,
                'provider_redundancy': 0.25,
                'recovery_time': 0.2,
                'alternatives_available': 0.15,
                'critical_dependencies': 0.1
            }
            
            irc = sum(factors[factor] * weights[factor] for factor in factors)
            return max(0.0, min(1.0, irc))  # Normalize to [0,1]
            
        except Exception as e:
            logger.error(f"Failed to calculate supply chain resilience for {node_id}: {e}")
            return 0.0

    def _analyze_supply_chain_dependencies(self, graph: 'nx.DiGraph', node_id: str, 
                                          max_depth: int = 3) -> List[Dict[str, Any]]:
        """Analyze multi-level supply chain dependencies"""
        dependencies = []
        visited = set()
        
        def explore_dependencies(current_node: str, depth: int = 1):
            if depth > max_depth or current_node in visited:
                return
            
            visited.add(current_node)
            
            for neighbor in graph.predecessors(current_node):  # Incoming dependencies
                edge_data = graph.get_edge_data(neighbor, current_node)
                neighbor_data = graph.nodes[neighbor]
                
                dependency = {
                    'provider': neighbor,
                    'level': depth,
                    'relationship_type': edge_data.get('relationship_type', 'UNKNOWN'),
                    'weight': edge_data.get('weight', 1.0),
                    'provider_type': neighbor_data.get('node_type', 'Unknown'),
                    'sector': neighbor_data.get('sector', 'other'),
                    'is_critical': neighbor_data.get('is_critical', False)
                }
                
                dependencies.append(dependency)
                
                # Recurse to next level
                explore_dependencies(neighbor, depth + 1)
        
        explore_dependencies(node_id)
        return dependencies

    def _calculate_geographic_diversification(self, supply_chain: List[Dict[str, Any]]) -> float:
        """Calculate geographic diversification of supply chain"""
        # Simplified: assume uniform distribution is best
        # In real implementation, use actual geographic data
        unique_providers = len(set(dep['provider'] for dep in supply_chain))
        if unique_providers <= 1:
            return 0.1  # Poor diversification
        elif unique_providers <= 3:
            return 0.5  # Moderate diversification
        else:
            return 0.9  # Good diversification

    def _calculate_provider_redundancy(self, supply_chain: List[Dict[str, Any]]) -> float:
        """Calculate provider redundancy score"""
        # Group by relationship type to see redundancy
        by_relationship = defaultdict(list)
        for dep in supply_chain:
            by_relationship[dep['relationship_type']].append(dep)
        
        redundancy_scores = []
        for rel_type, deps in by_relationship.items():
            if len(deps) > 1:
                redundancy_scores.append(min(len(deps) / 3.0, 1.0))  # Normalize
            else:
                redundancy_scores.append(0.2)  # Single point of failure
        
        return sum(redundancy_scores) / len(redundancy_scores) if redundancy_scores else 0.0

    def _estimate_recovery_time(self, supply_chain: List[Dict[str, Any]]) -> float:
        """Estimate recovery time based on supply chain complexity"""
        # More complex chains take longer to recover
        complexity_factor = len(supply_chain) / 20.0  # Normalize
        critical_deps = sum(1 for dep in supply_chain if dep['is_critical'])
        
        # Estimate in weeks (inverted for scoring)
        estimated_weeks = 1 + complexity_factor + critical_deps * 0.5
        recovery_score = max(0.0, 1.0 - estimated_weeks / 12.0)  # Normalize
        
        return recovery_score

    def _evaluate_alternatives(self, supply_chain: List[Dict[str, Any]]) -> float:
        """Evaluate availability of alternatives (simplified)"""
        # In real implementation, query for alternative providers
        critical_deps_count = sum(1 for dep in supply_chain if dep['is_critical'])
        total_deps = len(supply_chain)
        
        if total_deps == 0:
            return 1.0
        
        # Assume fewer critical dependencies means more alternatives available
        alternatives_score = 1.0 - (critical_deps_count / total_deps)
        return alternatives_score

    def _evaluate_critical_dependencies(self, supply_chain: List[Dict[str, Any]]) -> float:
        """Evaluate impact of critical dependencies"""
        critical_count = sum(1 for dep in supply_chain if dep['is_critical'])
        total_count = len(supply_chain)
        
        if total_count == 0:
            return 1.0
        
        # Lower critical dependency ratio is better
        critical_ratio = critical_count / total_count
        return 1.0 - critical_ratio

    # Algorithm 6: Critical Provider Evaluation (AEPC)
    def calculate_provider_systemic_importance(self, graph: 'nx.DiGraph', provider_id: str) -> float:
        """
        Calculate Índice de Importancia Sistémica del Proveedor (IISP)
        """
        try:
            if provider_id not in graph.nodes():
                return 0.0
            
            provider_data = graph.nodes[provider_id]
            
            # Count critical clients
            critical_clients = 0
            total_clients = 0
            
            for client in graph.successors(provider_id):  # Outgoing relationships
                client_data = graph.nodes[client]
                total_clients += 1
                if client_data.get('is_critical', False):
                    critical_clients += 1
            
            if total_clients == 0:
                return 0.0
            
            # 1. Critical market share
            critical_market_share = critical_clients / max(total_clients, 1)
            
            # 2. Substitutability (inverse of alternatives)
            # Simplified: assume fewer total clients means more substitutable
            substitutability_index = min(total_clients / 50.0, 1.0)  # Normalize
            
            # 3. Replacement time factor  
            # Simplified: based on provider type and criticality
            replacement_time_factor = 1.0 if provider_data.get('is_critical', False) else 0.5
            
            # 4. Technical complexity
            tech_complexity = 0.5  # Simplified placeholder
            
            # 5. Jurisdictional factor
            jurisdictional_factor = 0.3  # Simplified - assume some foreign dependency
            
            # Calculate IISP
            iisp = (
                0.3 * critical_market_share +
                0.25 * substitutability_index +
                0.2 * replacement_time_factor +
                0.15 * tech_complexity +
                0.1 * jurisdictional_factor
            )
            
            return iisp
            
        except Exception as e:
            logger.error(f"Failed to calculate provider importance for {provider_id}: {e}")
            return 0.0

    # Algorithm 9: National Risk Prioritization (APRN)
    def calculate_national_risk_index(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """
        Calculate Índice de Riesgo Nacional (IRN) for security prioritization
        """
        try:
            if node_id not in graph.nodes():
                return 0.0
            
            node_data = graph.nodes[node_id]
            
            components = {
                'national_criticality': self._evaluate_national_criticality(node_data),
                'foreign_dependency': self._calculate_foreign_dependency(graph, node_id),
                'response_capacity': self._evaluate_response_capacity(node_data),
                'economic_impact': self._estimate_economic_impact(graph, node_id),
                'reputational_risk': self._evaluate_reputational_risk(node_data)
            }
            
            # Weights for Chilean national priorities
            weights = {
                'national_criticality': 0.35,
                'foreign_dependency': 0.25,
                'response_capacity': 0.2,
                'economic_impact': 0.15,
                'reputational_risk': 0.05
            }
            
            irn = sum(components[comp] * weights[comp] for comp in components)
            return irn
            
        except Exception as e:
            logger.error(f"Failed to calculate national risk index for {node_id}: {e}")
            return 0.0

    def _evaluate_national_criticality(self, node_data: Dict[str, Any]) -> float:
        """Evaluate national criticality of a node"""
        is_critical = node_data.get('is_critical', False)
        sector = node_data.get('sector', 'other')
        sector_weight = self.config.sectoral_weights.get(sector, 1.0)
        
        base_score = 0.8 if is_critical else 0.3
        sector_bonus = (sector_weight - 1.0) * 0.2
        
        return min(1.0, base_score + sector_bonus)

    def _calculate_foreign_dependency(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """Calculate dependency on foreign entities"""
        # Simplified: assume some foreign dependency exists
        # In real implementation, analyze provider countries/jurisdictions
        dependencies = list(graph.predecessors(node_id))
        if not dependencies:
            return 0.0
        
        # Placeholder calculation
        foreign_deps = len(dependencies) * 0.3  # Assume 30% foreign
        foreign_ratio = foreign_deps / len(dependencies)
        
        return min(1.0, foreign_ratio)

    def _evaluate_response_capacity(self, node_data: Dict[str, Any]) -> float:
        """Evaluate local response capacity (inverted - higher capacity = lower risk)"""
        # Simplified: based on sector and size
        sector = node_data.get('sector', 'other')
        
        if sector in ['government', 'banking']:
            return 0.2  # Good response capacity
        elif sector in ['telecommunications', 'energy']:
            return 0.4  # Moderate response capacity  
        else:
            return 0.7  # Limited response capacity

    def _estimate_economic_impact(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """Estimate potential economic impact"""
        # Based on number of dependencies (simplified)
        dependents = len(list(graph.successors(node_id)))
        impact_score = min(dependents / 100.0, 1.0)  # Normalize
        
        return impact_score

    def _evaluate_reputational_risk(self, node_data: Dict[str, Any]) -> float:
        """Evaluate reputational risk to Chile"""
        sector = node_data.get('sector', 'other')
        is_critical = node_data.get('is_critical', False)
        
        if sector in ['government', 'banking'] and is_critical:
            return 0.8  # High reputational risk
        elif sector in ['telecommunications', 'energy']:
            return 0.5  # Moderate reputational risk
        else:
            return 0.2  # Low reputational risk

    # Main calculation methods
    def calculate_extended_risk(self, graph: 'nx.DiGraph', node_id: str) -> ExtendedRisk:
        """Calculate complete extended risk metrics for a node"""
        try:
            if node_id not in graph.nodes():
                return ExtendedRisk()
            
            node_data = graph.nodes[node_id]
            
            # Calculate all metrics
            ics, ics_components = self.calculate_systemic_criticality_index(graph, node_id)
            concentration_risk = self.calculate_provider_concentration_risk(graph, node_id)
            supply_chain_resilience = self.calculate_supply_chain_resilience(graph, node_id)
            national_risk = self.calculate_national_risk_index(graph, node_id)
            
            # Run propagation simulation (simplified for performance)
            propagation = self.simulate_risk_propagation(graph, node_id, max_time=10)
            cascade_potential = propagation.final_infection_rate
            
            # Determine risk level
            risk_score = (ics + concentration_risk + (1 - supply_chain_resilience) + national_risk) / 4
            
            if risk_score >= 0.8:
                risk_level = RiskLevel.CRITICAL
                classification = "Sistémicamente Crítico"
            elif risk_score >= 0.6:
                risk_level = RiskLevel.HIGH
                classification = "Alto Riesgo Sistémico"
            elif risk_score >= 0.4:
                risk_level = RiskLevel.MEDIUM
                classification = "Riesgo Moderado"
            else:
                risk_level = RiskLevel.LOW
                classification = "Bajo Riesgo"
            
            # Extract affected sectors from propagation
            affected_sectors = propagation.affected_sectors
            
            # Detect single point of failure
            single_point = self._is_single_point_of_failure(graph, node_id)
            
            # Create extended risk object
            extended_risk = ExtendedRisk(
                systemic_criticality_index=ics,
                provider_concentration_risk=concentration_risk,
                supply_chain_resilience=supply_chain_resilience,
                national_risk_index=national_risk,
                degree_centrality=ics_components.get('degree', 0.0) / self.config.ics_weights['degree'],
                betweenness_centrality=ics_components.get('betweenness', 0.0) / self.config.ics_weights['betweenness'],
                closeness_centrality=ics_components.get('closeness', 0.0) / self.config.ics_weights['closeness'],
                pagerank=ics_components.get('pagerank', 0.0) / self.config.ics_weights['pagerank'],
                risk_level=risk_level,
                systemic_classification=classification,
                critical_sectors_affected=affected_sectors,
                risk_factors=ics_components,
                cascade_potential=cascade_potential,
                single_point_of_failure=single_point,
                calculation_timestamp=datetime.now(),
                confidence_score=self._calculate_confidence_score(graph, node_id)
            )
            
            return extended_risk
            
        except Exception as e:
            logger.error(f"Failed to calculate extended risk for {node_id}: {e}")
            return ExtendedRisk()

    def _is_single_point_of_failure(self, graph: 'nx.DiGraph', node_id: str) -> bool:
        """Detect if node is a single point of failure"""
        try:
            # Create temporary graph without the node
            temp_graph = graph.copy()
            temp_graph.remove_node(node_id)
            
            # Check if removal significantly fragments the network
            original_components = nx.number_strongly_connected_components(graph)
            new_components = nx.number_strongly_connected_components(temp_graph)
            
            # If removing node increases components significantly, it's a SPOF
            return new_components > original_components * 1.5
            
        except Exception:
            return False

    def _calculate_confidence_score(self, graph: 'nx.DiGraph', node_id: str) -> float:
        """Calculate confidence in the risk calculation"""
        # Based on data completeness and graph connectivity
        node_data = graph.nodes[node_id]
        
        # Data completeness factors
        has_sector = 1.0 if node_data.get('sector') else 0.0
        has_criticality = 1.0 if 'is_critical' in node_data else 0.0
        
        # Connectivity factors
        degree = graph.degree(node_id)
        connectivity_score = min(degree / 10.0, 1.0)  # Normalize
        
        confidence = (has_sector + has_criticality + connectivity_score) / 3.0
        return confidence

    async def batch_calculate_extended_risks(self, graph: 'nx.DiGraph', 
                                           node_ids: List[str] = None) -> BatchRiskResults:
        """Calculate extended risks for multiple nodes"""
        start_time = datetime.now()
        
        if node_ids is None:
            node_ids = list(graph.nodes())
        
        results = []
        errors = []
        
        logger.info(f"Starting batch risk calculation for {len(node_ids)} nodes")
        
        # Process in batches to manage memory
        batch_size = config.batch_size
        
        for i in range(0, len(node_ids), batch_size):
            batch_ids = node_ids[i:i+batch_size]
            
            for node_id in batch_ids:
                try:
                    extended_risk = self.calculate_extended_risk(graph, node_id)
                    
                    if node_id in graph.nodes():
                        node_data = graph.nodes[node_id]
                        node_type = node_data.get('node_type', 'Unknown')
                        
                        result = RiskCalculationResult(
                            node_id=node_id,
                            node_type=node_type,
                            extended_risk=extended_risk
                        )
                        
                        results.append(result)
                    
                except Exception as e:
                    error_msg = f"Failed to calculate risk for {node_id}: {e}"
                    logger.error(error_msg)
                    errors.append({
                        'node_id': node_id,
                        'error': str(e)
                    })
            
            # Allow other tasks to run
            await asyncio.sleep(0.1)
        
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        batch_results = BatchRiskResults(
            timestamp=end_time,
            total_nodes_processed=len(node_ids),
            successful_calculations=len(results),
            failed_calculations=len(errors),
            execution_time_seconds=execution_time,
            results=results,
            errors=errors
        )
        
        logger.info(f"Batch calculation completed: {len(results)} successful, {len(errors)} failed")
        
        return batch_results