#!/usr/bin/env python3
"""
Risk Stats CLI - Main entry point for risk calculations
"""

import asyncio
import logging
import json
import sys
from typing import Optional, List
from datetime import datetime
import argparse

from .neo4j_connector import Neo4jConnector
from .risk_calculator import RiskCalculator
from .config import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskStatsCLI:
    """Command line interface for Risk Stats calculations"""
    
    def __init__(self):
        self.neo4j_connector: Optional[Neo4jConnector] = None
        self.risk_calculator: Optional[RiskCalculator] = None

    async def initialize(self):
        """Initialize connections and services"""
        try:
            logger.info("Initializing Risk Stats CLI...")
            
            self.neo4j_connector = Neo4jConnector()
            self.risk_calculator = RiskCalculator()
            
            # Test connection
            stats = self.neo4j_connector.get_graph_statistics()
            total_nodes = sum(stats.get('node_counts', {}).values())
            logger.info(f"Connected to Neo4j - {total_nodes} nodes available")
            
        except Exception as e:
            logger.error(f"Failed to initialize: {e}")
            raise

    async def calculate_batch_risks(self, node_types: Optional[List[str]] = None,
                                  sectors: Optional[List[str]] = None,
                                  limit: Optional[int] = None,
                                  save_results: bool = True,
                                  output_file: Optional[str] = None) -> dict:
        """Calculate risks for multiple nodes"""
        
        logger.info("Starting batch risk calculation...")
        start_time = datetime.now()
        
        # Load dependency graph
        logger.info("Loading dependency graph from Neo4j...")
        dependency_graph = self.neo4j_connector.load_dependency_graph(
            node_types=node_types,
            limit=limit or config.max_graph_load_size
        )
        
        logger.info(f"Loaded graph with {len(dependency_graph.nodes)} nodes, {len(dependency_graph.edges)} edges")
        
        # Convert to NetworkX
        nx_graph = self.neo4j_connector.create_networkx_graph(dependency_graph)
        
        # Filter nodes by sector if specified
        target_nodes = list(nx_graph.nodes())
        
        if sectors:
            filtered_nodes = []
            for node_id in target_nodes:
                node_data = nx_graph.nodes.get(node_id, {})
                node_sector = node_data.get('sector', 'other')
                if node_sector in sectors:
                    filtered_nodes.append(node_id)
            target_nodes = filtered_nodes
            logger.info(f"Filtered to {len(target_nodes)} nodes by sector: {sectors}")
        
        # Calculate risks
        logger.info(f"Calculating extended risks for {len(target_nodes)} nodes...")
        batch_results = await self.risk_calculator.batch_calculate_extended_risks(
            nx_graph, target_nodes
        )
        
        # Save to Neo4j if requested
        if save_results:
            logger.info("Saving extended risks to Neo4j...")
            risk_data = {
                result.node_id: result.extended_risk 
                for result in batch_results.results
            }
            saved_count = self.neo4j_connector.batch_save_extended_risks(risk_data)
            logger.info(f"Saved {saved_count} extended risk records to Neo4j")
        
        # Save to file if requested
        results_dict = batch_results.to_dict()
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
        
        # Print summary
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        logger.info(f"Batch calculation completed in {execution_time:.2f}s")
        logger.info(f"Results: {batch_results.successful_calculations} successful, {batch_results.failed_calculations} failed")
        logger.info(f"Success rate: {batch_results.successful_calculations/max(batch_results.total_nodes_processed,1)*100:.1f}%")
        
        return results_dict

    async def calculate_single_risk(self, node_id: str, save_result: bool = True) -> dict:
        """Calculate risk for a single node"""
        
        logger.info(f"Calculating risk for node: {node_id}")
        
        # Load dependency graph (limited scope for single node)
        dependency_graph = self.neo4j_connector.load_dependency_graph(
            limit=config.max_graph_load_size
        )
        
        nx_graph = self.neo4j_connector.create_networkx_graph(dependency_graph)
        
        if node_id not in nx_graph.nodes():
            raise ValueError(f"Node {node_id} not found in graph")
        
        # Calculate extended risk
        extended_risk = self.risk_calculator.calculate_extended_risk(nx_graph, node_id)
        
        # Save to Neo4j if requested
        if save_result:
            success = self.neo4j_connector.save_extended_risk(node_id, extended_risk)
            if success:
                logger.info(f"Extended risk saved to Neo4j for node {node_id}")
            else:
                logger.warning(f"Failed to save extended risk to Neo4j for node {node_id}")
        
        result = {
            "node_id": node_id,
            "calculation_timestamp": datetime.now().isoformat(),
            "extended_risk": extended_risk.to_dict()
        }
        
        return result

    async def get_risk_statistics(self) -> dict:
        """Get risk calculation statistics"""
        
        logger.info("Gathering risk statistics...")
        
        # Get graph statistics
        graph_stats = self.neo4j_connector.get_graph_statistics()
        
        # Query for extended risk summary
        query = """
        MATCH (n)
        WHERE n.ext_risk IS NOT NULL
        WITH JSON_EXTRACT(n.ext_risk, '$.risk_level') as risk_level,
             JSON_EXTRACT(n.ext_risk, '$.systemic_criticality_index') as ics,
             labels(n)[0] as node_type
        RETURN risk_level, node_type, count(*) as count,
               avg(toFloat(ics)) as avg_ics,
               max(toFloat(ics)) as max_ics
        ORDER BY count DESC
        """
        
        risk_summary = self.neo4j_connector.execute_query(query)
        
        # Calculate coverage statistics
        total_nodes = sum(graph_stats.get('node_counts', {}).values())
        nodes_with_ext_risk = sum(graph_stats.get('ext_risk_coverage', {}).values())
        coverage_percentage = (nodes_with_ext_risk / total_nodes * 100) if total_nodes > 0 else 0
        
        statistics = {
            "timestamp": datetime.now().isoformat(),
            "graph_statistics": graph_stats,
            "risk_coverage": {
                "total_nodes": total_nodes,
                "nodes_with_ext_risk": nodes_with_ext_risk,
                "coverage_percentage": round(coverage_percentage, 2)
            },
            "risk_distribution": [dict(record) for record in risk_summary]
        }
        
        return statistics

    async def simulate_propagation(self, node_id: str, max_time: int = 50) -> dict:
        """Simulate risk propagation from a node"""
        
        logger.info(f"Simulating risk propagation from node: {node_id}")
        
        # Load graph
        dependency_graph = self.neo4j_connector.load_dependency_graph()
        nx_graph = self.neo4j_connector.create_networkx_graph(dependency_graph)
        
        if node_id not in nx_graph.nodes():
            raise ValueError(f"Node {node_id} not found in graph")
        
        # Run simulation
        simulation_result = self.risk_calculator.simulate_risk_propagation(
            nx_graph, node_id, max_time
        )
        
        result = {
            "initial_node": simulation_result.initial_node,
            "simulation_parameters": {
                "max_time": max_time,
                "base_infection_rate": config.risk.propagation_base_rate
            },
            "results": {
                "simulation_steps": simulation_result.simulation_steps,
                "total_affected_nodes": simulation_result.total_affected_nodes,
                "final_infection_rate": simulation_result.final_infection_rate,
                "time_to_peak": simulation_result.time_to_peak,
                "recovery_time": simulation_result.recovery_time,
                "affected_sectors": simulation_result.affected_sectors,
                "cascade_paths_count": len(simulation_result.cascade_paths)
            }
        }
        
        return result

    def cleanup(self):
        """Cleanup resources"""
        if self.neo4j_connector:
            self.neo4j_connector.close()

async def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(description="Risk Stats - Systemic risk calculations")
    parser.add_argument('command', choices=['calculate', 'single', 'stats', 'simulate'],
                       help='Command to execute')
    
    # Common arguments
    parser.add_argument('--neo4j-uri', default=config.neo4j.uri,
                       help='Neo4j URI')
    parser.add_argument('--neo4j-user', default=config.neo4j.user,
                       help='Neo4j username')  
    parser.add_argument('--neo4j-password', default=config.neo4j.password,
                       help='Neo4j password')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    # Calculate command arguments
    parser.add_argument('--node-types', nargs='+',
                       help='Node types to include (Organization, Domain, etc.)')
    parser.add_argument('--sectors', nargs='+', 
                       help='Sectors to filter by')
    parser.add_argument('--limit', type=int,
                       help='Limit number of nodes to process')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save results to Neo4j')
    
    # Single node calculation
    parser.add_argument('--node-id', help='Node ID for single calculation or simulation')
    
    # Simulation arguments
    parser.add_argument('--max-time', type=int, default=50,
                       help='Maximum simulation time steps')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Update Neo4j configuration if provided
    if args.neo4j_uri != config.neo4j.uri:
        config.neo4j.uri = args.neo4j_uri
    if args.neo4j_user != config.neo4j.user:
        config.neo4j.user = args.neo4j_user  
    if args.neo4j_password != config.neo4j.password:
        config.neo4j.password = args.neo4j_password
    
    cli = RiskStatsCLI()
    
    try:
        await cli.initialize()
        
        if args.command == 'calculate':
            # Batch calculation
            results = await cli.calculate_batch_risks(
                node_types=args.node_types,
                sectors=args.sectors,
                limit=args.limit,
                save_results=not args.no_save,
                output_file=args.output
            )
            
            if not args.output:
                print(json.dumps(results, indent=2))
        
        elif args.command == 'single':
            # Single node calculation
            if not args.node_id:
                logger.error("--node-id is required for single calculation")
                sys.exit(1)
            
            result = await cli.calculate_single_risk(
                node_id=args.node_id,
                save_result=not args.no_save
            )
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
            else:
                print(json.dumps(result, indent=2))
        
        elif args.command == 'stats':
            # Risk statistics
            stats = await cli.get_risk_statistics()
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(stats, f, indent=2, ensure_ascii=False)
            else:
                print(json.dumps(stats, indent=2))
        
        elif args.command == 'simulate':
            # Risk propagation simulation
            if not args.node_id:
                logger.error("--node-id is required for simulation")
                sys.exit(1)
            
            result = await cli.simulate_propagation(
                node_id=args.node_id,
                max_time=args.max_time
            )
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
            else:
                print(json.dumps(result, indent=2))
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(1)
    finally:
        cli.cleanup()

if __name__ == "__main__":
    asyncio.run(main())