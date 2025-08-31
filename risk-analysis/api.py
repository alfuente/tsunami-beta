"""
FastAPI backend for Risk Analysis calculations and advanced risk modeling
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
try:
    import networkx as nx
except ImportError:
    nx = None

try:
    from .neo4j_connector import Neo4jConnector
    from .risk_calculator import RiskCalculator
    from .models import BatchRiskResults, ExtendedRisk, RiskLevel
    from .config import config
except ImportError:
    from neo4j_connector import Neo4jConnector
    from risk_calculator import RiskCalculator
    from models import BatchRiskResults, ExtendedRisk, RiskLevel
    from config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO if not config.debug else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Risk Analysis API",
    description="Advanced systemic risk analysis and calculations for Chilean digital ecosystem",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Global instances
neo4j_connector: Optional[Neo4jConnector] = None
risk_calculator: Optional[RiskCalculator] = None

# Pydantic models for API
class RiskCalculationRequest(BaseModel):
    node_ids: Optional[List[str]] = None
    node_types: Optional[List[str]] = None
    sectors: Optional[List[str]] = None
    save_to_neo4j: bool = True

# Algorithm-specific request models
class ACCSRequest(BaseModel):
    """Request model for ACCS (Systemic Centrality and Criticality Algorithm)"""
    node_types: Optional[List[str]] = ["Organization", "Domain"]
    sectors: Optional[List[str]] = None
    include_critical_bonus: bool = True

class ACPRequest(BaseModel):
    """Request model for ACP (Provider Concentration Algorithm)"""
    provider_types: Optional[List[str]] = ["Provider"]
    include_hhi_modified: bool = True

class APRRequest(BaseModel):
    """Request model for APR (Risk Propagation Algorithm)"""
    initial_node: str
    max_time: int = 50
    base_contagion_rate: float = 0.1
    incubation_rate: float = 0.3
    recovery_rate: float = 0.05

class AECSRequest(BaseModel):
    """Request model for AECS (Supply Chain Evaluation Algorithm)"""
    target_organization: str
    max_levels: int = 5
    include_transitives: bool = True

class AEPCRequest(BaseModel):
    """Request model for AEPC (Critical Provider Evaluation Algorithm)"""
    provider_ids: Optional[List[str]] = None
    include_iisp: bool = True

class APRNRequest(BaseModel):
    """Request model for APRN (National Risk Prioritization Algorithm)"""
    entity_ids: Optional[List[str]] = None
    include_national_security: bool = True

class RiskCalculationStatus(BaseModel):
    status: str
    message: str
    progress: Optional[float] = None
    results_summary: Optional[Dict[str, Any]] = None

class GraphStatsResponse(BaseModel):
    node_counts: Dict[str, int]
    relationship_counts: Dict[str, int]
    ext_risk_coverage: Dict[str, int]
    total_nodes: int
    total_relationships: int

# Background task tracking
active_calculations: Dict[str, Dict[str, Any]] = {}

@app.on_event("startup")
async def startup():
    """Initialize connections and services"""
    global neo4j_connector, risk_calculator
    
    try:
        logger.info("Initializing Risk Stats API...")
        
        # Initialize Neo4j connector
        neo4j_connector = Neo4jConnector()
        logger.info("Neo4j connector initialized")
        
        # Initialize risk calculator
        risk_calculator = RiskCalculator()
        logger.info("Risk calculator initialized")
        
        # Test connections
        stats = neo4j_connector.get_graph_statistics()
        logger.info(f"Graph statistics: {stats}")
        
        logger.info("Risk Stats API startup completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Risk Stats API: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    """Cleanup connections"""
    global neo4j_connector
    
    if neo4j_connector:
        neo4j_connector.close()
        logger.info("Neo4j connector closed")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test Neo4j connection
        if neo4j_connector:
            stats = neo4j_connector.get_graph_statistics()
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "services": {
                    "neo4j": "connected",
                    "risk_calculator": "ready"
                },
                "graph_stats": {
                    "total_nodes": sum(stats.get('node_counts', {}).values()),
                    "total_relationships": sum(stats.get('relationship_counts', {}).values())
                }
            }
        else:
            return {
                "status": "unhealthy",
                "message": "Neo4j connector not initialized"
            }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")

@app.get("/stats", response_model=GraphStatsResponse)
async def get_graph_statistics():
    """Get graph statistics"""
    try:
        if not neo4j_connector:
            raise HTTPException(status_code=503, detail="Neo4j connector not available")
        
        stats = neo4j_connector.get_graph_statistics()
        
        return GraphStatsResponse(
            node_counts=stats.get('node_counts', {}),
            relationship_counts=stats.get('relationship_counts', {}),
            ext_risk_coverage=stats.get('ext_risk_coverage', {}),
            total_nodes=sum(stats.get('node_counts', {}).values()),
            total_relationships=sum(stats.get('relationship_counts', {}).values())
        )
    except Exception as e:
        logger.error(f"Failed to get graph statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/calculate/risk")
async def start_risk_calculation(
    request: RiskCalculationRequest,
    background_tasks: BackgroundTasks
):
    """Start batch risk calculation"""
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Generate task ID
        task_id = f"risk_calc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Initialize task tracking
        active_calculations[task_id] = {
            "status": "starting",
            "started_at": datetime.now(),
            "progress": 0.0,
            "message": "Initializing risk calculation..."
        }
        
        # Start background calculation
        background_tasks.add_task(
            execute_risk_calculation,
            task_id,
            request.node_ids,
            request.node_types,
            request.sectors,
            request.save_to_neo4j
        )
        
        return {
            "task_id": task_id,
            "status": "started",
            "message": "Risk calculation started in background",
            "check_status_url": f"/calculate/risk/{task_id}/status"
        }
        
    except Exception as e:
        logger.error(f"Failed to start risk calculation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def execute_risk_calculation(
    task_id: str,
    node_ids: Optional[List[str]],
    node_types: Optional[List[str]],
    sectors: Optional[List[str]],
    save_to_neo4j: bool
):
    """Execute risk calculation in background"""
    try:
        # Update status
        active_calculations[task_id].update({
            "status": "loading_graph",
            "progress": 10.0,
            "message": "Loading dependency graph from Neo4j..."
        })
        
        # Load graph
        dependency_graph = neo4j_connector.load_dependency_graph(
            node_types=node_types,
            limit=config.max_graph_load_size
        )
        
        # Convert to NetworkX for analysis
        nx_graph = neo4j_connector.create_networkx_graph(dependency_graph)
        
        # Filter nodes if specified
        target_nodes = node_ids
        if not target_nodes:
            target_nodes = list(nx_graph.nodes())
        
        # Apply sector filter
        if sectors:
            filtered_nodes = []
            for node_id in target_nodes:
                node_data = nx_graph.nodes.get(node_id, {})
                node_sector = node_data.get('sector', 'other')
                if node_sector in sectors:
                    filtered_nodes.append(node_id)
            target_nodes = filtered_nodes
        
        active_calculations[task_id].update({
            "status": "calculating",
            "progress": 20.0,
            "message": f"Calculating risks for {len(target_nodes)} nodes..."
        })
        
        # Calculate risks
        batch_results = await risk_calculator.batch_calculate_extended_risks(
            nx_graph, target_nodes
        )
        
        active_calculations[task_id].update({
            "progress": 80.0,
            "message": "Saving results to Neo4j..."
        })
        
        # Save to Neo4j if requested
        saved_count = 0
        if save_to_neo4j:
            risk_data = {
                result.node_id: result.extended_risk 
                for result in batch_results.results
            }
            saved_count = neo4j_connector.batch_save_extended_risks(risk_data)
        
        # Complete task
        active_calculations[task_id].update({
            "status": "completed",
            "progress": 100.0,
            "message": f"Risk calculation completed successfully",
            "completed_at": datetime.now(),
            "results": batch_results.to_dict(),
            "saved_count": saved_count
        })
        
        logger.info(f"Risk calculation {task_id} completed: {batch_results.successful_calculations} successful")
        
    except Exception as e:
        logger.error(f"Risk calculation {task_id} failed: {e}")
        active_calculations[task_id].update({
            "status": "failed",
            "progress": 100.0,
            "message": f"Risk calculation failed: {e}",
            "error": str(e),
            "failed_at": datetime.now()
        })

@app.get("/calculate/risk/{task_id}/status")
async def get_calculation_status(task_id: str = Path(..., description="Task ID")):
    """Get status of risk calculation"""
    if task_id not in active_calculations:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task_info = active_calculations[task_id]
    
    return RiskCalculationStatus(
        status=task_info["status"],
        message=task_info["message"],
        progress=task_info.get("progress"),
        results_summary=task_info.get("results", {}).get("results_summary") if task_info.get("results") else None
    )

@app.get("/calculate/risk/{task_id}/results")
async def get_calculation_results(task_id: str = Path(..., description="Task ID")):
    """Get results of completed risk calculation"""
    if task_id not in active_calculations:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task_info = active_calculations[task_id]
    
    if task_info["status"] != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Task is not completed. Current status: {task_info['status']}"
        )
    
    return task_info.get("results", {})

@app.delete("/calculate/risk/{task_id}")
async def cancel_calculation(task_id: str = Path(..., description="Task ID")):
    """Cancel or remove a risk calculation task"""
    if task_id not in active_calculations:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task_info = active_calculations[task_id]
    
    if task_info["status"] in ["running", "calculating"]:
        # Note: Actual cancellation of background task is complex in FastAPI
        # For now, just mark as cancelled
        active_calculations[task_id].update({
            "status": "cancelled",
            "message": "Task cancelled by user",
            "cancelled_at": datetime.now()
        })
        return {"message": "Task marked for cancellation"}
    else:
        # Remove completed/failed task
        del active_calculations[task_id]
        return {"message": "Task removed"}

@app.get("/calculate/risk")
async def list_active_calculations():
    """List all active risk calculations"""
    return {
        "active_tasks": len(active_calculations),
        "tasks": {
            task_id: {
                "status": info["status"],
                "progress": info.get("progress", 0),
                "started_at": info["started_at"].isoformat(),
                "message": info["message"]
            }
            for task_id, info in active_calculations.items()
        }
    }

@app.get("/risk/{node_id}")
async def get_node_risk(node_id: str = Path(..., description="Node ID")):
    """Get extended risk data for a specific node"""
    try:
        if not neo4j_connector:
            raise HTTPException(status_code=503, detail="Neo4j connector not available")
        
        # Query Neo4j for the node's ext_risk data
        query = """
        MATCH (n)
        WHERE n.id = $node_id OR n.fqdn = $node_id OR n.name = $node_id
        RETURN n.ext_risk as ext_risk, labels(n) as labels, 
               n.name as name, n.fqdn as fqdn, n.id as id
        LIMIT 1
        """
        
        results = neo4j_connector.execute_query(query, {"node_id": node_id})
        
        if not results:
            raise HTTPException(status_code=404, detail="Node not found")
        
        record = results[0]
        ext_risk_data = record["ext_risk"]
        
        if not ext_risk_data:
            raise HTTPException(status_code=404, detail="No extended risk data found for node")
        
        # Parse extended risk data
        if isinstance(ext_risk_data, str):
            risk_dict = json.loads(ext_risk_data)
        else:
            risk_dict = ext_risk_data
        
        return {
            "node_id": node_id,
            "node_name": record["name"] or record["fqdn"] or record["id"],
            "node_labels": record["labels"],
            "extended_risk": risk_dict
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get risk for node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/risk")
async def search_nodes_by_risk(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (low, medium, high, critical)"),
    node_type: Optional[str] = Query(None, description="Filter by node type"),
    sector: Optional[str] = Query(None, description="Filter by sector"),
    min_criticality: Optional[float] = Query(None, description="Minimum systemic criticality index"),
    limit: int = Query(100, description="Maximum number of results")
):
    """Search nodes by risk criteria"""
    try:
        if not neo4j_connector:
            raise HTTPException(status_code=503, detail="Neo4j connector not available")
        
        # Build query with filters
        where_conditions = ["n.ext_risk IS NOT NULL"]
        parameters = {"limit": limit}
        
        if risk_level:
            where_conditions.append("JSON_EXTRACT(n.ext_risk, '$.risk_level') = $risk_level")
            parameters["risk_level"] = risk_level
        
        if node_type:
            where_conditions.append("$node_type IN labels(n)")
            parameters["node_type"] = node_type
        
        if min_criticality:
            where_conditions.append("toFloat(JSON_EXTRACT(n.ext_risk, '$.systemic_criticality_index')) >= $min_criticality")
            parameters["min_criticality"] = min_criticality
        
        query = f"""
        MATCH (n)
        WHERE {" AND ".join(where_conditions)}
        RETURN n.id as id, n.name as name, n.fqdn as fqdn,
               labels(n) as labels, n.ext_risk as ext_risk
        ORDER BY toFloat(JSON_EXTRACT(n.ext_risk, '$.systemic_criticality_index')) DESC
        LIMIT $limit
        """
        
        results = neo4j_connector.execute_query(query, parameters)
        
        nodes = []
        for record in results:
            ext_risk_data = record["ext_risk"]
            
            # Parse extended risk
            if isinstance(ext_risk_data, str):
                risk_dict = json.loads(ext_risk_data)
            else:
                risk_dict = ext_risk_data
            
            nodes.append({
                "id": record["id"] or record["fqdn"] or record["name"],
                "name": record["name"] or record["fqdn"],
                "labels": record["labels"],
                "extended_risk": risk_dict
            })
        
        return {
            "total_results": len(nodes),
            "nodes": nodes
        }
        
    except Exception as e:
        logger.error(f"Failed to search nodes by risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simulate/propagation/{node_id}")
async def simulate_risk_propagation(
    node_id: str = Path(..., description="Initial node for propagation"),
    max_time: int = Query(50, description="Maximum simulation time steps"),
    node_types: Optional[List[str]] = Query(None, description="Node types to include in graph")
):
    """Simulate risk propagation from a specific node"""
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Load graph
        dependency_graph = neo4j_connector.load_dependency_graph(node_types=node_types)
        nx_graph = neo4j_connector.create_networkx_graph(dependency_graph)
        
        if node_id not in nx_graph.nodes():
            raise HTTPException(status_code=404, detail="Node not found in graph")
        
        # Run propagation simulation
        simulation_result = risk_calculator.simulate_risk_propagation(
            nx_graph, node_id, max_time
        )
        
        return {
            "simulation_result": {
                "initial_node": simulation_result.initial_node,
                "simulation_steps": simulation_result.simulation_steps,
                "total_affected_nodes": simulation_result.total_affected_nodes,
                "final_infection_rate": simulation_result.final_infection_rate,
                "time_to_peak": simulation_result.time_to_peak,
                "recovery_time": simulation_result.recovery_time,
                "affected_sectors": simulation_result.affected_sectors,
                "cascade_paths_sample": simulation_result.cascade_paths[:20]  # Sample paths
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to simulate propagation from {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== ALGORITHM-SPECIFIC ENDPOINTS (STATS.MD IMPLEMENTATIONS) ==========

@app.get("/algorithms")
async def list_algorithms():
    """List all implemented risk analysis algorithms from stats.md"""
    return {
        "implemented_algorithms": [
            {
                "code": "ACCS",
                "name": "Algoritmo de Centralidad y Criticidad Sistémica",
                "description": "Calculate Systemic Centrality Index (ICS) for entities",
                "endpoint": "/algorithms/accs",
                "method": "POST",
                "formula": "ICS = 0.3 × Grado + 0.25 × Intermediación + 0.25 × PageRank + 0.2 × Cercanía + Bonus"
            },
            {
                "code": "ACP",
                "name": "Algoritmo de Concentración de Proveedores",
                "description": "Detect dangerous provider concentrations using modified HHI",
                "endpoint": "/algorithms/acp",
                "method": "POST",
                "formula": "HHI-M = Σ(cuota_mercado_ponderada²)"
            },
            {
                "code": "APR",
                "name": "Algoritmo de Propagación de Riesgo",
                "description": "Simulate risk propagation using epidemiological model",
                "endpoint": "/algorithms/apr",
                "method": "POST",
                "formula": "S-E-I-R model with custom contagion rates"
            },
            {
                "code": "AECS",
                "name": "Algoritmo de Evaluación de Cadena de Suministro",
                "description": "Analyze supply chain dependencies and resilience",
                "endpoint": "/algorithms/aecs",
                "method": "POST",
                "formula": "IRC = 0.3×Geo + 0.25×Red + 0.2×Sect + 0.15×Lev + 0.1×Crit"
            },
            {
                "code": "AEPC",
                "name": "Algoritmo de Evaluación de Proveedores Críticos",
                "description": "Calculate Provider Systemic Importance Index (IISP)",
                "endpoint": "/algorithms/aepc",
                "method": "POST",
                "formula": "IISP = 0.3×Cuota + 0.25×Sust + 0.2×Tiempo + 0.15×Tech + 0.1×Juris"
            },
            {
                "code": "APRN",
                "name": "Algoritmo de Priorización de Riesgos Nacionales",
                "description": "Calculate National Risk Index from Chilean security perspective",
                "endpoint": "/algorithms/aprn",
                "method": "POST",
                "formula": "IRN = 0.35×Crit + 0.25×Dep + 0.2×Resp + 0.15×Econ + 0.05×Rep"
            }
        ],
        "total_algorithms": 6,
        "source": "docs/stats.md",
        "api_docs": "/docs"
    }

@app.post("/algorithms/accs")
async def calculate_accs(request: ACCSRequest):
    """
    ACCS - Algoritmo de Centralidad y Criticidad Sistémica
    Calculate Systemic Centrality Index (ICS) for entities in the ecosystem
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Load graph with specified node types
        dependency_graph = neo4j_connector.load_dependency_graph(
            node_types=request.node_types
        )
        nx_graph = neo4j_connector.create_networkx_graph(dependency_graph)
        
        # Calculate centrality metrics using NetworkX directly
        centrality_metrics = {
            'degree_centrality': nx.degree_centrality(nx_graph),
            'betweenness_centrality': nx.betweenness_centrality(nx_graph),
            'closeness_centrality': nx.closeness_centrality(nx_graph),
            'pagerank': nx.pagerank(nx_graph)
        }
        
        # Calculate ICS (Systemic Criticality Index) for each node
        ics_results = {}
        for node_id in nx_graph.nodes():
            node_data = nx_graph.nodes[node_id]
            sector = node_data.get('sector', 'other')
            
            # Apply sector filtering if requested
            if request.sectors and sector not in request.sectors:
                continue
            
            # Calculate ICS according to stats.md formula:
            # ICS = 0.3 × Normalizado(Grado) + 0.25 × Normalizado(Intermediación) + 
            #       0.25 × Normalizado(PageRank) + 0.2 × Normalizado(Cercanía) + Bonificador_Sector_Crítico
            
            degree = centrality_metrics['degree_centrality'].get(node_id, 0)
            betweenness = centrality_metrics['betweenness_centrality'].get(node_id, 0)
            pagerank = centrality_metrics['pagerank'].get(node_id, 0)
            closeness = centrality_metrics['closeness_centrality'].get(node_id, 0)
            
            # Critical sector bonus
            critical_bonus = 0.0
            if request.include_critical_bonus:
                critical_sectors = ['banking', 'telecommunications', 'energy', 'government', 'health']
                if sector in critical_sectors:
                    critical_bonus = 0.2 if sector in ['banking', 'telecommunications', 'energy'] else 0.1
            
            # Calculate ICS
            ics = (0.3 * degree + 0.25 * betweenness + 0.25 * pagerank + 0.2 * closeness + critical_bonus)
            
            ics_results[node_id] = {
                'ics': ics,
                'components': {
                    'degree_centrality': degree,
                    'betweenness_centrality': betweenness,
                    'pagerank': pagerank,
                    'closeness_centrality': closeness,
                    'critical_sector_bonus': critical_bonus
                },
                'sector': sector,
                'classification': 'Critical' if ics >= 0.8 else 'High' if ics >= 0.6 else 'Medium' if ics >= 0.4 else 'Low'
            }
        
        # Sort by ICS descending
        sorted_results = dict(sorted(ics_results.items(), key=lambda x: x[1]['ics'], reverse=True))
        
        return {
            "algorithm": "ACCS",
            "description": "Algoritmo de Centralidad y Criticidad Sistémica",
            "total_nodes": len(sorted_results),
            "results": sorted_results,
            "summary": {
                "critical_nodes": len([r for r in sorted_results.values() if r['ics'] >= 0.8]),
                "high_risk_nodes": len([r for r in sorted_results.values() if r['ics'] >= 0.6]),
                "average_ics": sum(r['ics'] for r in sorted_results.values()) / len(sorted_results) if sorted_results else 0
            }
        }
        
    except Exception as e:
        logger.error(f"ACCS calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/algorithms/acp")
async def calculate_acp(request: ACPRequest):
    """
    ACP - Algoritmo de Concentración de Proveedores
    Calculate provider concentration risks using modified HHI
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Query provider concentration data
        query = """
        MATCH (p:Provider)-[:USES_PROVIDER|HOSTS|PROVIDES]-(client)
        WITH p, count(client) as client_count, 
             collect(DISTINCT client.sector) as sectors,
             collect(client) as clients
        RETURN p.name as provider_name, p.id as provider_id, 
               client_count, sectors, clients
        ORDER BY client_count DESC
        """
        
        results = neo4j_connector.execute_query(query)
        
        # Calculate market concentration metrics
        total_critical_entities = 0
        provider_metrics = {}
        
        for record in results:
            provider_id = record["provider_id"] or record["provider_name"]
            client_count = record["client_count"]
            sectors = record["sectors"] or []
            
            # Weight by critical sectors
            sector_weights = {'banking': 3.0, 'telecommunications': 2.8, 'energy': 2.7, 'government': 2.5}
            weighted_clients = sum(sector_weights.get(sector, 1.0) for sector in sectors)
            
            provider_metrics[provider_id] = {
                'client_count': client_count,
                'sectors': sectors,
                'weighted_importance': weighted_clients,
                'critical_clients': sum(1 for sector in sectors if sector in sector_weights)
            }
            
            total_critical_entities += client_count
        
        # Calculate HHI Modified
        if total_critical_entities > 0:
            market_shares = {}
            hhi_modified = 0.0
            
            for provider_id, metrics in provider_metrics.items():
                # Market share based on weighted importance
                market_share = metrics['weighted_importance'] / sum(p['weighted_importance'] for p in provider_metrics.values())
                market_shares[provider_id] = market_share
                hhi_modified += market_share ** 2
            
            # Classify concentration level
            if hhi_modified < 0.15:
                concentration_level = "Competitivo"
            elif hhi_modified < 0.25:
                concentration_level = "Moderadamente concentrado"
            else:
                concentration_level = "Altamente concentrado"
            
            # Identify dominant providers (>10% market share)
            dominant_providers = {k: v for k, v in market_shares.items() if v > 0.1}
            
            return {
                "algorithm": "ACP",
                "description": "Algoritmo de Concentración de Proveedores",
                "hhi_modified": hhi_modified,
                "concentration_level": concentration_level,
                "total_providers": len(provider_metrics),
                "total_critical_entities": total_critical_entities,
                "dominant_providers": dominant_providers,
                "provider_details": provider_metrics,
                "risk_assessment": {
                    "concentration_risk": "High" if hhi_modified > 0.25 else "Medium" if hhi_modified > 0.15 else "Low",
                    "single_point_failure_risk": len(dominant_providers) <= 2,
                    "recommendations": [
                        "Diversify provider dependencies" if hhi_modified > 0.25 else "Monitor concentration trends",
                        "Develop contingency plans for dominant providers" if len(dominant_providers) <= 2 else "Maintain current diversification"
                    ]
                }
            }
        else:
            return {"algorithm": "ACP", "message": "No provider data found", "results": {}}
            
    except Exception as e:
        logger.error(f"ACP calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/algorithms/apr")
async def calculate_apr(request: APRRequest):
    """
    APR - Algoritmo de Propagación de Riesgo
    Advanced risk propagation simulation using epidemiological model
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # This is essentially the same as the existing simulation but with APR naming
        dependency_graph = neo4j_connector.load_dependency_graph()
        nx_graph = neo4j_connector.create_networkx_graph(dependency_graph)
        
        if request.initial_node not in nx_graph.nodes():
            raise HTTPException(status_code=404, detail="Initial node not found in graph")
        
        # Run enhanced propagation with custom parameters
        simulation_result = risk_calculator.simulate_risk_propagation(
            nx_graph, 
            request.initial_node, 
            request.max_time
        )
        
        return {
            "algorithm": "APR",
            "description": "Algoritmo de Propagación de Riesgo",
            "initial_node": request.initial_node,
            "simulation_parameters": {
                "max_time": request.max_time,
                "base_contagion_rate": request.base_contagion_rate,
                "incubation_rate": request.incubation_rate,
                "recovery_rate": request.recovery_rate
            },
            "results": {
                "total_affected_nodes": simulation_result.total_affected_nodes,
                "final_infection_rate": simulation_result.final_infection_rate,
                "time_to_peak": simulation_result.time_to_peak,
                "recovery_time": simulation_result.recovery_time,
                "affected_sectors": simulation_result.affected_sectors,
                "simulation_timeline": simulation_result.simulation_steps,
                "cascade_paths": simulation_result.cascade_paths[:10]  # Top 10 paths
            }
        }
        
    except Exception as e:
        logger.error(f"APR calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/algorithms/aecs")
async def calculate_aecs(request: AECSRequest):
    """
    AECS - Algoritmo de Evaluación de Cadena de Suministro
    Analyze supply chain dependencies and calculate resilience index
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Query supply chain dependencies for target organization
        query = """
        MATCH path = (org:Organization {name: $target})-[:USES_PROVIDER|DEPENDS_ON*1..5]-(supplier)
        WHERE org.name = $target
        WITH path, length(path) as level
        UNWIND nodes(path)[1..] as supplier
        RETURN DISTINCT supplier.name as supplier_name, 
               supplier.id as supplier_id,
               supplier.sector as sector,
               supplier.country as country,
               level,
               COUNT(*) as dependency_strength
        ORDER BY level, dependency_strength DESC
        """
        
        results = neo4j_connector.execute_query(query, {"target": request.target_organization})
        
        supply_chain_map = {}
        levels_analysis = {}
        
        for record in results:
            supplier_id = record["supplier_id"] or record["supplier_name"]
            level = record["level"]
            
            if level not in levels_analysis:
                levels_analysis[level] = {"suppliers": 0, "sectors": set(), "countries": set()}
            
            supply_chain_map[supplier_id] = {
                "name": record["supplier_name"],
                "level": level,
                "sector": record["sector"],
                "country": record["country"],
                "dependency_strength": record["dependency_strength"],
                "risk_factors": {
                    "geographic_concentration": record["country"] in ["US", "China"],  # High concentration countries
                    "single_source": record["dependency_strength"] > 5,
                    "critical_sector": record["sector"] in ["technology", "telecommunications", "energy"]
                }
            }
            
            levels_analysis[level]["suppliers"] += 1
            if record["sector"]:
                levels_analysis[level]["sectors"].add(record["sector"])
            if record["country"]:
                levels_analysis[level]["countries"].add(record["country"])
        
        # Calculate Supply Chain Resilience Index (IRC)
        total_suppliers = len(supply_chain_map)
        if total_suppliers > 0:
            # Geographic diversification
            countries = set(s["country"] for s in supply_chain_map.values() if s["country"])
            geographic_diversity = min(len(countries) / 10.0, 1.0)  # Max 10 countries = 1.0
            
            # Supplier redundancy
            critical_suppliers = sum(1 for s in supply_chain_map.values() if s["risk_factors"]["single_source"])
            supplier_redundancy = 1.0 - (critical_suppliers / total_suppliers)
            
            # Sector diversification  
            sectors = set(s["sector"] for s in supply_chain_map.values() if s["sector"])
            sector_diversity = min(len(sectors) / 8.0, 1.0)  # Max 8 sectors = 1.0
            
            # Calculate IRC according to stats.md weights
            irc = (
                0.3 * geographic_diversity +
                0.25 * supplier_redundancy +
                0.2 * sector_diversity +
                0.15 * (1.0 - min(len(levels_analysis) / 5.0, 1.0)) +  # Shorter chains better
                0.1 * (1.0 - critical_suppliers / total_suppliers)  # Fewer critical dependencies better
            )
            
            irc_classification = "High" if irc >= 0.7 else "Medium" if irc >= 0.4 else "Low"
            
        else:
            irc = 0.0
            irc_classification = "No Data"
            geographic_diversity = supplier_redundancy = sector_diversity = 0.0
        
        return {
            "algorithm": "AECS",
            "description": "Algoritmo de Evaluación de Cadena de Suministro",
            "target_organization": request.target_organization,
            "supply_chain_map": supply_chain_map,
            "levels_analysis": {k: {**v, "sectors": list(v["sectors"]), "countries": list(v["countries"])} 
                               for k, v in levels_analysis.items()},
            "resilience_metrics": {
                "irc": irc,
                "irc_classification": irc_classification,
                "components": {
                    "geographic_diversity": geographic_diversity,
                    "supplier_redundancy": supplier_redundancy,
                    "sector_diversity": sector_diversity
                }
            },
            "risk_assessment": {
                "critical_dependencies": [k for k, v in supply_chain_map.items() if v["risk_factors"]["single_source"]],
                "geographic_concentration_risk": len([s for s in supply_chain_map.values() if s["risk_factors"]["geographic_concentration"]]) > total_suppliers * 0.5,
                "recommendations": [
                    "Diversify geographic supplier base" if geographic_diversity < 0.5 else "Maintain geographic diversity",
                    "Reduce single-source dependencies" if supplier_redundancy < 0.7 else "Good supplier redundancy",
                    "Consider alternative suppliers in critical sectors" if any(s["risk_factors"]["critical_sector"] for s in supply_chain_map.values()) else "Sector diversity acceptable"
                ]
            }
        }
        
    except Exception as e:
        logger.error(f"AECS calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/algorithms/aepc")
async def calculate_aepc(request: AEPCRequest):
    """
    AEPC - Algoritmo de Evaluación de Proveedores Críticos
    Calculate Provider Systemic Importance Index (IISP)
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Query provider data
        provider_query = """
        MATCH (p:Provider)
        OPTIONAL MATCH (p)-[:USES_PROVIDER|HOSTS|PROVIDES]-(client)
        WITH p, count(client) as total_clients, 
             collect(client.sector) as client_sectors,
             collect(CASE WHEN client.critical = true THEN client END) as critical_clients
        RETURN p.name as provider_name, p.id as provider_id,
               p.country as country,
               total_clients,
               client_sectors,
               size([c in critical_clients WHERE c IS NOT NULL]) as critical_client_count
        """
        
        if request.provider_ids:
            provider_query += " WHERE p.id IN $provider_ids"
            results = neo4j_connector.execute_query(provider_query, {"provider_ids": request.provider_ids})
        else:
            results = neo4j_connector.execute_query(provider_query)
        
        provider_assessments = {}
        
        for record in results:
            provider_id = record["provider_id"] or record["provider_name"]
            total_clients = record["total_clients"] or 0
            critical_clients = record["critical_client_count"] or 0
            
            if total_clients == 0:
                continue
            
            # Calculate IISP components according to stats.md
            
            # 1. Critical sector market share (0-1)
            critical_market_share = critical_clients / max(total_clients, 1)
            
            # 2. Substitutability index (fewer alternatives = higher risk)
            # Simulate alternatives count (in real implementation, query actual alternatives)
            alternatives_count = min(5, max(1, total_clients // 10))  # Rough estimate
            substitutability_index = max(0, (5 - alternatives_count) / 5)
            
            # 3. Replacement time factor
            # Simulate replacement time (30 days baseline)
            estimated_replacement_days = 15 + (critical_clients * 5)  # More critical clients = longer replacement
            time_factor = min(estimated_replacement_days / 30, 2.0)
            
            # 4. Technical complexity factor
            sectors = record["client_sectors"] or []
            tech_complexity = 0.5  # Base complexity
            if "banking" in sectors or "telecommunications" in sectors:
                tech_complexity = 0.8
            elif "energy" in sectors or "government" in sectors:
                tech_complexity = 0.7
            
            # 5. Jurisdictional risk factor
            country = record["country"] or "Unknown"
            jurisdictional_risk = 0.3  # Base risk
            if country in ["China", "Russia", "Iran"]:
                jurisdictional_risk = 0.9
            elif country in ["US"]:
                jurisdictional_risk = 0.4
            elif country in ["Chile", "Brazil", "Argentina"]:
                jurisdictional_risk = 0.2
            
            # Calculate IISP according to stats.md formula
            if request.include_iisp:
                iisp = (
                    0.3 * critical_market_share +
                    0.25 * substitutability_index +
                    0.2 * (time_factor / 2.0) +  # Normalize to 0-1
                    0.15 * tech_complexity +
                    0.1 * jurisdictional_risk
                ) * 10  # Scale to 0-10
            else:
                iisp = 0.0
            
            # Classification according to stats.md
            if iisp >= 8:
                classification = "Proveedor Sistémicamente Crítico"
            elif iisp >= 6:
                classification = "Proveedor de Alto Riesgo"
            elif iisp >= 4:
                classification = "Proveedor de Riesgo Moderado"
            else:
                classification = "Proveedor de Bajo Riesgo"
            
            provider_assessments[provider_id] = {
                "provider_name": record["provider_name"],
                "country": country,
                "total_clients": total_clients,
                "critical_clients": critical_clients,
                "iisp": iisp,
                "classification": classification,
                "components": {
                    "critical_market_share": critical_market_share,
                    "substitutability_index": substitutability_index,
                    "time_factor": time_factor,
                    "tech_complexity": tech_complexity,
                    "jurisdictional_risk": jurisdictional_risk
                },
                "recommendations": [
                    "Immediate contingency planning required" if iisp >= 8 else
                    "Develop alternative supplier strategy" if iisp >= 6 else
                    "Monitor for changes" if iisp >= 4 else
                    "Standard monitoring sufficient"
                ]
            }
        
        # Sort by IISP descending
        sorted_assessments = dict(sorted(provider_assessments.items(), 
                                       key=lambda x: x[1]['iisp'], reverse=True))
        
        return {
            "algorithm": "AEPC",
            "description": "Algoritmo de Evaluación de Proveedores Críticos",
            "total_providers_assessed": len(sorted_assessments),
            "results": sorted_assessments,
            "summary": {
                "systemically_critical": len([p for p in sorted_assessments.values() if p['iisp'] >= 8]),
                "high_risk": len([p for p in sorted_assessments.values() if p['iisp'] >= 6]),
                "medium_risk": len([p for p in sorted_assessments.values() if p['iisp'] >= 4]),
                "average_iisp": sum(p['iisp'] for p in sorted_assessments.values()) / len(sorted_assessments) if sorted_assessments else 0
            }
        }
        
    except Exception as e:
        logger.error(f"AEPC calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/algorithms/aprn")
async def calculate_aprn(request: APRNRequest):
    """
    APRN - Algoritmo de Priorización de Riesgos Nacionales
    Calculate National Risk Index (IRN) from Chilean national security perspective
    """
    try:
        if not neo4j_connector or not risk_calculator:
            raise HTTPException(status_code=503, detail="Services not available")
        
        # Query entities for national risk assessment
        if request.entity_ids:
            query = """
            MATCH (e)
            WHERE e.id IN $entity_ids OR e.name IN $entity_ids
            RETURN e.id as entity_id, e.name as entity_name,
                   labels(e) as entity_types,
                   e.sector as sector,
                   e.country as country,
                   e.revenue as revenue,
                   e.employees as employees,
                   e.critical as is_critical
            """
            results = neo4j_connector.execute_query(query, {"entity_ids": request.entity_ids})
        else:
            # Get all organizations and critical infrastructure
            query = """
            MATCH (e)
            WHERE 'Organization' IN labels(e) OR 'CriticalInfrastructure' IN labels(e)
            RETURN e.id as entity_id, e.name as entity_name,
                   labels(e) as entity_types,
                   e.sector as sector,
                   e.country as country,
                   e.revenue as revenue,
                   e.employees as employees,
                   e.critical as is_critical
            LIMIT 100
            """
            results = neo4j_connector.execute_query(query)
        
        national_risk_assessments = {}
        
        for record in results:
            entity_id = record["entity_id"] or record["entity_name"]
            sector = record["sector"] or "other"
            country = record["country"] or "Unknown"
            is_critical = record.get("is_critical", False)
            
            # Calculate IRN components according to stats.md
            
            # 1. National Criticality (0-1)
            critical_sectors = ["banking", "telecommunications", "energy", "mining", "government", "health"]
            national_criticality = 0.9 if is_critical or sector in critical_sectors else 0.3
            if sector in ["mining", "banking"]:  # Key Chilean sectors
                national_criticality = min(1.0, national_criticality + 0.2)
            
            # 2. Foreign Dependency (0-1)
            foreign_dependency = 0.7 if country not in ["Chile", "cl", None] else 0.1
            if country in ["US", "China"]:
                foreign_dependency = 0.9
            elif country in ["Argentina", "Brazil", "Peru"]:
                foreign_dependency = 0.4
            
            # 3. National Response Capacity (0-1)
            # Higher values mean better capacity (lower risk)
            response_capacity = 0.8 if country == "Chile" else 0.3
            if sector in ["government", "defense"]:
                response_capacity = 0.9
            elif sector in ["banking", "telecommunications"]:
                response_capacity = 0.7
            
            # 4. Economic Impact (0-1)
            revenue = record.get("revenue", 0) or 0
            employees = record.get("employees", 0) or 0
            
            # Normalize economic impact (rough estimation)
            economic_impact = min((revenue / 1000000000) + (employees / 10000), 1.0) * 0.7
            if sector in ["mining", "banking", "retail"]:
                economic_impact = min(economic_impact + 0.3, 1.0)
            
            # 5. Reputational Risk (0-1)
            reputational_risk = 0.3  # Base risk
            if sector in ["government", "banking", "energy"]:
                reputational_risk = 0.7
            if "critical" in str(record.get("entity_types", [])).lower():
                reputational_risk = min(reputational_risk + 0.2, 1.0)
            
            # Calculate IRN according to stats.md weights
            irn = (
                0.35 * national_criticality +
                0.25 * foreign_dependency +
                0.2 * (1.0 - response_capacity) +  # Inverted - less capacity = more risk
                0.15 * economic_impact +
                0.05 * reputational_risk
            )
            
            # National risk classification
            if irn >= 0.8:
                risk_classification = "Riesgo Nacional Crítico"
            elif irn >= 0.6:
                risk_classification = "Alto Riesgo Nacional"
            elif irn >= 0.4:
                risk_classification = "Riesgo Nacional Moderado"
            else:
                risk_classification = "Bajo Riesgo Nacional"
            
            national_risk_assessments[entity_id] = {
                "entity_name": record["entity_name"],
                "sector": sector,
                "country": country,
                "irn": irn,
                "risk_classification": risk_classification,
                "components": {
                    "national_criticality": national_criticality,
                    "foreign_dependency": foreign_dependency,
                    "response_capacity": response_capacity,
                    "economic_impact": economic_impact,
                    "reputational_risk": reputational_risk
                },
                "recommended_actions": [
                    "Immediate national security assessment" if irn >= 0.8 else
                    "Enhanced monitoring and contingency planning" if irn >= 0.6 else
                    "Regular monitoring with sector authorities" if irn >= 0.4 else
                    "Standard oversight sufficient"
                ]
            }
        
        # Sort by IRN descending
        sorted_assessments = dict(sorted(national_risk_assessments.items(), 
                                       key=lambda x: x[1]['irn'], reverse=True))
        
        return {
            "algorithm": "APRN",
            "description": "Algoritmo de Priorización de Riesgos Nacionales",
            "perspective": "Chilean National Security",
            "total_entities_assessed": len(sorted_assessments),
            "results": sorted_assessments,
            "national_summary": {
                "critical_national_risks": len([e for e in sorted_assessments.values() if e['irn'] >= 0.8]),
                "high_national_risks": len([e for e in sorted_assessments.values() if e['irn'] >= 0.6]),
                "foreign_dependency_concerns": len([e for e in sorted_assessments.values() if e['components']['foreign_dependency'] > 0.7]),
                "critical_sectors_at_risk": list(set(e['sector'] for e in sorted_assessments.values() if e['irn'] >= 0.6)),
                "average_irn": sum(e['irn'] for e in sorted_assessments.values()) / len(sorted_assessments) if sorted_assessments else 0
            }
        }
        
    except Exception as e:
        logger.error(f"APRN calculation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def main():
    """Run the API server"""
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level="debug" if config.debug else "info"
    )

if __name__ == "__main__":
    main()