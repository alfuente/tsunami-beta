"""
FastAPI backend for Risk Stats calculations
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
    title="Risk Stats API",
    description="Systemic risk calculations for Chilean digital ecosystem",
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