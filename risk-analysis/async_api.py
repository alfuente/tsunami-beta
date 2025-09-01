"""
Async Risk Analysis API with task management
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Path
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    from .neo4j_connector import Neo4jConnector
    from .risk_calculator import RiskCalculator
    from .task_manager import RiskTaskManager
    from .task_models import (
        RiskTaskInfo, RiskTaskStatus, RiskTaskType,
        ACCSTaskRequest, ACPTaskRequest, APRTaskRequest,
        AECSTaskRequest, AEPCTaskRequest, APRNTaskRequest,
        BatchRiskTaskRequest, PropagationSimulationTaskRequest
    )
    from .config import config
except ImportError:
    from neo4j_connector import Neo4jConnector
    from risk_calculator import RiskCalculator
    from task_manager import RiskTaskManager
    from task_models import (
        RiskTaskInfo, RiskTaskStatus, RiskTaskType,
        ACCSTaskRequest, ACPTaskRequest, APRTaskRequest,
        AECSTaskRequest, AEPCTaskRequest, APRNTaskRequest,
        BatchRiskTaskRequest, PropagationSimulationTaskRequest
    )
    from config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO if not config.debug else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Async Risk Analysis API",
    description="Asynchronous risk analysis and calculations for Chilean digital ecosystem",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
neo4j_connector: Optional[Neo4jConnector] = None
risk_calculator: Optional[RiskCalculator] = None
task_manager: Optional[RiskTaskManager] = None

@app.on_event("startup")
async def startup():
    """Initialize connections and services"""
    global neo4j_connector, risk_calculator, task_manager
    
    try:
        logger.info("Initializing Async Risk Analysis API...")
        
        # Initialize Neo4j connector
        neo4j_connector = Neo4jConnector()
        logger.info("Neo4j connector initialized")
        
        # Initialize risk calculator
        risk_calculator = RiskCalculator()
        logger.info("Risk calculator initialized")
        
        # Initialize task manager
        task_manager = RiskTaskManager(config.postgres.dict())
        logger.info("Task manager initialized")
        
        # Test connections
        stats = neo4j_connector.get_graph_statistics()
        logger.info(f"Graph statistics: {stats}")
        
        logger.info("Async Risk Analysis API startup completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Async Risk Analysis API: {e}")
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
        if neo4j_connector and task_manager:
            stats = neo4j_connector.get_graph_statistics()
            active_tasks = len(task_manager.active_tasks)
            
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "services": {
                    "neo4j": "connected",
                    "risk_calculator": "ready",
                    "task_manager": "ready"
                },
                "graph_stats": {
                    "total_nodes": sum(stats.get('node_counts', {}).values()),
                    "total_relationships": sum(stats.get('relationship_counts', {}).values())
                },
                "active_tasks": active_tasks
            }
        else:
            return {
                "status": "unhealthy",
                "message": "Services not initialized"
            }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")

# ========== TASK MANAGEMENT ENDPOINTS ==========

@app.get("/tasks")
async def list_tasks(
    limit: int = Query(100, description="Maximum number of tasks to return"),
    status: Optional[str] = Query(None, description="Filter by status: pending, running, completed, failed")
):
    """List all risk analysis tasks"""
    if not task_manager:
        raise HTTPException(status_code=503, detail="Task manager not available")
    
    tasks = task_manager.get_all_tasks(limit=limit, status_filter=status)
    return {"tasks": tasks, "total": len(tasks)}

@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str = Path(..., description="Task ID")):
    """Get task status and results"""
    if not task_manager:
        raise HTTPException(status_code=503, detail="Task manager not available")
    
    task = task_manager.get_task(task_id)
    if not task:
        task = task_manager.get_task_from_db(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
    
    if isinstance(task, RiskTaskInfo):
        return task.dict()
    return task

@app.get("/tasks/{task_id}/logs")
async def get_task_logs(task_id: str = Path(..., description="Task ID")):
    """Get logs for a specific task"""
    if not task_manager:
        raise HTTPException(status_code=503, detail="Task manager not available")
    
    task = task_manager.get_task(task_id)
    if not task:
        task = task_manager.get_task_from_db(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
    
    if isinstance(task, RiskTaskInfo):
        logs = task.logs
    else:
        logs = task.get('logs', 'No logs available')
    
    return {"task_id": task_id, "logs": logs}

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str = Path(..., description="Task ID")):
    """Delete a completed task"""
    if not task_manager:
        raise HTTPException(status_code=503, detail="Task manager not available")
    
    # Remove from active tasks if present
    if task_id in task_manager.active_tasks:
        task = task_manager.active_tasks[task_id]
        if task.status in [RiskTaskStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Cannot delete running task")
        
        del task_manager.active_tasks[task_id]
    
    return {"message": f"Task {task_id} deleted"}

# ========== ASYNC ALGORITHM ENDPOINTS ==========

@app.post("/algorithms/accs/async")
async def start_accs_analysis(request: ACCSTaskRequest, background_tasks: BackgroundTasks):
    """Start ACCS analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.ACCS_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_accs_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "ACCS analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/algorithms/acp/async")
async def start_acp_analysis(request: ACPTaskRequest, background_tasks: BackgroundTasks):
    """Start ACP analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.ACP_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_acp_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "ACP analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/algorithms/apr/async")
async def start_apr_analysis(request: APRTaskRequest, background_tasks: BackgroundTasks):
    """Start APR analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.APR_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_apr_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "APR analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/algorithms/aecs/async")
async def start_aecs_analysis(request: AECSTaskRequest, background_tasks: BackgroundTasks):
    """Start AECS analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.AECS_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_aecs_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "AECS analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/algorithms/aepc/async")
async def start_aepc_analysis(request: AEPCTaskRequest, background_tasks: BackgroundTasks):
    """Start AEPC analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.AEPC_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_aepc_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "AEPC analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/algorithms/aprn/async")
async def start_aprn_analysis(request: APRNTaskRequest, background_tasks: BackgroundTasks):
    """Start APRN analysis as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.APRN_ANALYSIS,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_aprn_analysis, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "APRN analysis started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/batch/risk-calculation/async")
async def start_batch_risk_calculation(request: BatchRiskTaskRequest, background_tasks: BackgroundTasks):
    """Start batch risk calculation as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.BATCH_RISK_CALCULATION,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_batch_risk_calculation, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "Batch risk calculation started",
        "status_url": f"/tasks/{task_id}"
    }

@app.post("/simulation/propagation/async")
async def start_propagation_simulation(request: PropagationSimulationTaskRequest, background_tasks: BackgroundTasks):
    """Start risk propagation simulation as async task"""
    if not task_manager or not neo4j_connector or not risk_calculator:
        raise HTTPException(status_code=503, detail="Services not available")
    
    task_id = task_manager.create_task(
        task_type=RiskTaskType.PROPAGATION_SIMULATION,
        parameters=request.dict()
    )
    
    background_tasks.add_task(run_propagation_simulation, task_id, request)
    
    return {
        "task_id": task_id,
        "status": "started",
        "message": "Propagation simulation started",
        "status_url": f"/tasks/{task_id}"
    }

# ========== BACKGROUND TASK FUNCTIONS ==========

async def run_accs_analysis(task_id: str, request: ACCSTaskRequest):
    """Background task for ACCS analysis"""
    start_time = time.time()
    
    try:
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, started_at=datetime.now())
        task_manager.add_task_log(task_id, "Starting ACCS analysis")
        
        # Load graph
        task_manager.add_task_log(task_id, f"Loading dependency graph with node types: {request.node_types}")
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=10)
        
        dependency_graph = neo4j_connector.load_dependency_graph(node_types=request.node_types)
        nx_graph = neo4j_connector.create_networkx_graph(dependency_graph)
        
        task_manager.add_task_log(task_id, f"Loaded graph with {len(nx_graph.nodes())} nodes and {len(nx_graph.edges())} edges")
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=30)
        
        # Calculate centrality metrics
        task_manager.add_task_log(task_id, "Calculating centrality metrics")
        centrality_metrics = {
            'degree_centrality': nx.degree_centrality(nx_graph),
            'betweenness_centrality': nx.betweenness_centrality(nx_graph),
            'closeness_centrality': nx.closeness_centrality(nx_graph),
            'pagerank': nx.pagerank(nx_graph)
        }
        
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=60)
        
        # Calculate ICS for each node
        task_manager.add_task_log(task_id, "Calculating ICS (Systemic Criticality Index) for each node")
        ics_results = {}
        total_nodes = len(nx_graph.nodes())
        
        for i, node_id in enumerate(nx_graph.nodes()):
            node_data = nx_graph.nodes[node_id]
            sector = node_data.get('sector', 'other')
            
            # Apply sector filtering
            if request.sectors and sector not in request.sectors:
                continue
            
            # Calculate ICS components
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
            
            # Update progress periodically
            if i % 100 == 0:
                progress = 60 + (i / total_nodes) * 30
                task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=int(progress))
        
        # Sort results by ICS
        sorted_results = dict(sorted(ics_results.items(), key=lambda x: x[1]['ics'], reverse=True))
        
        # Prepare final result
        result = {
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
        
        execution_time = time.time() - start_time
        task_manager.add_task_log(task_id, f"ACCS analysis completed successfully in {execution_time:.2f}s")
        task_manager.add_task_log(task_id, f"Found {result['summary']['critical_nodes']} critical nodes")
        
        task_manager.update_task_status(
            task_id, 
            RiskTaskStatus.COMPLETED, 
            completed_at=datetime.now(),
            result=result, 
            progress=100,
            execution_time=execution_time
        )
        
    except Exception as e:
        execution_time = time.time() - start_time
        error_msg = str(e)
        task_manager.add_task_log(task_id, f"ACCS analysis failed: {error_msg}")
        task_manager.update_task_status(
            task_id, 
            RiskTaskStatus.FAILED, 
            completed_at=datetime.now(),
            error=error_msg,
            execution_time=execution_time
        )

# Similar async functions for other algorithms would go here...
# For brevity, I'm including just the ACCS example, but all algorithms would follow the same pattern

async def run_aepc_analysis(task_id: str, request: AEPCTaskRequest):
    """Background task for AEPC analysis - Critical Providers"""
    start_time = time.time()
    
    try:
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, started_at=datetime.now())
        task_manager.add_task_log(task_id, "Starting AEPC (Critical Provider Evaluation) analysis")
        
        # Query provider data from Neo4j
        task_manager.add_task_log(task_id, "Querying provider data from Neo4j")
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=10)
        
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
        
        task_manager.add_task_log(task_id, f"Found {len(results)} providers to analyze")
        task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=30)
        
        provider_assessments = {}
        
        for i, record in enumerate(results):
            provider_id = record["provider_id"] or record["provider_name"]
            total_clients = record["total_clients"] or 0
            critical_clients = record["critical_client_count"] or 0
            
            if total_clients == 0:
                continue
            
            task_manager.add_task_log(task_id, f"Analyzing provider {provider_id} ({total_clients} clients, {critical_clients} critical)")
            
            # Calculate IISP components
            critical_market_share = critical_clients / max(total_clients, 1)
            alternatives_count = min(5, max(1, total_clients // 10))
            substitutability_index = max(0, (5 - alternatives_count) / 5)
            estimated_replacement_days = 15 + (critical_clients * 5)
            time_factor = min(estimated_replacement_days / 30, 2.0)
            
            sectors = record["client_sectors"] or []
            tech_complexity = 0.5
            if "banking" in sectors or "telecommunications" in sectors:
                tech_complexity = 0.8
            elif "energy" in sectors or "government" in sectors:
                tech_complexity = 0.7
            
            country = record["country"] or "Unknown"
            jurisdictional_risk = 0.3
            if country in ["China", "Russia", "Iran"]:
                jurisdictional_risk = 0.9
            elif country in ["US"]:
                jurisdictional_risk = 0.4
            elif country in ["Chile", "Brazil", "Argentina"]:
                jurisdictional_risk = 0.2
            
            # Calculate IISP
            if request.include_iisp:
                iisp = (
                    0.3 * critical_market_share +
                    0.25 * substitutability_index +
                    0.2 * (time_factor / 2.0) +
                    0.15 * tech_complexity +
                    0.1 * jurisdictional_risk
                ) * 10
            else:
                iisp = 0.0
            
            # Classification
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
                }
            }
            
            # Update progress
            progress = 30 + ((i + 1) / len(results)) * 60
            task_manager.update_task_status(task_id, RiskTaskStatus.RUNNING, progress=int(progress))
        
        # Sort by IISP
        sorted_assessments = dict(sorted(provider_assessments.items(), 
                                       key=lambda x: x[1]['iisp'], reverse=True))
        
        result = {
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
        
        execution_time = time.time() - start_time
        task_manager.add_task_log(task_id, f"AEPC analysis completed successfully in {execution_time:.2f}s")
        task_manager.add_task_log(task_id, f"Found {result['summary']['systemically_critical']} systemically critical providers")
        
        task_manager.update_task_status(
            task_id, 
            RiskTaskStatus.COMPLETED, 
            completed_at=datetime.now(),
            result=result, 
            progress=100,
            execution_time=execution_time
        )
        
    except Exception as e:
        execution_time = time.time() - start_time
        error_msg = str(e)
        task_manager.add_task_log(task_id, f"AEPC analysis failed: {error_msg}")
        task_manager.update_task_status(
            task_id, 
            RiskTaskStatus.FAILED, 
            completed_at=datetime.now(),
            error=error_msg,
            execution_time=execution_time
        )

# Placeholder functions for other algorithms
async def run_acp_analysis(task_id: str, request: ACPTaskRequest):
    """Background task for ACP analysis - Provider Concentration"""
    # Implementation similar to ACCS and AEPC patterns
    pass

async def run_apr_analysis(task_id: str, request: APRTaskRequest):
    """Background task for APR analysis - Risk Propagation"""
    # Implementation similar to ACCS and AEPC patterns
    pass

async def run_aecs_analysis(task_id: str, request: AECSTaskRequest):
    """Background task for AECS analysis - Supply Chain Evaluation"""
    # Implementation similar to ACCS and AEPC patterns
    pass

async def run_aprn_analysis(task_id: str, request: APRNTaskRequest):
    """Background task for APRN analysis - National Risk Prioritization"""
    # Implementation similar to ACCS and AEPC patterns
    pass

async def run_batch_risk_calculation(task_id: str, request: BatchRiskTaskRequest):
    """Background task for batch risk calculation"""
    # Implementation similar to ACCS and AEPC patterns
    pass

async def run_propagation_simulation(task_id: str, request: PropagationSimulationTaskRequest):
    """Background task for propagation simulation"""
    # Implementation similar to ACCS and AEPC patterns
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)