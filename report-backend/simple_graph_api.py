#!/usr/bin/env python3
"""
API REST simple para análisis del grafo Neo4j usando FastAPI
Alternativa lightweight al servicio Quarkus
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Agregar el directorio actual al path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Intentar importar el analizador
try:
    from graph_analysis_demo import GraphAnalyzer
    NEO4J_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: Neo4j driver not available, using mock data")
    NEO4J_AVAILABLE = False

app = FastAPI(
    title="Tsunami Report Backend API",
    description="API para análisis de grafos Neo4j y generación de reportes de seguridad",
    version="1.0.0",
    docs_url="/swagger-ui",
    redoc_url="/redoc",
    openapi_url="/openapi"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración Neo4j
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "test.password"

def get_latest_analysis_file(extension):
    """Encuentra el archivo de análisis más reciente"""
    project_dir = Path(__file__).parent.parent
    pattern = f"graph_analysis_*.{extension}"
    
    files = list(project_dir.glob(pattern))
    if not files:
        return None
    
    # Ordenar por fecha de modificación, más reciente primero
    latest_file = max(files, key=lambda p: p.stat().st_mtime)
    return str(latest_file)

@app.get("/")
async def root():
    """Endpoint raíz con información de la API"""
    return {
        "service": "Tsunami Report Backend API",
        "version": "1.0.0",
        "status": "running",
        "neo4j_available": NEO4J_AVAILABLE,
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "swagger_ui": "/swagger-ui",
            "openapi": "/openapi",
            "graph_analysis": "/api/v1/graph/analysis",
            "graph_health": "/api/v1/graph/health",
            "graph_report": "/api/v1/graph/report"
        }
    }

@app.get("/api/v1/graph/health")
async def graph_health():
    """Health check del grafo Neo4j"""
    try:
        if not NEO4J_AVAILABLE:
            return JSONResponse(
                status_code=503,
                content={
                    "neo4j_connection": "unavailable",
                    "error": "Neo4j driver not available",
                    "timestamp": datetime.now().isoformat(),
                    "service": "graph-analysis"
                }
            )
        
        analyzer = GraphAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Test básico de conectividad
        with analyzer.driver.session() as session:
            session.run("RETURN 1")
        
        analyzer.close()
        
        return {
            "neo4j_connection": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "graph-analysis",
            "uri": NEO4J_URI
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "neo4j_connection": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "service": "graph-analysis"
            }
        )

@app.get("/api/v1/graph/analysis")
async def graph_analysis():
    """Obtener análisis completo del grafo"""
    try:
        if not NEO4J_AVAILABLE:
            # Buscar archivo JSON existente
            json_file = get_latest_analysis_file("json")
            if json_file and os.path.exists(json_file):
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return data
            else:
                raise HTTPException(
                    status_code=503,
                    detail="Neo4j driver not available and no cached analysis found"
                )
        
        # Ejecutar análisis en tiempo real
        analyzer = GraphAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        analysis_data = analyzer.run_full_analysis()
        analyzer.close()
        
        return analysis_data
        
    except Exception as e:
        # Intentar devolver datos cached si hay error
        json_file = get_latest_analysis_file("json")
        if json_file and os.path.exists(json_file):
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Agregar nota sobre el error pero devolver datos cached
            data["_warning"] = f"Live analysis failed: {str(e)}, returning cached data"
            return data
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate graph analysis: {str(e)}"
        )

@app.get("/api/v1/graph/report")
async def graph_report():
    """Obtener reporte en texto plano"""
    try:
        # Buscar archivo de reporte más reciente
        report_file = get_latest_analysis_file("txt")
        if report_file and os.path.exists(report_file):
            with open(report_file, 'r', encoding='utf-8') as f:
                report_content = f.read()
            return PlainTextResponse(content=report_content)
        else:
            raise HTTPException(
                status_code=404,
                detail="No analysis report found"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get graph report: {str(e)}"
        )

@app.post("/api/v1/graph/analyze")
async def trigger_analysis():
    """Ejecutar nuevo análisis del grafo"""
    try:
        # Ejecutar script de análisis en background
        script_path = Path(__file__).parent / "graph_analysis_demo.py"
        if not script_path.exists():
            raise HTTPException(
                status_code=500,
                detail="Analysis script not found"
            )
        
        # Ejecutar en background
        process = subprocess.Popen([
            "python3", str(script_path)
        ], cwd=str(script_path.parent))
        
        return {
            "status": "Analysis started",
            "message": "Graph analysis has been triggered and is running in background",
            "process_id": process.pid,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to trigger analysis: {str(e)}"
        )

@app.get("/api/v1/reports/domain/{domain}/analysis")
async def domain_analysis(domain: str):
    """Análisis de dominio específico"""
    try:
        if not NEO4J_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="Neo4j driver not available for domain analysis"
            )
        
        analyzer = GraphAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Ejecutar consulta específica para el dominio
        with analyzer.driver.session() as session:
            # Consulta básica para obtener info del dominio
            result = session.run("""
                MATCH (d:Domain {fqdn: $domain})
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Domain)
                OPTIONAL MATCH (d)-[:USES_TECHNOLOGY]->(t:Technology)
                OPTIONAL MATCH (d)-[:USES_PROVIDER]->(p:Provider)
                OPTIONAL MATCH (d)-[:RUNS_SERVICE]->(srv:Service)
                RETURN d.fqdn as domain,
                       d.risk_score as riskScore,
                       d.risk_tier as riskTier,
                       collect(DISTINCT s.fqdn) as subdomains,
                       collect(DISTINCT t.name) as technologies,
                       collect(DISTINCT p.name) as providers,
                       count(DISTINCT srv) as serviceCount
            """, {"domain": domain})
            
            record = result.single()
            if not record:
                raise HTTPException(
                    status_code=404,
                    detail=f"Domain {domain} not found in graph"
                )
            
            domain_data = {
                "domain": record["domain"],
                "risk_score": record["riskScore"] or 0.0,
                "risk_tier": record["riskTier"] or "Unknown",
                "subdomains": [s for s in record["subdomains"] if s],
                "technologies": [t for t in record["technologies"] if t],
                "providers": [p for p in record["providers"] if p],
                "service_count": record["serviceCount"],
                "analysis_timestamp": datetime.now().isoformat()
            }
            
            analyzer.close()
            return domain_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze domain {domain}: {str(e)}"
        )

if __name__ == "__main__":
    print("🚀 Iniciando Tsunami Report Backend API (Python/FastAPI)")
    print("Puerto: 8082")
    print("Swagger UI: http://localhost:8082/swagger-ui")
    print("OpenAPI: http://localhost:8082/openapi")
    print("Health Check: http://localhost:8082/api/v1/graph/health")
    print(f"Neo4j disponible: {NEO4J_AVAILABLE}")
    print("")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8082,
        log_level="info"
    )